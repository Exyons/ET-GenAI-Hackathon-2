"""Run the LANL benchmark on the real sliced window. Manual (multi-GB): not in CI.

Usage: cd apps/api && uv run python scripts/run_real_benchmark.py [T0] [T1] [CAP]

CAP subsamples benign auth lines (all red-team lines are always kept) so we don't
build tens of millions of pydantic objects. Deterministic (seeded).
"""
from __future__ import annotations

import gzip
import random
import sys
from pathlib import Path

from prahari.data.benchmark import run_lanl_benchmark
from prahari.data.lanl_slice import redteam_in_window, slice_auth_lines

ROOT = Path(__file__).resolve().parents[3]


def load_redteam_gz(path: Path) -> set[tuple[str, str, str, str]]:
    keys = set()
    with gzip.open(path, "rt") as fh:
        for line in fh:
            line = line.strip()
            if line:
                t, u, s, d = line.split(",")
                keys.add((t, u, s, d))
    return keys


def _is_redteam(line: str, redteam: set[tuple[str, str, str, str]]) -> bool:
    p = line.split(",")
    return len(p) >= 5 and (p[0], p[1], p[3], p[4]) in redteam


def main() -> None:
    t0 = int(sys.argv[1]) if len(sys.argv) > 1 else 759600
    t1 = int(sys.argv[2]) if len(sys.argv) > 2 else 770400
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 400_000

    redteam_all = load_redteam_gz(ROOT / "data/redteam.txt.gz")
    redteam = redteam_in_window(redteam_all, t0, t1)

    # cache the sliced+subsampled window so tuning runs don't re-scan the 7.2G file
    cache = ROOT / f"data/lanl_slice_{t0}_{t1}_{cap}.txt"
    if cache.exists():
        kept = cache.read_text().splitlines()
        print(f"loaded cached slice {cache.name}: {len(kept)} lines")
    else:
        rng = random.Random(0)
        redteam_lines: list[str] = []
        benign_kept: list[str] = []
        benign_seen = 0
        with gzip.open(ROOT / "data/auth.txt.gz", "rt") as fh:
            for line in slice_auth_lines(fh, t0, t1):
                if _is_redteam(line, redteam):
                    redteam_lines.append(line)  # always keep positives
                else:
                    benign_seen += 1
                    if len(benign_kept) < cap:
                        benign_kept.append(line)
                    elif rng.random() < cap / benign_seen:  # reservoir sample benign
                        benign_kept[rng.randrange(cap)] = line
        kept = redteam_lines + benign_kept
        cache.write_text("\n".join(kept) + "\n")
        print(f"window [{t0},{t1}): kept {len(kept)} auth lines "
              f"(redteam_lines={len(redteam_lines)}, benign_seen={benign_seen}, "
              f"red-team keys in window={len(redteam)}) -> cached {cache.name}")

    results = run_lanl_benchmark(kept, redteam, train_frac=0.5, quantile=0.99)
    for name, m in results.items():
        print(f"{name:10s} recall={m.recall:.3f} precision={m.precision:.3f} "
              f"f1={m.f1:.3f} fpr={m.fpr:.4f} (tp={m.tp} fp={m.fp} fn={m.fn} tn={m.tn})")


if __name__ == "__main__":
    main()
