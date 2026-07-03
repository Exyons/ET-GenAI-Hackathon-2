from pathlib import Path

from prahari.data.benchmark import run_lanl_benchmark
from prahari.parsers.lanl import load_redteam

FIX = Path(__file__).parent / "fixtures"


def test_real_lanl_benchmark_sentinel_beats_signature():
    auth_lines = (FIX / "lanl_bench_auth.txt").read_text().splitlines()
    redteam = load_redteam(FIX / "lanl_bench_redteam.txt")

    results = run_lanl_benchmark(auth_lines, redteam, train_frac=0.8, quantile=0.99)

    assert results["signature"].recall == 0.0        # blind to valid-cred lateral movement
    assert results["sentinel"].recall >= 0.5         # catches the NTLM-to-new-host burst
    assert results["sentinel"].recall > results["signature"].recall
