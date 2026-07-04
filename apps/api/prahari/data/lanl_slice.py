from __future__ import annotations

from collections.abc import Iterable, Iterator

RedteamKey = tuple[str, str, str, str]


def slice_auth_lines(lines: Iterable[str], t0: int, t1: int) -> Iterator[str]:
    for line in lines:
        idx = line.find(",")
        if idx < 0:
            continue
        try:
            t = int(line[:idx])
        except ValueError:
            continue
        if t >= t1:
            return  # auth.txt is time-sorted: nothing later is in-window
        if t >= t0:
            yield line.rstrip("\n")


def redteam_in_window(
    redteam: set[RedteamKey], t0: int, t1: int
) -> set[RedteamKey]:
    return {k for k in redteam if t0 <= int(k[0]) < t1}


def lines_for_hosts(
    lines: Iterable[str], hosts: set[str], t0: int, t1: int, host_fields: tuple[int, ...]
) -> Iterator[str]:
    for line in lines:
        parts = line.rstrip("\n").split(",")
        if not parts or not parts[0].isdigit():
            continue
        t = int(parts[0])
        if t >= t1:
            return
        if t < t0:
            continue
        if any(len(parts) > f and parts[f] in hosts for f in host_fields):
            yield line.rstrip("\n")
