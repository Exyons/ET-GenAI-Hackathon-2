from __future__ import annotations

from prahari.schema import CanonicalEvent


class SignatureBaseline:
    """Classic indicator/IOC matching — the detector built to lose.

    It flags only known-bad IPs and known-bad command substrings. It has no
    concept of behavioural novelty, so low-and-slow lateral movement (ordinary
    auth events with no known indicator) passes straight through. This is the
    contrast that proves the behavioural approach's value.
    """

    def __init__(
        self,
        bad_ips: set[str] | None = None,
        bad_cmd_substrings: set[str] | None = None,
    ) -> None:
        self.bad_ips = bad_ips or set()
        self.bad_cmd_substrings = bad_cmd_substrings or set()

    def flag(self, event: CanonicalEvent) -> bool:
        if event.dst_ip in self.bad_ips or event.src_ip in self.bad_ips:
            return True
        if event.event_type == "process" and event.dest_entity:
            cmd = event.dest_entity.lower()
            if any(sub.lower() in cmd for sub in self.bad_cmd_substrings):
                return True
        return False

    def flag_all(self, events: list[CanonicalEvent]) -> list[bool]:
        return [self.flag(e) for e in events]
