from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Action lifecycle:
#   pending_approval → approved → dispatched → executed | failed
#                    ↘ rejected                 executed → reverted
# mode (dry_run | armed) is set at approval; the agent only really runs an armed
# action if its own PRAHARI_ALLOW_ARMED gate is also set — a deliberate triple gate.
OPEN_STATES = ("pending_approval", "approved", "dispatched")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Action:
    id: str
    incident_id: str
    host: str                 # which agent executes it (the affected host)
    playbook: str
    target: str
    reason: str
    reversible: bool
    status: str = "pending_approval"
    mode: str = "dry_run"     # dry_run | armed
    undo: bool = False        # a revert action
    created_at: str = field(default_factory=_now)
    decided_at: str | None = None
    dispatched_at: str | None = None
    executed_at: str | None = None
    approver: str | None = None
    result: dict | None = None
    revert_of: str | None = None


class ActionStore:
    """In-memory queue + audit log for response actions. One instance app-wide."""

    def __init__(self, bus) -> None:
        self.bus = bus
        self.actions: dict[str, Action] = {}

    def _emit(self, a: Action) -> None:
        try:
            self.bus.publish({"type": "action", **asdict(a)})
        except Exception:
            pass  # SSE must never break the response path

    def list(self) -> list[Action]:
        return sorted(self.actions.values(), key=lambda a: a.created_at, reverse=True)

    def get(self, aid: str) -> Action | None:
        return self.actions.get(aid)

    def create(self, incident_id, host, playbook, target, reason, reversible) -> Action:
        # dedup: one open (non-undo) action per (incident, playbook, target)
        for a in self.actions.values():
            if (not a.undo and a.status in OPEN_STATES
                    and (a.incident_id, a.playbook, a.target) == (incident_id, playbook, target)):
                return a
        a = Action(id="act-" + uuid.uuid4().hex[:8], incident_id=incident_id, host=host,
                   playbook=playbook, target=target, reason=reason, reversible=reversible)
        self.actions[a.id] = a
        self._emit(a)
        return a

    def approve(self, aid, approver="operator", arm=False) -> Action:
        a = self.actions[aid]
        a.status = "approved"
        a.mode = "armed" if arm else "dry_run"
        a.approver = approver
        a.decided_at = _now()
        self._emit(a)
        return a

    def reject(self, aid, approver="operator") -> Action:
        a = self.actions[aid]
        a.status = "rejected"
        a.approver = approver
        a.decided_at = _now()
        self._emit(a)
        return a

    def revert(self, aid, approver="operator") -> Action:
        orig = self.actions[aid]
        r = Action(
            id="act-" + uuid.uuid4().hex[:8], incident_id=orig.incident_id, host=orig.host,
            playbook=orig.playbook, target=orig.target,
            reason=f"revert {orig.playbook} on {orig.target}", reversible=orig.reversible,
            status="approved", mode=orig.mode, undo=True, approver=approver,
            decided_at=_now(), revert_of=orig.id,
        )
        self.actions[r.id] = r
        orig.status = "reverted"
        self._emit(orig)
        self._emit(r)
        return r

    def pending_for_host(self, host: str) -> list[Action]:
        """Agent poll: hand over approved actions for this host and mark dispatched."""
        out = []
        for a in self.actions.values():
            if a.host == host and a.status == "approved":
                a.status = "dispatched"
                a.dispatched_at = _now()
                self._emit(a)
                out.append(a)
        return out

    def report(self, aid, result: dict) -> Action:
        a = self.actions[aid]
        a.result = result
        a.status = "failed" if result.get("error") else "executed"
        a.executed_at = _now()
        self._emit(a)
        return a

    def stats(self) -> dict:
        c = Counter(a.status for a in self.actions.values())
        return {
            "total": len(self.actions),
            "pending": c["pending_approval"],
            "approved": c["approved"] + c["dispatched"],
            "executed": c["executed"],
            "failed": c["failed"],
            "rejected": c["rejected"],
            "reverted": c["reverted"],
        }
