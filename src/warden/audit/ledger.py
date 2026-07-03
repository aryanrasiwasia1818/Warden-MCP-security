"""Append-only, hash-chained audit ledger.

Provenance is a first-class requirement for agent security: you must be able to
answer "what did the agent do, when, and what did Warden decide?" — and prove
the record wasn't altered after the fact.

Each entry stores the hash of the previous entry, forming a chain. Any edit to a
past entry breaks every hash downstream, which :meth:`verify` detects. Entries
optionally stream to a JSONL file so the trail survives the process.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from warden.core.exceptions import ProvenanceError

_GENESIS = "0" * 64


def _hash_entry(payload: Dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    """One immutable record in the chain."""

    seq: int
    timestamp: float
    event_type: str
    subject: str
    decision: str
    data: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = _GENESIS
    entry_hash: str = ""

    def compute_hash(self) -> str:
        return _hash_entry(
            {
                "seq": self.seq,
                "timestamp": self.timestamp,
                "event_type": self.event_type,
                "subject": self.subject,
                "decision": self.decision,
                "data": self.data,
                "prev_hash": self.prev_hash,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditLedger:
    """A tamper-evident, append-only log of guardrail decisions."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._entries: List[AuditEntry] = []
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            self._load()

    # -- writing --------------------------------------------------------- #
    def record(
        self,
        event_type: str,
        subject: str,
        decision: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        prev = self._entries[-1].entry_hash if self._entries else _GENESIS
        entry = AuditEntry(
            seq=len(self._entries),
            timestamp=time.time(),
            event_type=event_type,
            subject=subject,
            decision=decision,
            data=data or {},
            prev_hash=prev,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        if self._path:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict()) + "\n")
        return entry

    # -- reading --------------------------------------------------------- #
    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def _load(self) -> None:
        assert self._path is not None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            self._entries.append(AuditEntry(**d))

    # -- integrity ------------------------------------------------------- #
    def verify(self) -> bool:
        """Recompute the chain; raise :class:`ProvenanceError` on any break."""

        prev = _GENESIS
        for entry in self._entries:
            if entry.prev_hash != prev:
                raise ProvenanceError(
                    f"Broken chain at seq {entry.seq}: prev_hash mismatch."
                )
            if entry.compute_hash() != entry.entry_hash:
                raise ProvenanceError(
                    f"Tampered entry at seq {entry.seq}: hash mismatch."
                )
            prev = entry.entry_hash
        return True

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self._entries:
            counts[e.decision] = counts.get(e.decision, 0) + 1
        return counts
