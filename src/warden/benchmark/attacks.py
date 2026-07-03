"""Attack-corpus loader.

The corpus lives as human-readable YAML in ``corpus/`` so it can be reviewed and
extended without touching code. Each case declares a *stage* (which entry point
of the guardrail it exercises) and an *expected* outcome, so the runner can
score real detection behavior rather than hard-coded assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from warden.core.exceptions import CorpusError
from warden.core.models import AttackCategory

_CORPUS_DIR = Path(__file__).resolve().parent / "corpus"

# Zero-width joiner inserted between words for the hidden-unicode fixtures.
_ZWSP = "​"

_VALID_STAGES = {"ingest", "call", "result", "swap", "unapproved", "sequence"}
_VALID_EXPECT = {"block", "flag", "allow"}


def _smuggle_unicode(text: str) -> str:
    """Insert zero-width characters between words (models invisible smuggling)."""

    return _ZWSP.join(text.split(" "))


@dataclass
class AttackCase:
    """A single benchmark case."""

    id: str
    name: str
    category: AttackCategory
    stage: str
    expect: str
    description: str = ""
    cve: Optional[str] = None
    # stage-specific payloads
    descriptor: Optional[Dict[str, Any]] = None
    baseline: Optional[Dict[str, Any]] = None
    approve: List[Dict[str, Any]] = field(default_factory=list)
    call: Optional[Dict[str, Any]] = None
    tool: Optional[str] = None
    result: Optional[str] = None
    sequence: List[Dict[str, Any]] = field(default_factory=list)
    repeat_call: Optional[Dict[str, Any]] = None
    repeat: int = 1
    vary_args: bool = False
    inject_hidden_unicode: bool = False

    @property
    def is_benign(self) -> bool:
        return self.category is AttackCategory.BENIGN or self.expect == "allow"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttackCase":
        try:
            category = AttackCategory(str(data["category"]))
        except (KeyError, ValueError) as exc:
            raise CorpusError(f"Case {data.get('id')} has invalid category: {exc}") from exc

        stage = str(data.get("stage", "")).lower()
        expect = str(data.get("expect", "")).lower()
        if stage not in _VALID_STAGES:
            raise CorpusError(f"Case {data.get('id')} has invalid stage '{stage}'.")
        if expect not in _VALID_EXPECT:
            raise CorpusError(f"Case {data.get('id')} has invalid expect '{expect}'.")

        result_text = data.get("result")
        if result_text is not None and data.get("inject_hidden_unicode"):
            result_text = _smuggle_unicode(str(result_text))

        descriptor = data.get("descriptor")
        if descriptor and data.get("inject_hidden_unicode"):
            descriptor = dict(descriptor)
            descriptor["description"] = _smuggle_unicode(str(descriptor.get("description", "")))

        return cls(
            id=str(data["id"]),
            name=str(data.get("name", data["id"])),
            category=category,
            stage=stage,
            expect=expect,
            description=str(data.get("description", "")),
            cve=data.get("cve"),
            descriptor=descriptor,
            baseline=data.get("baseline"),
            approve=list(data.get("approve", []) or []),
            call=data.get("call"),
            tool=data.get("tool"),
            result=result_text,
            sequence=list(data.get("sequence", []) or []),
            repeat_call=data.get("repeat_call"),
            repeat=int(data.get("repeat", 1)),
            vary_args=bool(data.get("vary_args", False)),
            inject_hidden_unicode=bool(data.get("inject_hidden_unicode", False)),
        )


def load_corpus(directory: Optional[Path] = None) -> List[AttackCase]:
    """Load every ``*.yaml`` case file from the corpus directory."""

    directory = Path(directory) if directory else _CORPUS_DIR
    if not directory.exists():
        raise CorpusError(f"Corpus directory not found: {directory}")

    cases: List[AttackCase] = []
    for path in sorted(directory.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in doc.get("cases", []):
            cases.append(AttackCase.from_dict(raw))
    if not cases:
        raise CorpusError(f"No cases found in {directory}")
    return cases
