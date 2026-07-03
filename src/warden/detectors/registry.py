"""Detector registry — assembles the enabled defense layers into a pipeline.

Keeps construction data-driven: the policy names which detectors to enable, and
the registry instantiates + configures them. Adding a new detector is a one-line
registration, honoring the open/closed principle.
"""

from __future__ import annotations

from typing import Callable, Dict, List

from warden.core.policy import Policy
from warden.detectors.base import Detector
from warden.detectors.behavioral import BehavioralAnomalyDetector
from warden.detectors.injection_detector import OutputInjectionDetector
from warden.detectors.provenance import ProvenanceGuard
from warden.detectors.static_analyzer import StaticMetadataAnalyzer

# name -> factory. Register new detectors here.
_FACTORIES: Dict[str, Callable[[], Detector]] = {
    StaticMetadataAnalyzer.name: StaticMetadataAnalyzer,
    ProvenanceGuard.name: ProvenanceGuard,
    OutputInjectionDetector.name: OutputInjectionDetector,
    BehavioralAnomalyDetector.name: BehavioralAnomalyDetector,
}


class DetectorRegistry:
    """Holds the ordered, configured detector instances for a guardrail."""

    def __init__(self, detectors: List[Detector]) -> None:
        self._detectors = detectors
        self._by_name = {d.name: d for d in detectors}

    @classmethod
    def available(cls) -> List[str]:
        return sorted(_FACTORIES)

    @classmethod
    def from_policy(cls, policy: Policy) -> "DetectorRegistry":
        detectors: List[Detector] = []
        for name in policy.enabled_detectors:
            factory = _FACTORIES.get(name)
            if factory is None:
                raise KeyError(
                    f"Unknown detector '{name}'. Available: {cls.available()}"
                )
            detector = factory()
            detector.configure(policy.detector_config.get(name, {}))
            detectors.append(detector)
        return cls(detectors)

    def __iter__(self):
        return iter(self._detectors)

    def __len__(self) -> int:
        return len(self._detectors)

    def get(self, name: str) -> Detector:
        return self._by_name[name]

    def has(self, name: str) -> bool:
        return name in self._by_name
