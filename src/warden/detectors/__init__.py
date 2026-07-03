"""Warden detection layers.

Each detector is a small, single-responsibility unit implementing the
:class:`~warden.detectors.base.Detector` contract. The
:class:`~warden.detectors.registry.DetectorRegistry` assembles the enabled
layers into a pipeline the guardrail drives.
"""

from warden.detectors.base import Detector, DetectorContext
from warden.detectors.behavioral import BehavioralAnomalyDetector
from warden.detectors.injection_detector import OutputInjectionDetector
from warden.detectors.provenance import ProvenanceGuard
from warden.detectors.registry import DetectorRegistry
from warden.detectors.static_analyzer import StaticMetadataAnalyzer

__all__ = [
    "Detector",
    "DetectorContext",
    "StaticMetadataAnalyzer",
    "ProvenanceGuard",
    "OutputInjectionDetector",
    "BehavioralAnomalyDetector",
    "DetectorRegistry",
]
