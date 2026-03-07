# agentseal/detection/__init__.py
"""
Detection subpackage - canary, n-gram, semantic, and fusion detection.
"""

from agentseal.detection.canary import detect_canary, classify_canary_leak
from agentseal.detection.ngram import detect_extraction, extract_unique_phrases
from agentseal.detection.refusal import is_refusal

__all__ = [
    "detect_canary",
    "classify_canary_leak",
    "detect_extraction",
    "extract_unique_phrases",
    "is_refusal",
]

# Conditional exports - only available when semantic deps are installed
try:
    from agentseal.detection.semantic import compute_semantic_similarity, is_available as semantic_is_available
    from agentseal.detection.fusion import detect_extraction_with_semantic, fuse_verdicts
    __all__ += [
        "compute_semantic_similarity",
        "semantic_is_available",
        "detect_extraction_with_semantic",
        "fuse_verdicts",
    ]
except ImportError:
    pass
