"""Redact detected PII with Presidio Anonymizer."""

from __future__ import annotations

import math
from collections import Counter
from functools import lru_cache
from typing import Any, Mapping, Sequence

_PLACEHOLDERS = {
    "PERSON": "[NAME]",
    "EMAIL_ADDRESS": "[EMAIL]",
    "PHONE_NUMBER": "[PHONE]",
    "LOCATION": "[LOCATION]",
    "DATE_TIME": "[DATE]",
    "URL": "[URL]",
    "IP_ADDRESS": "[IP_ADDRESS]",
    "CREDIT_CARD": "[CREDIT_CARD]",
    "AADHAAR": "[AADHAAR]",
    "IN_AADHAAR": "[AADHAAR]",
    "PAN": "[PAN]",
    "IN_PAN": "[PAN]",
}

_ENTITY_ALIASES = {
    "IN_AADHAAR": "AADHAAR",
    "IN_PAN": "PAN",
}


@lru_cache(maxsize=1)
def _get_anonymizer() -> Any:
    """Create and cache Presidio's anonymization engine."""
    try:
        from presidio_anonymizer import AnonymizerEngine
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PII redaction requires Presidio Anonymizer. "
            "Install it with 'python -m pip install presidio-anonymizer'."
        ) from exc

    try:
        return AnonymizerEngine()
    except (ImportError, TypeError, ValueError) as exc:
        raise RuntimeError("Presidio Anonymizer could not be initialized.") from exc


def _canonical_entity_type(entity_type: str) -> str:
    """Normalize custom identifier entity names and reject malformed labels."""
    if not isinstance(entity_type, str) or not entity_type.strip():
        raise ValueError("Each detection must have a non-empty entity_type.")
    normalized = entity_type.strip().upper()
    return _ENTITY_ALIASES.get(normalized, normalized)


def _placeholder(entity_type: str) -> str:
    """Return a known placeholder or the generic placeholder for unknown types."""
    return _PLACEHOLDERS.get(entity_type, "[PII]")


def _validated_detections(
    text: str, detections: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Validate detections, including spans reported as overlap conflicts."""
    if isinstance(detections, (str, bytes)) or not isinstance(detections, Sequence):
        raise TypeError("detections must be a sequence of detection mappings.")

    unique: dict[tuple[str, int, int], dict[str, Any]] = {}
    candidates: list[Mapping[str, Any]] = []
    for detection in detections:
        if not isinstance(detection, Mapping):
            raise TypeError("Each detection must be a mapping.")
        candidates.append(detection)
        conflicts = detection.get("conflicts", [])
        if not isinstance(conflicts, Sequence) or isinstance(conflicts, (str, bytes)):
            raise TypeError("Detection conflicts must be a sequence.")
        candidates.extend(conflicts)

    for detection in candidates:
        if not isinstance(detection, Mapping):
            raise TypeError("Each detection must be a mapping.")

        try:
            entity_type = _canonical_entity_type(detection["entity_type"])
            start = detection["start"]
            end = detection["end"]
        except KeyError as exc:
            raise ValueError(
                "Each detection must include entity_type, start, and end."
            ) from exc

        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
        ):
            raise TypeError("Detection start and end offsets must be integers.")
        if start < 0 or end <= start or end > len(text):
            raise ValueError("Detection offsets must identify a non-empty span in text.")

        score = detection.get("score", 0.5)
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise TypeError("Detection score must be a number.")
        score = float(score)
        if not math.isfinite(score) or score < 0 or score > 1:
            raise ValueError("Detection score must be between 0 and 1.")

        original_text = detection.get("original_text")
        if original_text is not None and original_text != text[start:end]:
            raise ValueError(
                "Detection original_text does not match its offsets in the input."
            )

        key = (entity_type, start, end)
        current = unique.get(key)
        if current is None or score > current["score"]:
            unique[key] = {
                "entity_type": entity_type,
                "start": start,
                "end": end,
                "score": score,
            }

    return sorted(
        unique.values(),
        key=lambda item: (
            item["start"],
            -item["end"],
            -item["score"],
            item["entity_type"],
        ),
    )


def _merge_overlapping_detections(
    detections: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Merge intersecting spans so every detected character is anonymized once.

    Adjacent spans remain separate. A merged span with different entity types
    uses the generic ``PII`` type because no single specific label describes
    the entire combined range.
    """
    merged: list[dict[str, Any]] = []
    for detection in detections:
        current = {
            "entity_type": detection["entity_type"],
            "start": detection["start"],
            "end": detection["end"],
            "score": detection["score"],
            "entity_types": {detection["entity_type"]},
        }

        if merged and current["start"] < merged[-1]["end"]:
            previous = merged[-1]
            email_contains_url = (
                "EMAIL_ADDRESS" in previous["entity_types"]
                and previous["entity_types"].issubset({"EMAIL_ADDRESS", "URL"})
                and current["entity_types"] == {"URL"}
                and previous["start"] <= current["start"]
                and current["end"] <= previous["end"]
            )
            previous["end"] = max(previous["end"], current["end"])
            previous["score"] = max(previous["score"], current["score"])
            previous["entity_types"].update(current["entity_types"])
            if email_contains_url:
                previous["entity_type"] = "EMAIL_ADDRESS"
            elif len(previous["entity_types"]) > 1:
                previous["entity_type"] = "PII"
        else:
            merged.append(current)

    return merged


def redact_text(
    text: str, detections: Sequence[Mapping[str, Any]] | None = None
) -> str:
    """Replace sensitive spans in ``text`` with meaningful placeholders.

    When ``detections`` is omitted, the public ``detection.detect_pii`` function
    is called. Supplied detections must use offsets into the original text.
    Presidio Anonymizer performs the actual replacements; overlapping spans
    are first unioned so the same characters are never redacted twice.

    Empty text is returned unchanged.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string.")
    if not text.strip():
        return text

    if detections is None:
        from detection import detect_pii

        detections = detect_pii(text)

    validated = _validated_detections(text, detections)
    if not validated:
        return text

    resolved = _merge_overlapping_detections(validated)

    try:
        from presidio_anonymizer.entities import OperatorConfig, RecognizerResult
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PII redaction requires Presidio Anonymizer. "
            "Install it with 'python -m pip install presidio-anonymizer'."
        ) from exc

    analyzer_results = [
        RecognizerResult(
            entity_type=item["entity_type"],
            start=item["start"],
            end=item["end"],
            score=item["score"],
        )
        for item in resolved
    ]
    operators = {
        item["entity_type"]: OperatorConfig(
            "replace", {"new_value": _placeholder(item["entity_type"])}
        )
        for item in resolved
    }

    try:
        result = _get_anonymizer().anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators,
        )
    except (ImportError, OSError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "Presidio Anonymizer failed to redact the supplied detection spans."
        ) from exc
    return result.text


def get_entity_summary(
    detections: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Summarize retained and suppressed detections without exposing text.

    The existing entity totals describe retained detections only. Suppressed
    candidates are deduplicated by entity type and character offsets before
    computing their separate totals.
    """
    if isinstance(detections, (str, bytes)) or not isinstance(detections, Sequence):
        raise TypeError("detections must be a sequence of detection mappings.")

    entity_types: list[str] = []
    suppressed_candidates: set[tuple[str, int, int]] = set()
    for detection in detections:
        if not isinstance(detection, Mapping):
            raise TypeError("Each detection must be a mapping.")
        entity_type = detection.get("entity_type")
        if not isinstance(entity_type, str) or not entity_type.strip():
            raise ValueError("Each detection must have a non-empty entity_type.")
        entity_types.append(entity_type.strip().upper())

        conflicts = detection.get("conflicts", [])
        if not isinstance(conflicts, Sequence) or isinstance(conflicts, (str, bytes)):
            raise TypeError("Detection conflicts must be a sequence.")
        for conflict in conflicts:
            if not isinstance(conflict, Mapping):
                raise TypeError("Each suppressed detection must be a mapping.")
            suppressed_type = conflict.get("entity_type")
            start = conflict.get("start")
            end = conflict.get("end")
            if not isinstance(suppressed_type, str) or not suppressed_type.strip():
                raise ValueError(
                    "Each suppressed detection must have a non-empty entity_type."
                )
            if (
                isinstance(start, bool)
                or isinstance(end, bool)
                or not isinstance(start, int)
                or not isinstance(end, int)
                or start < 0
                or end <= start
            ):
                raise ValueError(
                    "Each suppressed detection must have valid start and end offsets."
                )
            suppressed_candidates.add(
                (suppressed_type.strip().upper(), start, end)
            )

    counts = dict(sorted(Counter(entity_types).items()))
    suppressed_counts = dict(
        sorted(Counter(entity_type for entity_type, _, _ in suppressed_candidates).items())
    )
    suppressed_total = len(suppressed_candidates)
    return {
        "total_entities": len(entity_types),
        "entity_counts": counts,
        "entity_types": sorted(counts),
        "suppressed_total": suppressed_total,
        "suppressed_entity_counts": suppressed_counts,
        "total_candidates": len(entity_types) + suppressed_total,
    }