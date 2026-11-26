"""Presidio-based PII detection using spaCy and custom Indian identifiers.

Exact duplicate results (same entity and span) are consolidated, keeping the
highest score. For distinct overlapping spans, candidates are considered by
descending confidence, then longer span, then a stable entity priority. The
first non-overlapping candidate wins. Suppressed candidates are reported in a
``conflicts`` field on the winning result, with their offsets and a reason.
All offsets remain half-open character offsets into the original input string.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

_CUSTOM_ENTITY_PRIORITY = {
    "IN_AADHAAR": 0,
    "IN_PAN": 0,
}

_ANALYZED_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "LOCATION",
    "DATE_TIME",
    "URL",
    "IP_ADDRESS",
    "IN_AADHAAR",
    "IN_PAN",
]

_CUSTOM_RECOGNIZER_NAMES = {
    "Indian Aadhaar Pattern Recognizer",
    "Indian PAN Pattern Recognizer",
}


@lru_cache(maxsize=1)
def _get_analyzer() -> Any:
    """Create and cache Presidio configured with spaCy and custom recognizers."""
    try:
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "PII detection requires Presidio Analyzer and spaCy. "
            "Install them with 'python -m pip install presidio-analyzer spacy', "
            "then install the 'en_core_web_sm' model."
        ) from exc

    try:
        from .custom_patterns import (
            create_aadhaar_recognizer,
            create_pan_recognizer,
        )

        nlp_configuration = {
            "nlp_engine_name": "spacy",
            "models": [
                {"lang_code": "en", "model_name": "en_core_web_sm"},
            ],
        }
        nlp_engine = NlpEngineProvider(
            nlp_configuration=nlp_configuration
        ).create_engine()

        registry = RecognizerRegistry(supported_languages=["en"])
        # Load generic built-ins and the spaCy recognizer, but leave country-
        # specific recognizers out so these custom Indian patterns are explicit.
        registry.load_predefined_recognizers(
            languages=["en"],
            nlp_engine=nlp_engine,
            countries=[],
        )
        registry.add_recognizer(create_aadhaar_recognizer())
        registry.add_recognizer(create_pan_recognizer())

        analyzer = AnalyzerEngine(
            registry=registry,
            nlp_engine=nlp_engine,
            supported_languages=["en"],
            log_decision_process=False,
        )

        registered_names = {
            recognizer.name for recognizer in analyzer.get_recognizers("en")
        }
        if not _CUSTOM_RECOGNIZER_NAMES.issubset(registered_names):
            raise RuntimeError(
                "The custom Aadhaar and PAN recognizers were not registered."
            )

        supported_entities = set(analyzer.get_supported_entities("en"))
        missing_entities = set(_ANALYZED_ENTITIES) - supported_entities
        if missing_entities:
            missing = ", ".join(sorted(missing_entities))
            raise RuntimeError(
                "The configured Presidio installation does not support the "
                f"required entity types: {missing}."
            )

        return analyzer
    except OSError as exc:
        raise RuntimeError(
            "The spaCy model 'en_core_web_sm' is missing or could not be loaded. "
            "Install it with: python -m spacy download en_core_web_sm"
        ) from exc
    except ModuleNotFoundError as exc:
        if (exc.name or "").startswith("en_core_web_sm"):
            raise RuntimeError(
                "The spaCy model 'en_core_web_sm' is missing. "
                "Install it with: python -m spacy download en_core_web_sm"
            ) from exc
        raise RuntimeError(
            "Presidio or spaCy could not be initialized. Check that the "
            "required Python packages are installed."
        ) from exc
    except (ImportError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "Presidio could not be initialized with spaCy. Check the installed "
            "Presidio/spaCy versions and the 'en_core_web_sm' model."
        ) from exc


def _overlaps(first: dict[str, Any], second: dict[str, Any]) -> bool:
    """Return whether two half-open character spans intersect."""
    return first["start"] < second["end"] and second["start"] < first["end"]


def _conflict_summary(
    candidate: dict[str, Any], reason: str
) -> dict[str, Any]:
    """Describe a suppressed candidate without logging or duplicating its text."""
    return {
        "entity_type": candidate["entity_type"],
        "start": candidate["start"],
        "end": candidate["end"],
        "score": candidate["score"],
        "reason": reason,
    }


def _resolve_conflicts(
    analyzer_results: list[Any], original_text: str
) -> list[dict[str, Any]]:
    """Deduplicate results and return a deterministic, non-overlapping set."""
    unique: dict[tuple[str, int, int], dict[str, Any]] = {}

    for result in analyzer_results:
        start = result.start
        end = result.end
        if not isinstance(start, int) or not isinstance(end, int):
            raise RuntimeError("Presidio returned invalid character offsets.")
        if start < 0 or end <= start or end > len(original_text):
            raise RuntimeError("Presidio returned character offsets outside the input.")

        candidate = {
            "entity_type": result.entity_type,
            "start": start,
            "end": end,
            "score": float(result.score),
            "original_text": original_text[start:end],
            "conflicts": [],
        }
        key = (candidate["entity_type"], start, end)
        previous = unique.get(key)
        if previous is None:
            unique[key] = candidate
        elif candidate["score"] > previous["score"]:
            candidate["conflicts"].extend(previous["conflicts"])
            candidate["conflicts"].append(
                _conflict_summary(
                    previous, "duplicate entity and span; retained the higher score"
                )
            )
            unique[key] = candidate
        else:
            previous["conflicts"].append(
                _conflict_summary(
                    candidate, "duplicate entity and span; retained the higher score"
                )
            )

    candidates = sorted(
        unique.values(),
        key=lambda item: (
            -item["score"],
            -(item["end"] - item["start"]),
            _CUSTOM_ENTITY_PRIORITY.get(item["entity_type"], 1),
            item["start"],
            item["end"],
            item["entity_type"],
        ),
    )

    accepted: list[dict[str, Any]] = []
    for candidate in candidates:
        overlaps = [item for item in accepted if _overlaps(candidate, item)]
        if overlaps:
            conflict = _conflict_summary(
                candidate,
                "overlaps a higher-ranked candidate; kept non-overlapping spans "
                "to avoid double-redaction",
            )
            for winner in overlaps:
                winner["conflicts"].append(conflict)
        else:
            accepted.append(candidate)

    accepted.sort(key=lambda item: (item["start"], item["end"], item["entity_type"]))
    results: list[dict[str, Any]] = []
    for item in accepted:
        result = {
            "entity_type": item["entity_type"],
            "start": item["start"],
            "end": item["end"],
            "score": item["score"],
            "original_text": item["original_text"],
        }
        if item["conflicts"]:
            result["conflicts"] = item["conflicts"]
        results.append(result)
    return results


def detect_pii(text: str) -> list[dict[str, Any]]:
    """Detect PII in text and return entity spans measured against the input.

    Each detection includes ``entity_type``, ``start``, ``end``, ``score``,
    and ``original_text``. When candidates conflict, their summary and
    resolution reason are added to the retained result's optional ``conflicts``
    list. The input string is never modified, printed, or logged.

    Raises:
        TypeError: If ``text`` is not a string.
        ValueError: If ``text`` is empty or contains only whitespace.
        RuntimeError: If Presidio, spaCy, the model, or detection cannot run.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string.")
    if not text.strip():
        raise ValueError("text must not be empty.")

    analyzer = _get_analyzer()
    try:
        raw_results = analyzer.analyze(
            text=text,
            language="en",
            entities=_ANALYZED_ENTITIES,
        )
    except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "PII detection failed. The input text was not logged or included "
            "in this error."
        ) from exc

    return _resolve_conflicts(raw_results, text)
