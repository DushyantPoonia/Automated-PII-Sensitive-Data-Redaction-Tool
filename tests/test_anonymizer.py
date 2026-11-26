"""Tests for Presidio-backed text redaction."""

import pytest

from detection import detect_pii
from redaction import get_entity_summary, redact_text
from redaction.anonymizer import _merge_overlapping_detections


@pytest.mark.parametrize(
    ("entity_type", "value", "placeholder"),
    [
        ("EMAIL_ADDRESS", "alex@example.com", "[EMAIL]"),
        ("PHONE_NUMBER", "415-555-2671", "[PHONE]"),
        ("PERSON", "Alex Smith", "[NAME]"),
        ("LOCATION", "Seattle", "[LOCATION]"),
        ("URL", "https://example.com", "[URL]"),
        ("IP_ADDRESS", "192.0.2.10", "[IP_ADDRESS]"),
        ("CREDIT_CARD", "4111111111111111", "[CREDIT_CARD]"),
        ("IN_AADHAAR", "1234-5678-9012", "[AADHAAR]"),
        ("IN_PAN", "ABCDE1234F", "[PAN]"),
    ],
)
def test_supported_entity_types_use_meaningful_placeholders(
    entity_type, value, placeholder
):
    text = f"Value: {value}."
    start = text.index(value)
    detections = [
        {
            "entity_type": entity_type,
            "start": start,
            "end": start + len(value),
            "score": 0.9,
            "original_text": value,
        }
    ]

    assert redact_text(text, detections) == f"Value: {placeholder}."


def test_multiple_entity_types_each_use_their_placeholder():
    text = "Alex Smith alex@example.com 415-555-2671 Seattle"
    values = [
        ("PERSON", "Alex Smith", "[NAME]"),
        ("EMAIL_ADDRESS", "alex@example.com", "[EMAIL]"),
        ("PHONE_NUMBER", "415-555-2671", "[PHONE]"),
        ("LOCATION", "Seattle", "[LOCATION]"),
    ]
    detections = [
        {
            "entity_type": entity_type,
            "start": text.index(value),
            "end": text.index(value) + len(value),
            "score": 0.9,
            "original_text": value,
        }
        for entity_type, value, _ in values
    ]

    redacted = redact_text(text, detections)

    assert redacted == "[NAME] [EMAIL] [PHONE] [LOCATION]"


def test_preserves_normal_text_punctuation_line_breaks_and_original_input():
    text = "Hi, Alex Smith!\nEmail: alex@example.com.\nKeep this line."
    original_text = text
    values = [
        ("PERSON", "Alex Smith"),
        ("EMAIL_ADDRESS", "alex@example.com"),
    ]
    detections = [
        {
            "entity_type": entity_type,
            "start": text.index(value),
            "end": text.index(value) + len(value),
            "score": 0.9,
            "original_text": value,
        }
        for entity_type, value in values
    ]

    redacted = redact_text(text, detections)

    assert redacted == "Hi, [NAME]!\nEmail: [EMAIL].\nKeep this line."
    assert text == original_text


def test_email_with_contained_url_conflict_keeps_email_placeholder():
    text = "Contact alice@example.com."
    email = "alice@example.com"
    url = "example.com"
    detections = [
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": text.index(email),
            "end": text.index(email) + len(email),
            "score": 1.0,
            "original_text": email,
            "conflicts": [
                {
                    "entity_type": "URL",
                    "start": text.index(url),
                    "end": text.index(url) + len(url),
                    "score": 0.5,
                    "reason": "contained URL match within email",
                }
            ],
        }
    ]

    assert redact_text(text, detections) == "Contact [EMAIL]."


def test_redacts_multiple_pii_types_and_preserves_surrounding_text():
    text = (
        "Hello Rahul Sharma. Email rahul@example.com; phone +1 415-555-2671. "
        "Aadhaar 1234 5678 9012; PAN ABCDE1234F."
    )

    redacted = redact_text(text)

    assert "[NAME]" in redacted
    assert "[PHONE]" in redacted
    assert "[PII]" in redacted
    assert "[PAN]" in redacted
    assert "Hello " in redacted
    assert ". Email " in redacted
    assert "rahul@example.com" not in redacted
    assert "1234 5678 9012" not in redacted
    assert "ABCDE1234F" not in redacted


def test_returns_text_unchanged_when_no_detections_exist():
    text = "This ordinary sentence has nothing private."

    assert redact_text(text, detections=[]) == text


def test_redacts_repeated_email_addresses():
    text = "Write to sam@example.com, or copy sam@example.com."
    email = "sam@example.com"
    first_start = text.index(email)
    second_start = text.rindex(email)
    detections = [
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": start,
            "end": start + len(email),
            "score": 1.0,
            "original_text": email,
        }
        for start in (first_start, second_start)
    ]

    redacted = redact_text(text, detections)

    assert redacted == "Write to [EMAIL], or copy [EMAIL]."


def test_merges_overlapping_detections_without_leaving_sensitive_characters():
    text = "prefix ABCDEFGHIJ suffix"
    detections = [
        {
            "entity_type": "PERSON",
            "start": 7,
            "end": 14,
            "score": 0.9,
            "original_text": "ABCDEFG",
        },
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": 12,
            "end": 17,
            "score": 0.8,
            "original_text": "FGHIJ",
        },
    ]

    redacted = redact_text(text, detections)

    assert redacted == "prefix [PII] suffix"


@pytest.mark.parametrize(
    ("detections", "expected_start", "expected_end"),
    [
        (
            [
                {"entity_type": "PERSON", "start": 0, "end": 10, "score": 0.6},
                {"entity_type": "EMAIL_ADDRESS", "start": 2, "end": 7, "score": 0.9},
            ],
            0,
            10,
        ),
        (
            [
                {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 10, "score": 0.6},
                {"entity_type": "PERSON", "start": 2, "end": 7, "score": 0.9},
            ],
            0,
            10,
        ),
    ],
)
def test_fully_contained_overlaps_merge_type_and_keep_highest_score(
    detections, expected_start, expected_end
):
    merged = _merge_overlapping_detections(detections)

    assert len(merged) == 1
    assert merged[0]["entity_type"] == "PII"
    assert merged[0]["entity_types"] == {"PERSON", "EMAIL_ADDRESS"}
    assert merged[0]["score"] == 0.9
    assert (merged[0]["start"], merged[0]["end"]) == (
        expected_start,
        expected_end,
    )


def test_partially_overlapping_spans_merge_types_and_extend_end():
    merged = _merge_overlapping_detections(
        [
            {"entity_type": "PERSON", "start": 1, "end": 6, "score": 0.7},
            {"entity_type": "EMAIL_ADDRESS", "start": 4, "end": 9, "score": 0.8},
        ]
    )

    assert len(merged) == 1
    assert merged[0]["entity_type"] == "PII"
    assert merged[0]["entity_types"] == {"PERSON", "EMAIL_ADDRESS"}
    assert (merged[0]["start"], merged[0]["end"], merged[0]["score"]) == (
        1,
        9,
        0.8,
    )


def test_chained_overlaps_merge_into_one_union():
    merged = _merge_overlapping_detections(
        [
            {"entity_type": "PERSON", "start": 0, "end": 5, "score": 0.6},
            {"entity_type": "EMAIL_ADDRESS", "start": 4, "end": 9, "score": 0.8},
            {"entity_type": "PHONE_NUMBER", "start": 8, "end": 12, "score": 0.7},
        ]
    )

    assert len(merged) == 1
    assert merged[0]["entity_type"] == "PII"
    assert merged[0]["entity_types"] == {
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
    }
    assert (merged[0]["start"], merged[0]["end"], merged[0]["score"]) == (
        0,
        12,
        0.8,
    )


def test_adjacent_spans_are_not_merged():
    merged = _merge_overlapping_detections(
        [
            {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 5, "score": 0.8},
            {"entity_type": "PERSON", "start": 5, "end": 10, "score": 0.9},
        ]
    )

    assert len(merged) == 2
    assert [item["entity_type"] for item in merged] == [
        "EMAIL_ADDRESS",
        "PERSON",
    ]


def test_redacts_suppressed_overlap_spans_reported_by_detector():
    text = "prefix ABCDEFGHIJ suffix"
    detections = [
        {
            "entity_type": "PERSON",
            "start": 10,
            "end": 17,
            "score": 0.9,
            "original_text": "DEFGHIJ",
            "conflicts": [
                {
                    "entity_type": "EMAIL_ADDRESS",
                    "start": 7,
                    "end": 12,
                    "score": 0.8,
                    "reason": "overlaps a higher-ranked candidate",
                }
            ],
        }
    ]

    redacted = redact_text(text, detections)

    assert redacted == "prefix [PII] suffix"


def test_custom_aadhaar_and_pan_detection_are_redacted():
    text = "Aadhaar 1234-5678-9012 and PAN ABCDE1234F"

    redacted = redact_text(text)

    assert redacted == "Aadhaar [PII] and PAN [PAN]"


def test_custom_identifier_placeholders_are_used_without_conflicting_spans():
    text = "Aadhaar 1234-5678-9012 and PAN ABCDE1234F"
    aadhaar = "1234-5678-9012"
    pan = "ABCDE1234F"
    detections = [
        {
            "entity_type": "IN_AADHAAR",
            "start": text.index(aadhaar),
            "end": text.index(aadhaar) + len(aadhaar),
            "score": 0.85,
            "original_text": aadhaar,
        },
        {
            "entity_type": "IN_PAN",
            "start": text.index(pan),
            "end": text.index(pan) + len(pan),
            "score": 0.85,
            "original_text": pan,
        },
    ]

    assert redact_text(text, detections) == "Aadhaar [AADHAAR] and PAN [PAN]"


def test_empty_and_multiline_text_are_handled():
    assert redact_text("") == ""
    text = "Email: alex@example.com\nSecond line is unchanged."
    detections = detect_pii(text)

    assert redact_text(text, detections) == (
        "Email: [EMAIL]\nSecond line is unchanged."
    )


def test_generic_entity_uses_a_safe_type_placeholder():
    text = "Account ID: AB-123"
    detections = [
        {
            "entity_type": "CUSTOM-ID!",
            "start": 12,
            "end": 18,
            "score": 0.7,
            "original_text": "AB-123",
        }
    ]

    assert redact_text(text, detections) == "Account ID: [PII]"


def test_summary_counts_types_without_including_sensitive_values():
    detections = [
        {"entity_type": "EMAIL_ADDRESS", "original_text": "secret@example.com"},
        {"entity_type": "EMAIL_ADDRESS", "original_text": "other@example.com"},
        {"entity_type": "IN_PAN", "original_text": "ABCDE1234F"},
    ]

    summary = get_entity_summary(detections)

    assert summary == {
        "total_entities": 3,
        "entity_counts": {"EMAIL_ADDRESS": 2, "IN_PAN": 1},
        "entity_types": ["EMAIL_ADDRESS", "IN_PAN"],
        "suppressed_total": 0,
        "suppressed_entity_counts": {},
        "total_candidates": 3,
    }
    assert "secret@example.com" not in repr(summary)


def test_summary_counts_unique_suppressed_detections_separately():
    detections = [
        {
            "entity_type": "PERSON",
            "start": 0,
            "end": 10,
            "conflicts": [
                {
                    "entity_type": "EMAIL_ADDRESS",
                    "start": 2,
                    "end": 7,
                    "score": 0.8,
                    "reason": "overlap",
                    "original_text": "private",
                },
                {
                    "entity_type": "EMAIL_ADDRESS",
                    "start": 2,
                    "end": 7,
                    "score": 0.7,
                    "reason": "duplicate conflict",
                    "original_text": "private",
                },
                {
                    "entity_type": "PHONE_NUMBER",
                    "start": 6,
                    "end": 10,
                    "score": 0.6,
                    "reason": "overlap",
                    "original_text": "secret",
                },
            ],
        },
        {
            "entity_type": "PERSON",
            "start": 20,
            "end": 28,
            "conflicts": [
                {
                    "entity_type": "EMAIL_ADDRESS",
                    "start": 2,
                    "end": 7,
                    "score": 0.9,
                    "reason": "repeated conflict",
                }
            ],
        },
    ]

    summary = get_entity_summary(detections)

    assert summary == {
        "total_entities": 2,
        "entity_counts": {"PERSON": 2},
        "entity_types": ["PERSON"],
        "suppressed_total": 2,
        "suppressed_entity_counts": {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1},
        "total_candidates": 4,
    }
    assert "private" not in repr(summary)
    assert "secret" not in repr(summary)


def test_empty_detection_summary_has_zero_counts():
    assert get_entity_summary([]) == {
        "total_entities": 0,
        "entity_counts": {},
        "entity_types": [],
        "suppressed_total": 0,
        "suppressed_entity_counts": {},
        "total_candidates": 0,
    }


@pytest.mark.parametrize(
    ("text", "detections", "error"),
    [
        ("abc", [{"entity_type": "PERSON", "start": 2, "end": 9}], ValueError),
        ("abc", [{"entity_type": "PERSON", "start": True, "end": 2}], TypeError),
        (
            "abc",
            [
                {
                    "entity_type": "PERSON",
                    "start": 0,
                    "end": 2,
                    "original_text": "wrong",
                }
            ],
            ValueError,
        ),
    ],
)
def test_invalid_input_is_rejected(text, detections, error):
    with pytest.raises(error):
        redact_text(text, detections)


def test_non_string_text_is_rejected():
    with pytest.raises(TypeError):
        redact_text(42)