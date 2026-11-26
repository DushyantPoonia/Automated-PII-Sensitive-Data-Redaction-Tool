"""Tests for Presidio and custom-pattern PII detection."""

import pytest

from detection import detect_pii


@pytest.mark.parametrize(
    ("text", "entity_type", "expected_text"),
    [
        ("Message: John Smith will call.", "PERSON", "John Smith"),
        (
            "Contact john.smith@example.com today.",
            "EMAIL_ADDRESS",
            "john.smith@example.com",
        ),
        ("Call +1-415-555-2671 today.", "PHONE_NUMBER", "+1-415-555-2671"),
        ("Mary Johnson lives in Seattle.", "LOCATION", "Seattle"),
        ("Aadhaar: 2345 6789 0123.", "IN_AADHAAR", "2345 6789 0123"),
        ("PAN: ABCDE1234F.", "IN_PAN", "ABCDE1234F"),
    ],
)
def test_detects_entity_with_exact_original_offsets(text, entity_type, expected_text):
    detections = detect_pii(text)

    matches = [item for item in detections if item["entity_type"] == entity_type]
    assert any(
        item["start"] >= 0
        and item["end"] <= len(text)
        and text[item["start"] : item["end"]] == expected_text
        and item["original_text"] == expected_text
        for item in matches
    )
    assert all(item["end"] > item["start"] for item in detections)


def test_detects_multiple_entity_types_in_one_paragraph_with_valid_offsets():
    text = (
        "John Smith lives in Seattle. Contact john.smith@example.com or "
        "+1-415-555-2671. Aadhaar 2345 6789 0123; PAN ABCDE1234F."
    )

    detections = detect_pii(text)

    assert {
        "PERSON",
        "LOCATION",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "IN_AADHAAR",
        "IN_PAN",
    }.issubset({item["entity_type"] for item in detections})
    for item in detections:
        assert 0 <= item["start"] < item["end"] <= len(text)
        assert item["original_text"] == text[item["start"] : item["end"]]


def test_detects_repeated_entities_at_each_original_offset():
    text = "Email alex@example.com and alex@example.com again."
    email = "alex@example.com"
    expected_spans = [
        (text.index(email), text.index(email) + len(email)),
        (text.rindex(email), text.rindex(email) + len(email)),
    ]

    detections = [
        item for item in detect_pii(text) if item["entity_type"] == "EMAIL_ADDRESS"
    ]

    assert [(item["start"], item["end"]) for item in detections] == expected_spans
    assert all(item["original_text"] == email for item in detections)


def test_text_without_pii_returns_no_detections():
    assert detect_pii("A routine status update is ready for review.") == []


def test_empty_and_whitespace_text_are_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        detect_pii("")
    with pytest.raises(ValueError, match="must not be empty"):
        detect_pii(" \n\t ")


def test_non_string_input_is_rejected():
    with pytest.raises(TypeError, match="must be a string"):
        detect_pii(None)