"""Custom Presidio pattern recognizers for Indian identifier formats."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from presidio_analyzer import PatternRecognizer


def create_aadhaar_recognizer() -> PatternRecognizer:
    """Create a recognizer for 12-digit Aadhaar-style numbers.

    The pattern allows digits as one group or in three groups of four, with
    optional spaces or hyphens between groups. It checks format only and does
    not validate that a number was issued or is officially valid.
    """
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        name="Indian Aadhaar Pattern Recognizer",
        supported_entity="IN_AADHAAR",
        supported_language="en",
        patterns=[
            Pattern(
                name="aadhaar_style_12_digits",
                regex=r"\b[0-9]{4}(?:[ -]?[0-9]{4}){2}\b",
                score=0.85,
            )
        ],
        context=["aadhaar", "aadhar", "uid"],
    )


def create_pan_recognizer() -> PatternRecognizer:
    """Create a recognizer for the common uppercase Indian PAN format."""
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        name="Indian PAN Pattern Recognizer",
        supported_entity="IN_PAN",
        supported_language="en",
        patterns=[
            Pattern(
                name="pan_five_letters_four_digits_one_letter",
                # The scoped flag keeps PAN uppercase-only even when Presidio's
                # default regex flags include IGNORECASE.
                regex=r"\b(?-i:[A-Z]{5}[0-9]{4}[A-Z])\b",
                score=0.85,
            )
        ],
        context=["pan", "permanent account number"],
    )