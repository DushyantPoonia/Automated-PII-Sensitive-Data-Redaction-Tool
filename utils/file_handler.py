"""In-memory validation and decoding for uploaded TXT files."""

from __future__ import annotations

from typing import AbstractSet

from werkzeug.datastructures import FileStorage


class UploadError(ValueError):
    """Base class for expected file-upload validation failures."""


class NoFileSelectedError(UploadError):
    """Raised when a file input has no selected filename."""


class UnsupportedFileTypeError(UploadError):
    """Raised when the upload extension is not allowed."""


class UploadTooLargeError(UploadError):
    """Raised when the uploaded bytes exceed the configured size limit."""


class InvalidTextFileError(UploadError):
    """Raised when the upload cannot be treated as UTF-8 text."""


def read_uploaded_text(
    uploaded_file: FileStorage,
    max_size: int,
    allowed_extensions: AbstractSet[str] = frozenset({"txt"}),
) -> str:
    """Validate and decode an upload without writing it to disk.

    The user-supplied filename is consulted only for its extension; it is
    never used as a path or persisted.
    """
    if not uploaded_file or not uploaded_file.filename:
        raise NoFileSelectedError("No file was selected.")

    extension = uploaded_file.filename.rpartition(".")[2].lower()
    if extension not in {item.lower().lstrip(".") for item in allowed_extensions}:
        raise UnsupportedFileTypeError("Unsupported file type. Upload a .txt file.")
    if max_size < 0:
        raise ValueError("max_size must not be negative.")

    content = uploaded_file.stream.read(max_size + 1)
    if len(content) > max_size:
        raise UploadTooLargeError("The uploaded file exceeds the 2 MB limit.")

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidTextFileError(
            "The uploaded file must use UTF-8 text encoding."
        ) from exc

    if "\x00" in text:
        raise InvalidTextFileError("The uploaded file is not valid text.")
    return text