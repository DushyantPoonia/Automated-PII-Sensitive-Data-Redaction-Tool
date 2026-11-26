"""Tests for the Flask scanning and download routes."""

from io import BytesIO

import pytest

import app as app_module
from app import create_app


@pytest.fixture
def client():
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret",
            "WTF_CSRF_ENABLED": False,
        }
    )
    return application.test_client()


def _stub_scan(monkeypatch, detections=None, sanitized="[PERSON]"):
    monkeypatch.setattr(app_module, "detect_pii", lambda _text: detections or [])
    monkeypatch.setattr(app_module, "redact_text", lambda _text, _detections: sanitized)


def test_homepage_renders(client):
    response = client.get("/")

    assert response.status_code == 200


def test_scan_accepts_pasted_text_and_passes_results(monkeypatch, client):
    detections = [
        {
            "entity_type": "PERSON",
            "start": 0,
            "end": 10,
            "score": 0.9,
            "original_text": "Jane Smith",
        }
    ]
    _stub_scan(monkeypatch, detections, "[PERSON]")
    rendered = {}

    def capture_template(template_name, **context):
        rendered["template_name"] = template_name
        rendered.update(context)
        return "rendered"

    monkeypatch.setattr(app_module, "render_template", capture_template)

    response = client.post("/scan", data={"text": "Jane Smith has PII."})

    assert response.status_code == 200
    assert rendered["template_name"] == "results.html"
    assert rendered["original_text"] == "Jane Smith has PII."
    assert rendered["redacted_text"] == "[PERSON]"
    assert rendered["detections"] == detections
    assert rendered["total_entities"] == 1
    assert rendered["entity_counts"] == {"PERSON": 1}
    assert rendered["entity_types"] == ["PERSON"]


def test_scan_with_no_pii_is_still_successful(monkeypatch, client):
    _stub_scan(monkeypatch, detections=[], sanitized="Nothing to redact.")
    rendered = {}

    def capture_template(template_name, **context):
        rendered["template_name"] = template_name
        rendered.update(context)
        return "rendered"

    monkeypatch.setattr(app_module, "render_template", capture_template)

    response = client.post("/scan", data={"text": "Nothing to redact."})

    assert response.status_code == 200
    assert rendered["total_entities"] == 0
    assert rendered["redacted_text"] == "Nothing to redact."


def test_detection_failure_returns_generic_error_without_logging_input(
    monkeypatch, client, caplog
):
    sensitive_input = "Private text that must not appear in logs."

    def fail_detection(_text):
        raise RuntimeError("internal failure")

    monkeypatch.setattr(app_module, "detect_pii", fail_detection)

    response = client.post("/scan", data={"text": sensitive_input})

    assert response.status_code == 500
    assert sensitive_input not in caplog.text
    assert sensitive_input not in response.get_data(as_text=True)
    assert "Traceback" not in response.get_data(as_text=True)


def test_redaction_failure_returns_generic_error(monkeypatch, client, caplog):
    sensitive_input = "Private text that must not appear in logs."
    monkeypatch.setattr(app_module, "detect_pii", lambda _text: [])

    def fail_redaction(_text, _detections):
        raise RuntimeError("internal failure")

    monkeypatch.setattr(app_module, "redact_text", fail_redaction)

    response = client.post("/scan", data={"text": sensitive_input})

    assert response.status_code == 500
    assert sensitive_input not in caplog.text
    assert "Traceback" not in response.get_data(as_text=True)


def test_scan_accepts_txt_upload(monkeypatch, client):
    _stub_scan(monkeypatch)

    response = client.post(
        "/scan",
        data={"file": (BytesIO(b"Jane Smith"), "private.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200


def test_upload_filename_is_not_used_as_a_filesystem_path(monkeypatch, client):
    _stub_scan(monkeypatch)

    response = client.post(
        "/scan",
        data={"file": (BytesIO(b"in-memory text"), "../../untrusted.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("data", "expected_status"),
    [
        ({"text": "  "}, 400),
        ({"file": (BytesIO(b""), "")}, 400),
        ({"file": (BytesIO(b"data"), "document.pdf")}, 400),
        ({"file": (BytesIO(b"\xff\xfe"), "document.txt")}, 400),
        ({"file": (BytesIO(b"plain\x00text"), "document.txt")}, 400),
        (
            {"file": (BytesIO(b"x" * (2 * 1024 * 1024 + 1)), "large.txt")},
            413,
        ),
    ],
)
def test_scan_rejects_invalid_input(client, data, expected_status):
    response = client.post(
        "/scan",
        data=data,
        content_type="multipart/form-data" if "file" in data else None,
    )

    assert response.status_code == expected_status


def test_scan_rejects_when_text_and_file_are_both_submitted(client):
    response = client.post(
        "/scan",
        data={
            "text": "pasted text",
            "file": (BytesIO(b"uploaded text"), "input.txt"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400


def test_scan_escapes_untrusted_html_in_results(monkeypatch, client):
    monkeypatch.setattr(app_module, "detect_pii", lambda _text: [])
    monkeypatch.setattr(app_module, "redact_text", lambda text, _detections: text)
    untrusted_text = "<script>alert('xss')</script> ordinary text."

    response = client.post("/scan", data={"text": untrusted_text})
    rendered = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "<script>alert('xss')</script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_download_returns_sanitized_text_as_attachment(client):
    response = client.post("/download", data={"redacted_text": "Hello [PERSON]"})

    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    assert response.headers["Content-Disposition"].endswith(
        'filename=redacted_text.txt'
    )
    assert response.get_data(as_text=True) == "Hello [PERSON]"
    assert response.headers["Cache-Control"] == "no-store"


def test_download_rejects_empty_sanitized_text(client):
    response = client.post("/download", data={"redacted_text": ""})

    assert response.status_code == 400


def test_post_routes_require_csrf():
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret",
            "WTF_CSRF_ENABLED": True,
        }
    )

    test_client = application.test_client()

    scan_response = test_client.post("/scan", data={"text": "Hello"})
    download_response = test_client.post(
        "/download", data={"redacted_text": "Sanitized"}
    )

    assert scan_response.status_code == 400
    assert download_response.status_code == 400