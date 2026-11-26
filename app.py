"""Flask routes for scanning text and downloading redacted results."""

from __future__ import annotations

import io
import secrets

from flask import (
    Flask,
    current_app,
    make_response,
    render_template,
    request,
    send_file,
)
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from config import Config
from detection import detect_pii
from redaction import get_entity_summary, redact_text
from utils import (
    InvalidTextFileError,
    NoFileSelectedError,
    UnsupportedFileTypeError,
    UploadTooLargeError,
    read_uploaded_text,
)

csrf = CSRFProtect()


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        if app.config["APP_ENV"] == "production":
            raise RuntimeError("Set FLASK_SECRET_KEY before starting in production.")
        app.config["SECRET_KEY"] = secrets.token_urlsafe(32)

    csrf.init_app(app)

    @app.context_processor
    def provide_csrf_token() -> dict[str, object]:
        """Make Flask-WTF's token generator available to the templates."""
        return {"csrf_token": generate_csrf}

    def render_home(message: str | None = None, status: int = 200):
        return render_template("index.html", error_message=message), status

    @app.get("/")
    def home():
        """Render the text-entry and TXT-upload page."""
        return render_template("index.html")

    @app.post("/scan")
    def scan():
        """Validate input, detect and redact PII, then render the results."""
        pasted_text = request.form.get("text", "")
        if not isinstance(pasted_text, str):
            return render_home("Text input must be plain text.", 400)

        uploads = request.files.getlist("file")
        if len(uploads) > 1:
            return render_home("Upload only one TXT file at a time.", 400)
        uploaded_file = uploads[0] if uploads else None
        has_selected_file = bool(uploaded_file and uploaded_file.filename)

        if has_selected_file and pasted_text.strip():
            return render_home(
                "Paste text or upload a file, but do not submit both.", 400
            )

        if has_selected_file:
            try:
                text = read_uploaded_text(
                    uploaded_file,
                    max_size=current_app.config["MAX_UPLOAD_SIZE"],
                    allowed_extensions=current_app.config["ALLOWED_EXTENSIONS"],
                )
            except NoFileSelectedError as exc:
                return render_home(str(exc), 400)
            except UnsupportedFileTypeError as exc:
                return render_home(str(exc), 400)
            except UploadTooLargeError as exc:
                return render_home(str(exc), 413)
            except InvalidTextFileError as exc:
                return render_home(str(exc), 400)
        elif uploaded_file is not None and not pasted_text.strip():
            return render_home("No file was selected.", 400)
        else:
            text = pasted_text

        if not text.strip():
            return render_home("Enter text or select a TXT file to scan.", 400)

        try:
            detections = detect_pii(text)
        except (RuntimeError, ValueError, TypeError):
            current_app.logger.error("PII detection failed.")
            return render_home("PII detection failed. Please try again.", 500)

        try:
            sanitized_text = redact_text(text, detections)
        except (RuntimeError, ValueError, TypeError):
            current_app.logger.error("PII redaction failed.")
            return render_home("Text redaction failed. Please try again.", 500)

        try:
            summary = get_entity_summary(detections)
        except (ValueError, TypeError):
            current_app.logger.error("PII results could not be summarized.")
            return render_home("Scan results could not be prepared.", 500)

        return render_template(
            "results.html",
            original_text=text,
            redacted_text=sanitized_text,
            detections=detections,
            total_entities=summary["total_entities"],
            entity_counts=summary["entity_counts"],
            entity_types=summary["entity_types"],
        )

    @app.post("/download")
    def download():
        """Return submitted sanitized text as an in-memory TXT attachment."""
        sanitized_text = request.form.get("redacted_text")
        if not isinstance(sanitized_text, str) or not sanitized_text:
            return render_home("There is no sanitized text to download.", 400)

        content = sanitized_text.encode("utf-8")
        if len(content) > current_app.config["MAX_UPLOAD_SIZE"]:
            return render_home(
                "The sanitized text exceeds the 2 MB download limit.", 413
            )

        response = make_response(
            send_file(
                io.BytesIO(content),
                mimetype="text/plain; charset=utf-8",
                as_attachment=True,
                download_name="redacted_text.txt",
                max_age=0,
            )
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(_error: CSRFError):
        return render_home(
            "The form could not be verified. Reload the page and try again.", 400
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(_error: RequestEntityTooLarge):
        return render_home("The submitted request exceeds the size limit.", 413)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        if isinstance(error, HTTPException):
            return error
        current_app.logger.error("An unexpected application error occurred.")
        return render_home("An unexpected error occurred. Please try again.", 500)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])