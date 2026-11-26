(() => {
    "use strict";

    const toast = document.getElementById("toast");
    let toastTimer;

    function showToast(message) {
        if (!toast) return;
        toast.textContent = message;
        toast.classList.add("is-visible");
        window.clearTimeout(toastTimer);
        toastTimer = window.setTimeout(() => {
            toast.classList.remove("is-visible");
        }, 2600);
    }

    function parseJsonElement(id, fallback) {
        const element = document.getElementById(id);
        if (!element) return fallback;
        try {
            return JSON.parse(element.textContent);
        } catch (_error) {
            return fallback;
        }
    }

    function renderTextWithTokens(element, text) {
        const fragment = document.createDocumentFragment();
        const tokenPattern = /\[[A-Z0-9_]+\]/g;
        let lastIndex = 0;
        let match;

        while ((match = tokenPattern.exec(text)) !== null) {
            if (match.index > lastIndex) {
                fragment.appendChild(
                    document.createTextNode(text.slice(lastIndex, match.index))
                );
            }
            const token = document.createElement("span");
            token.className = "redacted-token";
            token.textContent = match[0];
            fragment.appendChild(token);
            lastIndex = tokenPattern.lastIndex;
        }

        if (lastIndex < text.length) {
            fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
        }
        element.replaceChildren(fragment);
    }

    function codePointOffsetsToUtf16(text, ranges) {
        const offsets = Array.from(
            new Set(ranges.flatMap((range) => [range.start, range.end]))
        ).sort((left, right) => left - right);
        const converted = new Map();
        let codePointIndex = 0;
        let utf16Index = 0;

        for (const target of offsets) {
            if (!Number.isInteger(target) || target < 0) continue;
            while (codePointIndex < target && utf16Index < text.length) {
                const codePoint = text.codePointAt(utf16Index);
                utf16Index += codePoint > 0xffff ? 2 : 1;
                codePointIndex += 1;
            }
            if (codePointIndex === target) {
                converted.set(target, utf16Index);
            }
        }

        return ranges
            .map((range) => ({
                start: converted.get(range.start),
                end: converted.get(range.end),
            }))
            .filter(
                (range) =>
                    Number.isInteger(range.start) &&
                    Number.isInteger(range.end) &&
                    range.start >= 0 &&
                    range.end > range.start &&
                    range.end <= text.length
            );
    }

    function renderHighlightedText(element, text, detections) {
        const candidates = [];
        for (const detection of detections) {
            if (!detection || typeof detection !== "object") continue;
            candidates.push(detection);
            if (Array.isArray(detection.conflicts)) {
                candidates.push(...detection.conflicts);
            }
        }

        const codePointRanges = candidates
            .filter(
                (item) =>
                    Number.isInteger(item.start) &&
                    Number.isInteger(item.end) &&
                    item.start >= 0 &&
                    item.end > item.start
            )
            .map((item) => ({ start: item.start, end: item.end }))
            .sort((left, right) => left.start - right.start || left.end - right.end);

        const mergedRanges = [];
        for (const range of codePointRanges) {
            const previous = mergedRanges[mergedRanges.length - 1];
            if (previous && range.start < previous.end) {
                previous.end = Math.max(previous.end, range.end);
            } else {
                mergedRanges.push({ ...range });
            }
        }

        const ranges = codePointOffsetsToUtf16(text, mergedRanges);
        const fragment = document.createDocumentFragment();
        let lastIndex = 0;

        for (const range of ranges) {
            if (range.start < lastIndex) continue;
            fragment.appendChild(
                document.createTextNode(text.slice(lastIndex, range.start))
            );
            const highlight = document.createElement("mark");
            highlight.className = "sensitive-highlight";
            highlight.textContent = text.slice(range.start, range.end);
            fragment.appendChild(highlight);
            lastIndex = range.end;
        }

        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
        element.replaceChildren(fragment);
    }

    const scanForm = document.getElementById("scan-form");
    if (scanForm) {
        const textInput = document.getElementById("text-input");
        const fileInput = document.getElementById("file-input");
        const dropZone = document.getElementById("drop-zone");
        const selectedFile = document.getElementById("selected-file");
        const selectedFileName = document.getElementById("selected-file-name");
        const removeFileButton = document.getElementById("remove-file");
        const clearButton = document.getElementById("clear-input");
        const characterCount = document.getElementById("character-count");
        const validationMessage = document.getElementById("form-validation");
        const scanButton = document.getElementById("scan-button");
        const loadingState = document.getElementById("loading-state");
        const tabs = Array.from(document.querySelectorAll(".input-tab"));
        const panels = Array.from(document.querySelectorAll(".input-panel"));
        let activeMode = "paste";
        let isSubmitting = false;

        function setValidationMessage(message) {
            validationMessage.textContent = message;
            validationMessage.hidden = !message;
            if (message) {
                if (activeMode === "paste") {
                    textInput.setAttribute("aria-invalid", "true");
                } else {
                    fileInput.setAttribute("aria-invalid", "true");
                }
            } else {
                textInput.removeAttribute("aria-invalid");
                fileInput.removeAttribute("aria-invalid");
            }
        }

        function updateCharacterCount() {
            const count = textInput.value.length;
            characterCount.textContent =
                count === 1 ? "1 character" : `${count.toLocaleString()} characters`;
        }

        function clearSelectedFile() {
            fileInput.value = "";
            selectedFileName.textContent = "";
            selectedFile.hidden = true;
        }

        function clearAllInputs() {
            textInput.value = "";
            clearSelectedFile();
            updateCharacterCount();
            setValidationMessage("");
        }

        function setMode(mode, moveFocus = false) {
            activeMode = mode;
            for (const tab of tabs) {
                const isActive = tab.dataset.mode === mode;
                tab.classList.toggle("is-active", isActive);
                tab.setAttribute("aria-selected", String(isActive));
                tab.tabIndex = isActive ? 0 : -1;
            }
            for (const panel of panels) {
                panel.hidden = panel.dataset.panel !== mode;
            }

            textInput.disabled = mode !== "paste";
            fileInput.disabled = mode !== "upload";
            if (mode === "paste") {
                clearSelectedFile();
                if (moveFocus) textInput.focus();
            } else {
                textInput.value = "";
                updateCharacterCount();
                if (moveFocus) fileInput.focus();
            }
            setValidationMessage("");
        }

        function validateFile(file) {
            if (!file.name.toLowerCase().endsWith(".txt")) {
                return "Please choose a TXT file.";
            }
            if (file.size > 2 * 1024 * 1024) {
                return "The maximum file size is 2 MB.";
            }
            return "";
        }

        function selectFile(file) {
            if (!file) return;
            const error = validateFile(file);
            if (error) {
                clearSelectedFile();
                setValidationMessage(error);
                return;
            }
            selectedFileName.textContent = file.name;
            selectedFile.hidden = false;
            setValidationMessage("");
        }

        tabs.forEach((tab, index) => {
            tab.addEventListener("click", () => setMode(tab.dataset.mode));
            tab.addEventListener("keydown", (event) => {
                let nextIndex = index;
                if (event.key === "ArrowRight") nextIndex = (index + 1) % tabs.length;
                else if (event.key === "ArrowLeft") {
                    nextIndex = (index - 1 + tabs.length) % tabs.length;
                } else if (event.key === "Home") nextIndex = 0;
                else if (event.key === "End") nextIndex = tabs.length - 1;
                else return;

                event.preventDefault();
                tabs[nextIndex].focus();
                setMode(tabs[nextIndex].dataset.mode);
            });
        });

        textInput.addEventListener("input", () => {
            updateCharacterCount();
            if (textInput.value.trim()) setValidationMessage("");
        });

        fileInput.addEventListener("change", () => {
            selectFile(fileInput.files && fileInput.files[0]);
        });

        removeFileButton.addEventListener("click", () => {
            clearSelectedFile();
            setValidationMessage("");
            fileInput.focus();
        });

        clearButton.addEventListener("click", () => {
            clearAllInputs();
            if (activeMode === "paste") textInput.focus();
            else fileInput.focus();
        });

        ["dragenter", "dragover"].forEach((eventName) => {
            dropZone.addEventListener(eventName, (event) => {
                event.preventDefault();
                if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
                dropZone.classList.add("is-dragging");
            });
        });

        ["dragleave", "drop"].forEach((eventName) => {
            dropZone.addEventListener(eventName, (event) => {
                event.preventDefault();
                dropZone.classList.remove("is-dragging");
            });
        });

        dropZone.addEventListener("drop", (event) => {
            const file = event.dataTransfer.files && event.dataTransfer.files[0];
            if (!file) return;
            setMode("upload");
            const transfer = new DataTransfer();
            transfer.items.add(file);
            fileInput.files = transfer.files;
            selectFile(file);
        });

        scanForm.addEventListener("submit", (event) => {
            if (isSubmitting) {
                event.preventDefault();
                return;
            }

            if (activeMode === "paste" && !textInput.value.trim()) {
                event.preventDefault();
                setValidationMessage("Enter some text before starting the scan.");
                textInput.focus();
                return;
            }

            if (activeMode === "upload") {
                const file = fileInput.files && fileInput.files[0];
                if (!file) {
                    event.preventDefault();
                    setValidationMessage("Choose a TXT file to upload.");
                    return;
                }
                const fileError = validateFile(file);
                if (fileError) {
                    event.preventDefault();
                    setValidationMessage(fileError);
                    return;
                }
            }

            isSubmitting = true;
            scanButton.disabled = true;
            scanButton.setAttribute("aria-disabled", "true");
            scanForm.setAttribute("aria-busy", "true");
            loadingState.hidden = false;
        });

        updateCharacterCount();
        setMode("paste");
    }

    const originalElement = document.getElementById("original-text");
    const redactedElement = document.getElementById("redacted-text");
    if (originalElement && redactedElement) {
        const originalText = parseJsonElement("original-text-data", originalElement.textContent);
        const redactedText = parseJsonElement("redacted-text-data", redactedElement.textContent);
        const detections = parseJsonElement("detection-data", []);

        if (typeof originalText === "string" && Array.isArray(detections)) {
            renderHighlightedText(originalElement, originalText, detections);
        }
        if (typeof redactedText === "string") {
            renderTextWithTokens(redactedElement, redactedText);
            const downloadField = document.querySelector(
                'form.download-form [name="redacted_text"]'
            );
            if (downloadField) downloadField.value = redactedText;
        }

        const copyButton = document.getElementById("copy-redacted");
        if (copyButton) {
            copyButton.addEventListener("click", async () => {
                const text = redactedElement.textContent;
                try {
                    if (navigator.clipboard && window.isSecureContext) {
                        await navigator.clipboard.writeText(text);
                    } else {
                        const temporary = document.createElement("textarea");
                        temporary.value = text;
                        temporary.setAttribute("readonly", "");
                        temporary.style.position = "fixed";
                        temporary.style.opacity = "0";
                        document.body.appendChild(temporary);
                        temporary.select();
                        const copied = document.execCommand("copy");
                        temporary.remove();
                        if (!copied) throw new Error("Copy command was unavailable.");
                    }
                    showToast("Redacted text copied to clipboard.");
                } catch (_error) {
                    showToast("Could not copy automatically. Select and copy the text.");
                }
            });
        }
    }
})();