"""
In-Memory Paste and Raw File Stream Vault

Features:
- Stores pasted text in RAM
- Receives files as raw HTTP request-body streams
- Does not use multipart/form-data for file uploads
- Does not write uploaded files to disk
- Downloads individual files from memory
- Creates ZIP files entirely in memory
"""

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    send_file,
    render_template_string,
    jsonify,
)

import io
import mimetypes
import os
import urllib.parse
import uuid
import zipfile
import mimetypes
import os

from datetime import datetime


app = Flask(__name__)

app.config["SECRET_KEY"] = "in-memory-vault-secret-key"

# Maximum size of one upload request.
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB

# The browser uses a relative URL for uploads, but keep the API usable by
# explicitly configured frontends as well. Do not reflect arbitrary origins.
configured_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in configured_origins.split(",")
    if origin.strip()
}


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "").rstrip("/")

    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, OPTIONS"
        )
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-Requested-With"
        )

    return response


# All data is stored only in memory.
# The data is lost when the application restarts.
STORAGE = {}


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />

    <title>In-Memory File Vault</title>

    <style>
      :root {
        --background: #0b0f19;
        --card: #151d30;
        --border: #233152;
        --text: #f8fafc;
        --muted: #94a3b8;
        --primary: #4f46e5;
        --primary-hover: #4338ca;
        --success: #059669;
        --danger: #ef4444;
      }

      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family:
          system-ui,
          -apple-system,
          BlinkMacSystemFont,
          sans-serif;
      }

      body {
        min-height: 100vh;
        padding: 2rem 1rem;
        background: var(--background);
        color: var(--text);
      }

      .container {
        width: 100%;
        max-width: 1100px;
        margin: 0 auto;
      }

      header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
        margin-bottom: 2rem;
      }

      h1 {
        font-size: 1.8rem;
      }

      h2,
      h3 {
        margin-bottom: 1rem;
      }

      .subtitle {
        color: var(--muted);
        margin-top: 0.4rem;
      }

      .badge {
        padding: 0.4rem 0.8rem;
        border-radius: 999px;
        background: #064e3b;
        color: #6ee7b7;
        font-size: 0.8rem;
        font-weight: 700;
        white-space: nowrap;
      }

      .summary {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1.5rem;
        padding: 1rem 1.25rem;
        border: 1px solid var(--border);
        border-radius: 12px;
        background: var(--card);
      }

      .summary-actions {
        display: flex;
        gap: 0.75rem;
      }

      .grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 2rem;
      }

      .card {
        padding: 1.5rem;
        border: 1px solid var(--border);
        border-radius: 14px;
        background: var(--card);
      }

      .tabs {
        display: flex;
        gap: 0.5rem;
        margin-bottom: 1.25rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid var(--border);
      }

      .tab-button {
        padding: 0.55rem 1rem;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--background);
        color: var(--muted);
        cursor: pointer;
        font-weight: 600;
      }

      .tab-button.active {
        border-color: var(--primary);
        background: var(--primary);
        color: white;
      }

      label {
        display: block;
        margin-bottom: 0.35rem;
        color: var(--muted);
        font-size: 0.85rem;
      }

      input[type="text"],
      input[type="file"],
      textarea {
        width: 100%;
        margin-bottom: 1rem;
        padding: 0.75rem;
        border: 1px solid var(--border);
        border-radius: 8px;
        outline: none;
        background: var(--background);
        color: white;
      }

      textarea {
        min-height: 220px;
        resize: vertical;
        font-family: monospace;
      }

      input:focus,
      textarea:focus {
        border-color: var(--primary);
      }

      .dropzone {
        margin-bottom: 1rem;
        padding: 2rem 1rem;
        border: 2px dashed var(--border);
        border-radius: 10px;
        background: var(--background);
        text-align: center;
      }

      .dropzone p {
        margin-bottom: 0.75rem;
      }

      .help-text {
        color: var(--muted);
        font-size: 0.8rem;
      }

      button,
      .button {
        display: inline-flex;
        justify-content: center;
        align-items: center;
        padding: 0.65rem 1.25rem;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        text-decoration: none;
        font-weight: 600;
      }

      .primary-button {
        width: 100%;
        background: var(--primary);
        color: white;
      }

      .primary-button:hover {
        background: var(--primary-hover);
      }

      .success-button {
        background: var(--success);
        color: white;
      }

      .secondary-button {
        background: #334155;
        color: #cbd5e1;
      }

      .danger-button {
        background: transparent;
        color: #f87171;
      }

      .items {
        max-height: 560px;
        overflow-y: auto;
      }

      .item {
        margin-bottom: 0.75rem;
        padding: 1rem;
        border: 1px solid var(--border);
        border-radius: 10px;
        background: var(--background);
      }

      .item-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 1rem;
      }

      .filename {
        display: block;
        margin-bottom: 0.35rem;
        color: #818cf8;
        font-family: monospace;
        word-break: break-word;
      }

      .metadata {
        color: var(--muted);
        font-size: 0.78rem;
      }

      .item-actions {
        display: flex;
        gap: 0.5rem;
        margin-top: 0.8rem;
      }

      .item-actions a,
      .item-actions button {
        padding: 0.4rem 0.7rem;
        font-size: 0.8rem;
      }

      .empty {
        padding: 3rem 1rem;
        color: var(--muted);
        text-align: center;
      }

      #upload-status {
        margin-top: 1rem;
        color: var(--muted);
        font-size: 0.85rem;
        text-align: center;
      }

      @media (max-width: 800px) {
        header {
          align-items: flex-start;
          flex-direction: column;
        }

        .summary {
          align-items: flex-start;
          flex-direction: column;
        }

        .grid {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <main class="container">
      <header>
        <div>
          <h1>In-Memory File Vault</h1>
          <p class="subtitle">
            Raw file streams, RAM-only storage, and in-memory ZIP downloads
          </p>
        </div>

        <span class="badge">RAM Storage Active</span>
      </header>

      <section class="summary">
        <span>
          <strong>{{ items|length }}</strong>
          item(s) stored in RAM
          <strong>({{ total_size }})</strong>
        </span>

        {% if items %}
        <div class="summary-actions">
          <a href="{{ url_for('download_zip') }}" class="button success-button">
            Download ZIP
          </a>

          <form
            action="{{ url_for('clear_store') }}"
            method="POST"
            onsubmit="return confirm('Delete all items from memory?');"
          >
            <button type="submit" class="secondary-button">Clear RAM</button>
          </form>
        </div>
        {% endif %}
      </section>

      <section class="grid">
        <div class="card">
          <div class="tabs">
            <button
              type="button"
              class="tab-button active"
              onclick="switchTab('text-tab', this)"
            >
              Paste Text
            </button>

            <button
              type="button"
              class="tab-button"
              onclick="switchTab('file-tab', this)"
            >
              Stream File
            </button>
          </div>

          <div id="text-tab">
            <form action="{{ url_for('create_paste') }}" method="POST">
              <label for="filename"> Filename </label>

              <input
                id="filename"
                type="text"
                name="filename"
                placeholder="notes.txt"
              />

              <label for="content"> Content </label>

              <textarea
                id="content"
                name="content"
                placeholder="Paste text, code, logs, or markdown..."
                required
              ></textarea>

              <button type="submit" class="primary-button">
                Store Text in RAM
              </button>
            </form>
          </div>

          <div id="file-tab" style="display: none">
            <div class="dropzone">
              <p>Select a file to send as a raw HTTP stream</p>

              <p class="help-text">This does not use multipart/form-data.</p>

              <input id="file-input" type="file" />

              <button id="upload-button" type="button" class="primary-button">
                Stream File to Server
              </button>

              <p id="upload-status"></p>
            </div>
          </div>
        </div>

        <div class="card">
          <h3>Stored Items</h3>

          <div class="items">
            {% for item_id, item in items.items() %}
            <article class="item">
              <div class="item-header">
                <div>
                  <strong class="filename"> {{ item.filename }} </strong>

                  <span class="metadata">
                    {{ item.size_str }} &bull; {{ item.mimetype }} &bull; {{
                    item.created_at }}
                  </span>
                </div>

                <span class="metadata">
                  {{ "Binary" if item.is_binary else "Text" }}
                </span>
              </div>

              <div class="item-actions">
                <a
                  href="{{ url_for('view_item', item_id=item.id) }}"
                  class="button secondary-button"
                  target="_blank"
                >
                  View
                </a>

                <a
                  href="{{ url_for('download_file', item_id=item.id) }}"
                  class="button success-button"
                >
                  Download
                </a>

                <form
                  action="{{ url_for('delete_item', item_id=item.id) }}"
                  method="POST"
                >
                  <button type="submit" class="danger-button">Delete</button>
                </form>
              </div>
            </article>
            {% else %}
            <div class="empty">
              No files or text snippets are stored in memory.
            </div>
            {% endfor %}
          </div>
        </div>
      </section>
    </main>

    <script>
      function switchTab(tabId, selectedButton) {
        document.getElementById("text-tab").style.display =
          tabId === "text-tab" ? "block" : "none";

        document.getElementById("file-tab").style.display =
          tabId === "file-tab" ? "block" : "none";

        document.querySelectorAll(".tab-button").forEach((button) => {
          button.classList.remove("active");
        });

        selectedButton.classList.add("active");
      }

      document
        .getElementById("upload-button")
        .addEventListener("click", async () => {
            const fileInput = document.getElementById("file-input");
            const uploadStatus = document.getElementById("upload-status");
            const uploadButton = document.getElementById("upload-button");
            const file = fileInput.files[0];

            if (!file) {
                uploadStatus.textContent = "Please select a file first.";
                return;
            }

            uploadButton.disabled = true;
            uploadStatus.textContent = "Uploading file...";

            try {
                const filename = encodeURIComponent(file.name);

                /*
                 * Use a relative URL so the request stays on the same origin.
                 * The filename is sent in the URL instead of a custom header.
                 */
                const response = await fetch(
                    `/api/upload-stream?filename=${filename}`,
                    {
                        method: "POST",

                        /*
                         * Send the File directly as the raw request body.
                         * Do not use FormData or file.stream().
                         */
                        body: file
                    }
                );

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(
                        result.error || "Upload failed."
                    );
                }

                uploadStatus.textContent =
                    `Stored ${result.filename} ` +
                    `(${result.size_bytes} bytes) in RAM.`;

                setTimeout(() => {
                    window.location.reload();
                }, 700);
            } catch (error) {
                uploadStatus.textContent =
                    `Upload failed: ${error.message}`;
            } finally {
                uploadButton.disabled = false;
            }
        });

  
  </script>   
  </body>
</html>

"""


def format_bytes(num_bytes):
    """Convert a byte count into a readable string."""
    if num_bytes == 0:
        return "0 B"

    value = float(num_bytes)

    for unit in ("B", "KB", "MB", "GB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"

        value /= 1024

    return f"{value:.1f} TB"


def read_request_stream(max_size):
    """
    Read the raw request body in chunks.

    The data is kept in memory and is never saved to disk.
    """
    content_length = request.content_length

    if content_length is not None and content_length > max_size:
        raise ValueError(
            f"File is too large. Maximum size is "
            f"{format_bytes(max_size)}."
        )

    buffer = bytearray()
    total_size = 0
    chunk_size = 1024 * 1024  # 1 MB

    while True:
        chunk = request.stream.read(chunk_size)

        if not chunk:
            break

        total_size += len(chunk)

        if total_size > max_size:
            raise ValueError(
                f"File is too large. Maximum size is "
                f"{format_bytes(max_size)}."
            )

        buffer.extend(chunk)

    return bytes(buffer)


def create_storage_item(filename, raw_bytes, mimetype):
    """Create and store an item in the in-memory storage."""
    item_id = str(uuid.uuid4())[:8]

    text_extensions = (
        ".txt",
        ".json",
        ".py",
        ".md",
        ".csv",
        ".sql",
        ".html",
        ".css",
        ".js",
        ".xml",
        ".yaml",
        ".yml",
    )

    is_binary = (
        not mimetype.startswith("text/")
        and not filename.lower().endswith(text_extensions)
    )

    STORAGE[item_id] = {
        "id": item_id,
        "filename": filename,
        "content": raw_bytes,
        "size_bytes": len(raw_bytes),
        "size_str": format_bytes(len(raw_bytes)),
        "is_binary": is_binary,
        "mimetype": mimetype,
        "created_at": datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
    }

    return STORAGE[item_id]


@app.route("/", methods=["GET"])
def index():
    total_bytes = sum(
        item["size_bytes"]
        for item in STORAGE.values()
    )

    return render_template_string(
        HTML_TEMPLATE,
        items=STORAGE,
        total_size=format_bytes(total_bytes),
    )


@app.route("/paste/new", methods=["POST"])
def create_paste():
    content = request.form.get("content", "").strip()

    if not content:
        return redirect(url_for("index"))

    item_id = str(uuid.uuid4())[:8]

    filename = request.form.get("filename", "").strip()

    if not filename:
        filename = f"paste_{item_id}.txt"

    filename = os.path.basename(filename)

    raw_bytes = content.encode("utf-8")

    mimetype = (
        mimetypes.guess_type(filename)[0]
        or "text/plain; charset=utf-8"
    )

    create_storage_item(
        filename=filename,
        raw_bytes=raw_bytes,
        mimetype=mimetype,
    )

    return redirect(url_for("index"))


@app.route("/api/upload-stream", methods=["POST"])
def api_upload_stream():
    """
    Receive raw file bytes.

    The file content is in the request body.
    The filename is sent as a query parameter.
    """
    max_size = app.config["MAX_CONTENT_LENGTH"]

    filename = request.args.get("filename", "").strip()

    if not filename:
        return jsonify({
            "error": "Missing filename query parameter."
        }), 400

    # Remove any directory component from the supplied name.
    filename = os.path.basename(filename)

    if not filename:
        return jsonify({
            "error": "Invalid filename."
        }), 400

    try:
        raw_bytes = read_request_stream(max_size)
    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 413

    if not raw_bytes:
        return jsonify({
            "error": "The request body is empty."
        }), 400

    mimetype = (
        request.args.get("content_type", "").strip()
        or mimetypes.guess_type(filename)[0]
        or "application/octet-stream"
    )

    item = create_storage_item(
        filename=filename,
        raw_bytes=raw_bytes,
        mimetype=mimetype,
    )

    return jsonify({
        "message": f'Stored "{item["filename"]}" in RAM memory.',
        "item_id": item["id"],
        "filename": item["filename"],
        "size_bytes": item["size_bytes"],
        "mimetype": item["mimetype"],
    }), 201
@app.route("/api/items", methods=["GET"])
def api_get_items():
    """Return metadata for all stored items."""
    summary = [
        {
            "id": item["id"],
            "filename": item["filename"],
            "size_bytes": item["size_bytes"],
            "size_str": item["size_str"],
            "is_binary": item["is_binary"],
            "mimetype": item["mimetype"],
            "created_at": item["created_at"],
        }
        for item in STORAGE.values()
    ]

    return jsonify(summary)


@app.route("/view/<item_id>", methods=["GET"])
def view_item(item_id):
    """Display text files in the browser."""
    item = STORAGE.get(item_id)

    if not item:
        return "Item not found in memory.", 404

    if item["is_binary"]:
        return (
            f"<h3>{item['filename']}</h3>"
            f"<p>Binary file ({item['size_str']}). "
            "Download the file to view it.</p>"
        )

    text_content = item["content"].decode(
        "utf-8",
        errors="replace",
    )

    return (
        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        f"<title>{item['filename']}</title>"
        "</head>"
        "<body>"
        f"<h3>{item['filename']}</h3>"
        "<pre style='"
        "background:#111;"
        "color:#eee;"
        "padding:1.5rem;"
        "white-space:pre-wrap;"
        "font-family:monospace;"
        "'>"
        f"{text_content}"
        "</pre>"
        "</body>"
        "</html>"
    )


@app.route("/download/<item_id>", methods=["GET"])
def download_file(item_id):
    """Download one file from the in-memory byte buffer."""
    item = STORAGE.get(item_id)

    if not item:
        return "Item not found in memory.", 404

    memory_file = io.BytesIO(item["content"])

    return send_file(
        memory_file,
        mimetype=item["mimetype"],
        as_attachment=True,
        download_name=item["filename"],
    )


@app.route("/download-zip", methods=["GET"])
def download_zip():
    """Create a ZIP archive entirely in memory."""
    if not STORAGE:
        return redirect(url_for("index"))

    memory_zip = io.BytesIO()
    used_names = {}

    with zipfile.ZipFile(
        memory_zip,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for item in STORAGE.values():
            original_name = item["filename"]
            archive_name = original_name

            if archive_name in used_names:
                used_names[original_name] += 1

                name, extension = os.path.splitext(original_name)

                archive_name = (
                    f"{name}_{used_names[original_name]}"
                    f"{extension}"
                )
            else:
                used_names[original_name] = 0

            archive.writestr(
                archive_name,
                item["content"],
            )

    memory_zip.seek(0)

    zip_name = (
        "vault_"
        f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        ".zip"
    )

    return send_file(
        memory_zip,
        mimetype="application/zip",
        as_attachment=True,
        download_name=zip_name,
    )


@app.route("/delete/<item_id>", methods=["POST"])
def delete_item(item_id):
    """Delete one item from RAM."""
    STORAGE.pop(item_id, None)

    return redirect(url_for("index"))


@app.route("/clear", methods=["POST"])
def clear_store():
    """Delete all items from RAM."""
    STORAGE.clear()

    return redirect(url_for("index"))


@app.errorhandler(413)
def request_too_large(error):
    """Return a JSON response when Flask rejects an oversized request."""
    if request.path.startswith("/api/"):
        return jsonify({
            "error": "The uploaded file exceeds the 100 MB limit.",
        }), 413

    return "The uploaded file exceeds the 100 MB limit.", 413


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "").lower() == "true",
    )
