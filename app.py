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
import base64
import json
import os
import uuid
import zipfile

from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)

app.config["SECRET_KEY"] = "in-memory-vault-secret-key"
private_key_text = '''-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+5y0CVnUL/IRp
Vl7PQdFLBPkvZw9fLEODLUszn+r+ZioyVvKjKj5fBk3ZNAykKdL4G73ucEwe1RXB
ClczvVRN6MGT7M5ZRK6Uyy1jWy87ZPZzIG984REpk5flZ862OUH2/qtASeUUXMHy
wv2++EyL/wKMMF+iZq6zsS/IFK6WR0RIq9LrDZTDsi875tKVTi/QJuYgUsVXmeKW
7SRoia0UTp6I3eEFiMsVhWonEHV9EGX2TJmgTEggNY1yVr5L8vS/R6B4ma7/ci/V
TrIJIBDEQI8ISkP3UDCgwKXso674zWZYCuIv42i7ca54xwk6PTFchyzhBHdv6GB7
ozAJJAJ5AgMBAAECggEAAnclFkmETbUzRxJ72zieAbZk2vM9aDTfwtUOCnLDY8lx
PFDx5YBNSaggz4Ar9R9Kp5RhI7AM1Z2aIDH4XhVQ/kgWHulRIWdBC3AjzAuQjLdx
NNurgOz9riAnNynb6i/LXaucjdIefKC1iwNwaDvX7jtq/qE9zPC/SxgL1k1JE2z+
ubyOP+WRB9uy555/EYkK5Kgz6iyUmUmWmU+JIcDarqhH6uGFElNJNf384aWhjxsg
X1DSdikdjKiWYs9qEr4TcZPo1qayJg/ahy2EI/pWRxNB36HIcJ8gMKNptQwLCo5C
Z4FDnyQ4abcUOj/evC6MO21z0xV1WmthExlwP3JCYQKBgQDokSJdE3Hp/lsEtaVG
+l0nL/Ssabrp1oJ3p11QHZlNVTEMTmX8edajUYmX1cFrVgkUDHOercCpKVmDidST
fiJp9Rsk3PASfavz5AXLS9zdIiQH02gzdM2b2T33KyEPOHa0/R3mE4tfRnQp9S8M
CDwtStuHY/hED269HFw5UI0YGQKBgQDSI1tWoIBahs/O+FDWuIMIfWIuteBUOnJh
jVU+aKkWSBF82wV2Hd46lekut9dQZ3k0hB9LorVy8rwdcsIZNqZUX/oSaDHu2d3z
V1DlYUgdd2Ci6m3R7Znj6GkOubi9IuO61znsmZzekGdcQyOLTRCUxNN1O+6KTBoP
gqlsyx0JYQKBgD5jeNF5PuzjxCz+QalJzqWNktiRwIesePF6X2j3l8GMIg1IFsnl
MXQ8kmm9+RY/TU4ojPe7aty2cAH+fp1WkArWqwJ3lpuPRQq3V+qSnlxgJURILULo
iaPOYnYlBshbgFTLNjMbeR8E+nKrCIT0zJfl5gBrDBXOAgoPSppBhqg5AoGAX6w1
U7VzesPSLTslIv2SuvTLFNU9s1uA5CVC4E0qXrilLaFSVTq4CRhjuB9/al4R8vUM
gpUr44/cUdQDxxL4m4WvB15lDYgn4zin3idye+f0GXh+U4vH+tm/qzKnh4UxBcoj
1zMBFtvME1eGAVAu8mzCkaedrV2Ep/cnSB8Zs0ECgYEAuyfiYJ8UYx2xg85irqA3
aU3oOWrR1lenr26vigKVj/VLAQc9edMMtoQo3yRPIoo8/7/P0oIPX1pg7K3/CSVe
CqnbIIDrvP36SdxaPqGuwTMu+IjiCwttExDQ7PzuQvUTkFQHvnI+revsK/4+p2+/
kl5I+MmCv95t2gsW2hhUlig=
-----END PRIVATE KEY-----
'''
if private_key_text:
    try:
        SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
            private_key_text.encode("ascii"),
            password=None,
        )
    except (ValueError, TypeError, UnicodeEncodeError) as error:
        raise RuntimeError(
            "VAULT_RSA_PRIVATE_KEY must contain a valid PEM private key."
        ) from error
else:
    SERVER_PRIVATE_KEY = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
SERVER_PUBLIC_KEY_PEM = SERVER_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
SERVER_PUBLIC_KEY_DER = SERVER_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Maximum size of one upload request.
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB

# The API is public by default. Set CORS_ALLOWED_ORIGINS to a comma-separated
# list of origins if the deployment should be restricted later.
configured_origins = os.getenv("CORS_ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in configured_origins.split(",")
    if origin.strip()
}
ALLOW_ALL_ORIGINS = "*" in ALLOWED_ORIGINS


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "").rstrip("/")

    if ALLOW_ALL_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = "*"
    elif origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"

    if ALLOW_ALL_ORIGINS or (origin and origin in ALLOWED_ORIGINS):
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, OPTIONS"
        )
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-Requested-With"
        )

    return response


# All data is stored only in memory. Browsers encrypt content before insertion.
# The data is lost when the application restarts.
STORAGE = {}


HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />

    <title>Obsidian Relay</title>

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

      #file-info,
      #file-preview {
        width: 100%;
        margin-top: 1rem;
        padding: 0.85rem;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--background);
        color: var(--muted);
        font: 0.78rem/1.5 monospace;
        overflow: auto;
        white-space: pre-wrap;
        word-break: break-word;
      }

      #file-preview {
        max-height: 220px;
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
          <h1>Obsidian Relay</h1>
          <p class="subtitle">
            Aster packets, transient staging, and sealed retrieval
          </p>
        </div>

        <span class="badge">Drift Channel Active</span>
      </header>

      <section class="summary">
        <span>
          <strong>{{ items|length }}</strong>
          item(s) stored in RAM
          <strong>({{ total_size }})</strong>
        </span>

        {% if items %}
        <div class="summary-actions">
          <form
            action="{{ url_for('clear_store') }}"
            method="POST"
            onsubmit="return confirm('Delete all items from memory?');"
          >
            <button type="submit" class="secondary-button">Reset Drift</button>
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
              Lumen Input
            </button>

            <button
              type="button"
              class="tab-button"
              onclick="switchTab('file-tab', this)"
            >
              Quill Transfer
            </button>
          </div>

          <div id="text-tab">
            <form id="paste-form" action="{{ url_for('create_paste') }}" method="POST">
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
                Commit Lumen
              </button>
            </form>
          </div>

          <div id="file-tab" style="display: none">
            <div class="dropzone">
              <p>Select a file to send as a raw HTTP stream</p>

              <p class="help-text">This does not use multipart/form-data.</p>

              <input id="file-input" type="file" />

              <button id="upload-button" type="button" class="primary-button">
                Send Quill
              </button>

              <pre id="file-info" hidden></pre>
              <pre id="file-preview" hidden></pre>
              <p id="upload-status"></p>
            </div>
          </div>
        </div>

        <div class="card">
          <h3>Aster Index</h3>

          <div class="items">
            {% for item_id, item in items.items() %}
            <article class="item">
              <div class="item-header">
                <div>
                  <strong class="filename">Encrypted item {{ item.id }}</strong>
                </div>
                <span class="metadata">{{ item.encrypted_size }} bytes encrypted</span>
              </div>

              <div class="item-actions">
                <button
                  type="button"
                  class="button secondary-button client-view"
                  data-item-id="{{ item.id }}"
                >
                  Open
                </button>

                <button
                  type="button"
                  class="button success-button client-download"
                  data-item-id="{{ item.id }}"
                >
                  Retrieve
                </button>

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
              The index is currently quiet.
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

      const fileInput = document.getElementById("file-input");
      const fileInfo = document.getElementById("file-info");
      const filePreview = document.getElementById("file-preview");
      const maxPreviewBytes = 4096;
      const textFilePattern =
        /\\.(txt|log|md|json|js|jsx|ts|tsx|py|java|c|cpp|h|css|html|xml|yaml|yml|csv|svg)$/i;

      function bytesToBase64(bytes) {
        let binary = "";
        for (let index = 0; index < bytes.length; index += 0x8000) {
          binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
        }
        return btoa(binary);
      }

      function base64ToBytes(value) {
        const binary = atob(value);
        return Uint8Array.from(binary, (character) => character.charCodeAt(0));
      }

      function createEnvelope(fileMetadata, content) {
        return {
          version: 1,
          metadata: {
            ...fileMetadata,
            encrypted_at: new Date().toISOString()
          },
          content: bytesToBase64(content)
        };
      }

      async function cloakEnvelope(envelope) {
        const keyResponse = await fetch("/aurora/orbit", {
          credentials: "same-origin",
          cache: "no-store"
        });
        if (!keyResponse.ok) {
          throw new Error(`Could not load encryption key (HTTP ${keyResponse.status}).`);
        }
        const publicKey = await crypto.subtle.importKey(
          "spki",
          await keyResponse.arrayBuffer(),
          { name: "RSA-OAEP", hash: "SHA-256" },
          false,
          ["encrypt"]
        );
        const contentKey = await crypto.subtle.generateKey(
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"]
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const sealed = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          contentKey,
          new TextEncoder().encode(JSON.stringify(envelope))
        );
        const rawKey = await crypto.subtle.exportKey("raw", contentKey);
        const wrappedKey = await crypto.subtle.encrypt(
          { name: "RSA-OAEP" },
          publicKey,
          rawKey
        );
        return JSON.stringify({
          version: 2,
          wrapped_key: bytesToBase64(new Uint8Array(wrappedKey)),
          iv: bytesToBase64(iv),
          ciphertext: bytesToBase64(new Uint8Array(sealed))
        });
      }

      function bytesToHex(bytes) {
        return Array.from(bytes, (byte) =>
          byte.toString(16).padStart(2, "0")
        ).join(" ");
      }

      function explainError(error) {
        if (error instanceof Error && error.message) {
          return error.message;
        }
        if (typeof error === "string" && error) {
          return error;
        }
        try {
          return JSON.stringify(error);
        } catch {
          return "Unknown browser error.";
        }
      }

      async function inspectFile(file) {
        const metadata = {
          name: file.name,
          type: file.type || "unknown",
          size_bytes: file.size,
          last_modified: new Date(file.lastModified).toISOString()
        };

        console.group("Selected file");
        console.log("Metadata:", metadata);

        fileInfo.textContent = JSON.stringify(metadata, null, 2);
        fileInfo.hidden = false;

        const preview = await file.slice(0, maxPreviewBytes).arrayBuffer();
        const previewBytes = new Uint8Array(preview);
        const isLikelyText =
          file.type.startsWith("text/") || textFilePattern.test(file.name);

        if (isLikelyText) {
          const text = new TextDecoder().decode(previewBytes);
          console.log("Content preview:", text);
          filePreview.textContent =
            `Text preview (first ${previewBytes.length} bytes):\n\n${text}`;
        } else {
          const hex = bytesToHex(previewBytes);
          console.log("Binary preview (hex):", hex);
          filePreview.textContent =
            `Binary preview (first ${previewBytes.length} bytes, hex):\n\n${hex}`;
        }

        console.log(
          `Preview limited to ${maxPreviewBytes} bytes; full size is ${file.size} bytes.`
        );
        console.groupEnd();
        filePreview.hidden = false;
      }

      fileInput.addEventListener("change", async () => {
        const file = fileInput.files[0];

        if (!file) {
          fileInfo.hidden = true;
          filePreview.hidden = true;
          return;
        }

        try {
          await inspectFile(file);
        } catch (error) {
          console.error("Could not inspect selected file:", error);
          filePreview.textContent =
            `Could not read a preview: ${error.message}`;
          filePreview.hidden = false;
        }
      });

      document
        .getElementById("upload-button")
        .addEventListener("click", async () => {
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
                const content = new Uint8Array(await file.arrayBuffer());
                const envelope = createEnvelope({
                    name: file.name,
                    type: file.type || "application/octet-stream",
                    size_bytes: file.size,
                    last_modified: file.lastModified,
                    relative_path: file.webkitRelativePath || ""
                }, content);
                const cloakedPayload = await cloakEnvelope(envelope);

                /*
                 * Send only the encrypted envelope. No file metadata is sent
                 * in the URL, headers, or other plaintext request fields.
                 */
                const response = await fetch(
                    "/quasar/relay",
                    {
                        method: "POST",
                        credentials: "same-origin",
                        cache: "no-store",

                        /* Send only the encrypted envelope as the raw body. */
                        body: cloakedPayload
                    }
                );

                const contentType =
                    response.headers.get("content-type") || "";
                const result = contentType.includes("application/json")
                    ? await response.json()
                    : {};

                if (!response.ok) {
                    throw new Error(
                        result.error || "Upload failed."
                    );
                }

                uploadStatus.textContent = `Stored encrypted item ${result.item_id} in RAM.`;

                setTimeout(() => {
                    window.location.reload();
                }, 700);
            } catch (error) {
                const message = error instanceof TypeError
                    ? "The upload request was blocked before reaching the "
                      + "server. Check the network proxy or firewall."
                    : explainError(error);

                uploadStatus.textContent = `Upload failed: ${message}`;
            } finally {
                uploadButton.disabled = false;
            }
        });

      document.getElementById("paste-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = event.currentTarget;
        const content = form.elements.content.value;
        const filename = form.elements.filename.value.trim() || "paste.txt";

        if (!content) return;

        try {
          const plaintext = new TextEncoder().encode(content);
          const envelope = createEnvelope({
            name: filename,
            type: "text/plain",
            size_bytes: plaintext.length,
            last_modified: Date.now(),
            relative_path: ""
          }, plaintext);
          const cloakedPayload = await cloakEnvelope(envelope);
          const response = await fetch(
            "/quasar/relay",
            {
              method: "POST",
              credentials: "same-origin",
              cache: "no-store",
              body: cloakedPayload
            }
          );
          if (!response.ok) {
            const result = await response.json();
            throw new Error(result.error || "Could not store pasted content.");
          }
          window.location.reload();
        } catch (error) {
          alert(`Could not encrypt and store content: ${explainError(error)}`);
        }
      });

      async function loadEncryptedItems() {
        const response = await fetch("/nebula/catalog", {
          credentials: "same-origin",
          cache: "no-store"
        });
        if (!response.ok) throw new Error("Could not load encrypted items.");

        const items = await response.json();
        const list = document.querySelector(".items");
        list.replaceChildren();

        for (const item of items) {
          try {
            const decrypted = item;
            const article = document.createElement("article");
            article.className = "item";
            article.innerHTML = `
              <div class="item-header">
                <div>
                  <strong class="filename"></strong>
                  <span class="metadata"></span>
                </div>
                <span class="metadata">${item.encrypted_size} encrypted bytes</span>
              </div>
              <div class="item-actions">
                <button type="button" class="button secondary-button">Open</button>
                <button type="button" class="button success-button">Retrieve</button>
              </div>`;
            article.querySelector(".filename").textContent = decrypted.name;
            article.querySelector(".metadata").textContent =
              `${decrypted.size_bytes} bytes | ${decrypted.type || "unknown"}`;
            article.querySelector(".secondary-button").addEventListener(
              "click", () => clientDownloadById(item.id, true)
            );
            article.querySelector(".success-button").addEventListener(
              "click", () => clientDownloadById(item.id, false)
            );
            list.appendChild(article);
          } catch (error) {
            throw new Error(`Could not decrypt item ${item.id}: ${error.message}`);
          }
        }
      }

      async function clientDownloadById(itemId, viewOnly) {
        if (viewOnly) {
          window.open(`/ember/${encodeURIComponent(itemId)}`, "_blank", "noopener");
        } else {
          const link = document.createElement("a");
          link.href = `/ember/${encodeURIComponent(itemId)}`;
          link.click();
        }
      }

      loadEncryptedItems().catch((error) => {
        document.querySelector(".items").textContent =
          `Could not decrypt stored items in this browser: ${error.message}`;
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


def create_storage_item(encrypted_bytes):
    """Encrypt and store one complete file envelope in RAM."""
    item_id = str(uuid.uuid4())[:8]

    STORAGE[item_id] = {
        "id": item_id,
        "encrypted": encrypted_bytes,
        "encrypted_size": len(encrypted_bytes),
    }

    return STORAGE[item_id]


def unseal_item(item):
    """Decrypt and validate one browser-created hybrid envelope."""
    try:
        envelope = json.loads(item["encrypted"].decode("utf-8"))
        content_key = SERVER_PRIVATE_KEY.decrypt(
            base64.b64decode(envelope["wrapped_key"], validate=True),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        plaintext = AESGCM(content_key).decrypt(
            base64.b64decode(envelope["iv"], validate=True),
            base64.b64decode(envelope["ciphertext"], validate=True),
            None,
        )
        payload = json.loads(plaintext.decode("utf-8"))
        content = base64.b64decode(payload["content"], validate=True)
        if payload.get("version") != 1 or payload["metadata"]["size_bytes"] != len(content):
            raise ValueError
        return payload
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Stored file payload is invalid.") from error


@app.route("/", methods=["GET"])
def index():
    total_bytes = sum(len(item["encrypted"]) for item in STORAGE.values())

    return render_template_string(
        HTML_TEMPLATE,
        items=STORAGE,
        total_size=format_bytes(total_bytes),
    )


@app.route("/paste/new", methods=["POST"])
def create_paste():
    return (
        "Paste content must be submitted through the browser interface.",
        400,
    )


@app.route("/quasar/relay", methods=["POST"])
def api_upload_stream():
    """
    Receive only the browser-encrypted hybrid envelope.
    """
    max_size = app.config["MAX_CONTENT_LENGTH"]

    try:
        encrypted_bytes = read_request_stream(max_size)
    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 413

    if not encrypted_bytes:
        return jsonify({
            "error": "The request body is empty."
        }), 400

    try:
        envelope = json.loads(encrypted_bytes.decode("utf-8"))
        if envelope.get("version") != 2:
            raise ValueError
        for field in ("wrapped_key", "iv", "ciphertext"):
            base64.b64decode(envelope[field], validate=True)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return jsonify({"error": "Invalid file envelope."}), 400

    item = create_storage_item(encrypted_bytes)

    return jsonify({
        "message": "Stored protected payload in RAM memory.",
        "item_id": item["id"],
    }), 201


@app.route("/aurora/orbit", methods=["GET"])
def public_orbit_key():
    """Publish only the public key used by browsers to encrypt envelopes."""
    return SERVER_PUBLIC_KEY_DER, 200, {"Content-Type": "application/octet-stream"}


@app.route("/nebula/catalog", methods=["GET"])
def api_get_items():
    """Return decrypted metadata for browser rendering."""
    summary = [
        {**unseal_item(item)["metadata"], "id": item["id"]}
        for item in STORAGE.values()
    ]

    return jsonify(summary)


@app.route("/view/<item_id>", methods=["GET"])
def view_item(item_id):
    if item_id not in STORAGE:
        return "Item not found in memory.", 404
    return "This item must be decrypted in the browser.", 400


@app.route("/ember/<item_id>", methods=["GET"])
def download_file(item_id):
    """Return the original file after server-side decryption."""
    item = STORAGE.get(item_id)

    if not item:
        return "Item not found in memory.", 404

    payload = unseal_item(item)
    memory_file = io.BytesIO(base64.b64decode(payload["content"], validate=True))

    return send_file(
        memory_file,
        mimetype=payload["metadata"].get("type", "application/octet-stream"),
        as_attachment=True,
        download_name=payload["metadata"]["name"],
    )


@app.route("/download-zip", methods=["GET"])
def download_zip():
    """Create a ZIP of ciphertext payloads; browsers decrypt individual files."""
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
            payload = unseal_item(item)
            original_name = payload["metadata"]["name"]
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
                base64.b64decode(payload["content"], validate=True),
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
