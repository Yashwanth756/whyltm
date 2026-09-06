"""
In-Memory Paste & File ZIP Vault - Flask Application
Stores pasted text snippets and ANY uploaded files purely in memory (RAM).
Generates in-memory ZIP archives on-the-fly without saving any files to disk or using a database.

Requirements:
    pip install flask

Run:
    python app.py
"""

from flask import Flask, request, redirect, url_for, send_file, render_template_string, jsonify
import io
import zipfile
import uuid
import mimetypes
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'in-memory-vault-secret-key'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # Max 100MB in-memory per upload request

# In-memory storage (RAM only - 100% ephemeral, zero database, zero disk writes)
# Key: item_id (str), Value: dict containing raw bytes buffer and metadata
STORAGE = {}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>In-Memory Paste & File ZIP Vault (Flask)</title>
    <style>
        :root {
            --bg: #0b0f19;
            --card-bg: #151d30;
            --card-border: #233152;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #4f46e5;
            --accent-hover: #4338ca;
            --success: #10b981;
            --danger: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: system-ui, -apple-system, sans-serif; }
        body { background: var(--bg); color: var(--text-main); padding: 2rem 1rem; }
        .container { max-width: 1050px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .badge { background: #064e3b; color: #6ee7b7; padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; }
        .grid { display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 2rem; }
        @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
        .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 14px; padding: 1.5rem; }
        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1.25rem; border-bottom: 1px solid var(--card-border); padding-bottom: 0.75rem; }
        .tab-btn { background: #0b0f19; color: var(--text-muted); border: 1px solid var(--card-border); padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 600; }
        .tab-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
        input[type="text"], input[type="file"], textarea { width: 100%; background: #0b0f19; border: 1px solid var(--card-border); border-radius: 8px; color: #fff; padding: 0.75rem; margin-bottom: 1rem; }
        textarea { min-height: 200px; font-family: monospace; }
        .dropzone { border: 2px dashed var(--card-border); padding: 2rem 1rem; text-align: center; border-radius: 10px; background: #0b0f19; margin-bottom: 1rem; }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.65rem 1.25rem; font-weight: 600; border-radius: 8px; border: none; cursor: pointer; text-decoration: none; }
        .btn-primary { background: var(--accent); color: white; width: 100%; }
        .btn-success { background: var(--success); color: white; }
        .item { background: #0b0f19; border: 1px solid var(--card-border); border-radius: 10px; padding: 1rem; margin-bottom: 0.75rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>In-Memory Paste &amp; File Vault</h1>
                <p style="color: var(--text-muted); margin-top: 0.25rem;">100% In-Memory RAM Storage &bull; Zero Disk Writes &bull; Zero Database</p>
            </div>
            <span class="badge">In-Memory Store Active</span>
        </header>

        <div style="margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; background: var(--card-bg); border: 1px solid var(--card-border); padding: 0.85rem 1.25rem; border-radius: 10px;">
            <span><strong>{{ items|length }}</strong> files / snippets stored in RAM ({{ total_size }})</span>
            <div style="display: flex; gap: 0.75rem;">
                {% if items %}
                <a href="{{ url_for('download_zip') }}" class="btn btn-success" style="padding: 0.4rem 0.9rem; font-size: 0.85rem;">Download All as ZIP</a>
                <form action="{{ url_for('clear_store') }}" method="POST" onsubmit="return confirm('Purge all memory?')">
                    <button type="submit" class="btn" style="background:#334155; color:#cbd5e1; padding: 0.4rem 0.9rem; font-size: 0.85rem;">Clear RAM</button>
                </form>
                {% endif %}
            </div>
        </div>

        <div class="grid">
            <!-- Left: Inputs for Text Paste and Any File Upload -->
            <div class="card">
                <div class="tabs">
                    <button type="button" class="tab-btn active" onclick="switchTab('text-tab')">Paste Text / Code</button>
                    <button type="button" class="tab-btn" onclick="switchTab('file-tab')">Upload Any File</button>
                </div>

                <!-- Text Paste Form -->
                <div id="text-tab">
                    <form action="{{ url_for('create_paste') }}" method="POST">
                        <label style="font-size:0.8rem; color:var(--text-muted); display:block; margin-bottom:0.25rem;">Filename (optional)</label>
                        <input type="text" name="filename" placeholder="e.g. notes.txt, query.sql, config.json">
                        <label style="font-size:0.8rem; color:var(--text-muted); display:block; margin-bottom:0.25rem;">Content *</label>
                        <textarea name="content" placeholder="Paste your text, code, logs, or markdown..." required></textarea>
                        <button type="submit" class="btn btn-primary">Store Text in RAM</button>
                    </form>
                </div>

                <!-- File Upload Form (Any file type) -->
                <div id="file-tab" style="display: none;">
                    <form action="{{ url_for('upload_files') }}" method="POST" enctype="multipart/form-data">
                        <div class="dropzone">
                            <p style="font-weight:600; margin-bottom:0.5rem;">Select any file(s) to store directly in memory</p>
                            <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:1rem;">Images, PDFs, Audio, Video, Binaries, ZIPs, Documents</p>
                            <input type="file" name="files" multiple style="margin-bottom:0;">
                        </div>
                        <button type="submit" class="btn btn-primary" style="background:#059669;">Store File(s) in RAM</button>
                    </form>
                </div>
            </div>

            <!-- Right: Stored items list -->
            <div class="card">
                <h3 style="margin-bottom: 1rem;">Buffered In-Memory Items ({{ items|length }})</h3>
                <div style="max-height: 520px; overflow-y: auto;">
                    {% for id, item in items.items() %}
                    <div class="item">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <strong style="color: #818cf8; font-family: monospace; display:block;">{{ item.filename }}</strong>
                                <small style="color: var(--text-muted);">{{ item.size_str }} &bull; {{ item.mimetype }} &bull; {{ item.created_at }}</small>
                            </div>
                            <span style="font-size:0.75rem; padding:0.15rem 0.5rem; border-radius:4px; background:#1e293b; color:#cbd5e1;">
                                {{ 'Binary' if item.is_binary else 'Text' }}
                            </span>
                        </div>
                        <div style="display: flex; gap: 0.75rem; margin-top: 0.75rem; align-items:center;">
                            {% if not item.is_binary %}
                            <a href="{{ url_for('view_item', item_id=id) }}" style="color: #93c5fd; font-size: 0.85rem;">View</a>
                            {% endif %}
                            <a href="{{ url_for('download_file', item_id=id) }}" style="color: #34d399; font-size: 0.85rem;">Download</a>
                            <form action="{{ url_for('delete_item', item_id=id) }}" method="POST" style="margin-left: auto;">
                                <button type="submit" style="background: none; border: none; color: #f87171; cursor: pointer; font-size: 0.85rem;">Delete</button>
                            </form>
                        </div>
                    </div>
                    {% else %}
                    <p style="color: var(--text-muted); text-align: center; padding: 3rem 1rem;">No files or pastes stored in memory yet.</p>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabId) {
            document.getElementById('text-tab').style.display = tabId === 'text-tab' ? 'block' : 'none';
            document.getElementById('file-tab').style.display = tabId === 'file-tab' ? 'block' : 'none';
            const btns = document.querySelectorAll('.tab-btn');
            btns[0].classList.toggle('active', tabId === 'text-tab');
            btns[1].classList.toggle('active', tabId === 'file-tab');
        }
    </script>
</body>
</html>
"""

def format_bytes(num_bytes):
    if num_bytes == 0:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"

@app.route('/')
def index():
    total_bytes = sum(item['size_bytes'] for item in STORAGE.values())
    return render_template_string(
        HTML_TEMPLATE,
        items=STORAGE,
        total_size=format_bytes(total_bytes)
    )

@app.route('/paste/new', methods=['POST'])
def create_paste():
    content = request.form.get('content', '').strip()
    if not content:
        return redirect(url_for('index'))

    filename = request.form.get('filename', '').strip()
    item_id = str(uuid.uuid4())[:8]

    if not filename:
        filename = f"paste_{item_id}.txt"

    content_bytes = content.encode('utf-8')
    mimetype = mimetypes.guess_type(filename)[0] or 'text/plain; charset=utf-8'

    # Store in-memory buffer
    STORAGE[item_id] = {
        'id': item_id,
        'filename': filename,
        'content': content_bytes,
        'size_bytes': len(content_bytes),
        'size_str': format_bytes(len(content_bytes)),
        'is_binary': False,
        'mimetype': mimetype,
        'created_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }

    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_files():
    """Uploads ANY file type directly into RAM bytes buffer without saving to disk."""
    uploaded_files = request.files.getlist('files')
    if not uploaded_files:
        file = request.files.get('file')
        if file:
            uploaded_files = [file]

    for file in uploaded_files:
        if not file or not file.filename:
            continue

        raw_bytes = file.read()
        item_id = str(uuid.uuid4())[:8]
        filename = file.filename
        mimetype = file.mimetype or mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        is_binary = not mimetype.startswith('text/') and not filename.endswith(('.txt', '.json', '.py', '.md', '.csv', '.sql'))

        STORAGE[item_id] = {
            'id': item_id,
            'filename': filename,
            'content': raw_bytes,
            'size_bytes': len(raw_bytes),
            'size_str': format_bytes(len(raw_bytes)),
            'is_binary': is_binary,
            'mimetype': mimetype,
            'created_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        }

    return redirect(url_for('index'))

@app.route('/view/<item_id>')
def view_item(item_id):
    item = STORAGE.get(item_id)
    if not item:
        return "Item not found in memory", 404
    if item['is_binary']:
        return f"<h3>{item['filename']}</h3><p>Binary file ({item['size_str']}) - download to view.</p>"
    text_content = item['content'].decode('utf-8', errors='replace')
    return f"<pre style='background:#111;color:#eee;padding:1.5rem;font-family:monospace;white-space:pre-wrap;'>{text_content}</pre>"

@app.route('/download/<item_id>')
def download_file(item_id):
    item = STORAGE.get(item_id)
    if not item:
        return "Item not found in memory", 404

    # Stream file directly from in-memory byte buffer (RAM)
    mem_file = io.BytesIO(item['content'])
    return send_file(
        mem_file,
        mimetype=item['mimetype'],
        as_attachment=True,
        download_name=item['filename']
    )

@app.route('/download-zip')
def download_zip():
    """
    Builds a ZIP archive entirely in RAM with io.BytesIO and zipfile.ZipFile.
    Packs both text pastes and arbitrary binary files without writing to disk.
    """
    if not STORAGE:
        return redirect(url_for('index'))

    memory_zip = io.BytesIO()

    with zipfile.ZipFile(memory_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        used_names = {}
        for item_id, item in STORAGE.items():
            name = item['filename']
            if name in used_names:
                used_names[name] += 1
                parts = name.rsplit('.', 1)
                name = f"{parts[0]}_{used_names[name]}.{parts[1]}" if len(parts) == 2 else f"{name}_{used_names[name]}"
            else:
                used_names[name] = 0

            # Write raw in-memory bytes directly to archive
            zf.writestr(name, item['content'])

    memory_zip.seek(0)
    zip_name = f"vault_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"

    return send_file(
        memory_zip,
        mimetype='application/zip',
        as_attachment=True,
        download_name=zip_name
    )

@app.route('/delete/<item_id>', methods=['POST'])
def delete_item(item_id):
    STORAGE.pop(item_id, None)
    return redirect(url_for('index'))

@app.route('/clear', methods=['POST'])
def clear_store():
    STORAGE.clear()
    return redirect(url_for('index'))

# JSON REST API
@app.route('/api/items', methods=['GET'])
def api_get_items():
    summary = [
        {
            'id': item['id'],
            'filename': item['filename'],
            'size_bytes': item['size_bytes'],
            'size_str': item['size_str'],
            'is_binary': item['is_binary'],
            'mimetype': item['mimetype'],
            'created_at': item['created_at']
        }
        for item in STORAGE.values()
    ]
    return jsonify(summary)

@app.route('/api/upload', methods=['POST'])
def api_upload_file():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file provided in form field "file"'}), 400

    raw_bytes = file.read()
    item_id = str(uuid.uuid4())[:8]
    filename = file.filename or f"upload_{item_id}.bin"
    mimetype = file.mimetype or 'application/octet-stream'

    STORAGE[item_id] = {
        'id': item_id,
        'filename': filename,
        'content': raw_bytes,
        'size_bytes': len(raw_bytes),
        'size_str': format_bytes(len(raw_bytes)),
        'is_binary': not mimetype.startswith('text/'),
        'mimetype': mimetype,
        'created_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }
    return jsonify({
        'message': f'Stored "{filename}" in RAM memory',
        'item_id': item_id,
        'size_bytes': len(raw_bytes)
    }), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
