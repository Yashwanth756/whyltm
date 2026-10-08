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
private_key_text = """-----BEGIN PRIVATE KEY-----
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
"""
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
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-Requested-With"
        )

    return response


# All data is stored only in memory. Browsers encrypt content before insertion.
# The data is lost when the application restarts.
STORAGE = {}


HTML_TEMPLATE = r"""
<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
<title>Obsidian Relay</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,400;12..96,500;12..96,600;12..96,700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet" />
<script>
try {
  const saved = localStorage.getItem("relay-theme");
  const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = saved || (dark ? "dark" : "light");
} catch (e) {}
</script>
<style>
:root[data-theme="dark"]{
  --bg:#0e1013;--panel:#14171b;--sunk:#0b0d0f;--hover:#1a1e23;--line:#242930;--line-strong:#3a414b;
  --text:#eceef2;--muted:#98a0ac;--faint:#5d6672;--accent:#8aa4ff;--accent-strong:#a5b9ff;--accent-ink:#0b1124;
  --accent-soft:rgba(138,164,255,.13);--ok:#6cc59b;--bad:#f2837b;--shadow:0 24px 60px rgba(0,0,0,.55);color-scheme:dark;
}
:root[data-theme="light"]{
  --bg:#eceef1;--panel:#f9fafb;--sunk:#e4e7eb;--hover:#f0f2f5;--line:#d9dde3;--line-strong:#b8bec8;
  --text:#15171c;--muted:#5a606b;--faint:#8b919c;--accent:#3249d8;--accent-strong:#2336b8;--accent-ink:#fff;
  --accent-soft:rgba(50,73,216,.09);--ok:#12805a;--bad:#c2392f;--shadow:0 24px 60px rgba(20,24,33,.16);color-scheme:light;
}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-font-smoothing:antialiased;-webkit-text-size-adjust:100%}
body{min-height:100vh;background:var(--bg);color:var(--text);
  font:15px/1.5 "Bricolage Grotesque",ui-sans-serif,-apple-system,"Segoe UI",system-ui,sans-serif;font-optical-sizing:auto;transition:background .2s,color .2s}
::selection{background:var(--accent-soft)}
button,input,select,textarea{font:inherit;color:inherit}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
[hidden]{display:none!important}
.mono{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}

.shell{width:100%;max-width:1240px;margin:0 auto;padding:calc(32px + env(safe-area-inset-top,0px)) 28px calc(64px + env(safe-area-inset-bottom,0px))}
.top{display:flex;justify-content:space-between;align-items:flex-end;gap:1.5rem;margin-bottom:2.25rem}
h1{font-size:clamp(2rem,4.6vw,3.4rem);font-weight:700;letter-spacing:-.045em;line-height:1.02}
.subtitle{margin-top:.7rem;max-width:46ch;color:var(--muted);font-size:1.02rem}
.top-side{display:flex;align-items:center;gap:.6rem}
.badge{display:inline-flex;align-items:center;gap:.55rem;height:36px;padding:0 .9rem;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:.8rem;font-weight:500;white-space:nowrap}
.badge::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 24%,transparent);animation:beat 2.8s ease-in-out infinite}
@keyframes beat{50%{box-shadow:0 0 0 6px transparent}}

.layout{display:grid;grid-template-columns:minmax(0,540px) minmax(0,1fr);gap:1.5rem;align-items:start}
.panel{border:1px solid var(--line);border-radius:18px;background:var(--panel)}
.compose{position:sticky;top:24px;padding:.5rem 1.5rem 1.5rem}
.index{padding:1.5rem 0 .5rem;min-height:520px}

.tabs{display:flex;gap:1.5rem;margin:0 0 1.4rem;border-bottom:1px solid var(--line)}
.tab-button{position:relative;padding:1rem 0 .95rem;border:0;background:none;cursor:pointer;color:var(--muted);font-size:.95rem;font-weight:500;transition:color .15s}
.tab-button:hover,.tab-button.active{color:var(--text)}
.tab-button.active::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:2px;background:var(--accent)}

label{display:block;margin-bottom:.4rem;color:var(--muted);font-size:.82rem;font-weight:500}
input[type=text],input[type=search],select,textarea{width:100%;padding:.7rem .85rem;border:1px solid var(--line);border-radius:10px;outline:none;background:var(--sunk);font-size:.95rem;transition:border-color .15s,box-shadow .15s}
input[type=text]{margin-bottom:1.1rem}
::placeholder{color:var(--faint)}
input:hover,textarea:hover,select:hover{border-color:var(--line-strong)}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}

/* custom select */
.select{position:relative;display:inline-block}
.select select{appearance:none;-webkit-appearance:none;width:auto;min-width:132px;height:40px;padding:0 2.2rem 0 .9rem;cursor:pointer;font-size:.88rem;font-weight:500;background:var(--sunk)}
.select::after{content:"";position:absolute;right:.95rem;top:50%;width:7px;height:7px;margin-top:-6px;border:solid var(--muted);border-width:0 1.6px 1.6px 0;transform:rotate(45deg);pointer-events:none;transition:border-color .15s}
.select:hover::after,.select:focus-within::after{border-color:var(--accent)}
.select option{background:var(--panel);color:var(--text);padding:.5rem}

/* editor */
.editor{margin-bottom:.9rem;border:1px solid var(--line);border-radius:12px;background:var(--sunk);overflow:hidden;transition:border-color .15s,box-shadow .15s}
.editor:hover{border-color:var(--line-strong)}
.editor:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.editor-bar{display:flex;justify-content:space-between;align-items:center;padding:.4rem .5rem .4rem .85rem;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--panel) 70%,var(--sunk));color:var(--muted);font-size:.8rem;font-weight:500}
.editor-tools{display:flex;gap:.25rem}
.editor textarea{display:block;width:100%;min-height:360px;max-height:600px;padding:1.1rem 1.2rem;border:0;border-radius:0;background:transparent;box-shadow:none;resize:none;tab-size:2;
  font:500 .85rem/1.7 "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}
.editor-foot{display:flex;justify-content:space-between;gap:1rem;padding:.45rem .85rem;border-top:1px solid var(--line);color:var(--faint);font-size:.74rem}
.editor-foot span{white-space:nowrap}
kbd{padding:.05rem .4rem;border:1px solid var(--line-strong);border-radius:5px;background:var(--sunk);font:500 .7rem "JetBrains Mono",ui-monospace,monospace;color:var(--muted)}

.btn{display:inline-flex;justify-content:center;align-items:center;gap:.4rem;min-height:40px;padding:0 1rem;border:1px solid var(--line);border-radius:10px;background:transparent;color:var(--text);font-size:.88rem;font-weight:500;text-decoration:none;cursor:pointer;transition:background .15s,border-color .15s,color .15s,transform .06s}
.btn:hover{border-color:var(--line-strong);background:var(--hover)}
.btn:active{transform:scale(.98)}
.btn:focus-visible,.tab-button:focus-visible,.dropzone:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-primary{width:100%;min-height:46px;border-color:transparent;background:var(--accent);color:var(--accent-ink);font-weight:600;font-size:.95rem}
.btn-primary:hover:not(:disabled){background:var(--accent-strong);border-color:transparent}
.btn-quiet{border-color:transparent;color:var(--muted)}
.btn-quiet:hover{color:var(--text)}
.btn-danger{border-color:transparent;color:var(--muted)}
.btn-danger:hover{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad);border-color:transparent}
.btn-sm{min-height:32px;padding:0 .75rem;border-radius:8px;font-size:.8rem}
.btn-icon{min-height:36px;padding:0 .85rem;border-radius:999px;font-size:.8rem;color:var(--muted)}

/* dropzone */
.dropzone{display:grid;justify-items:center;gap:.35rem;padding:2rem 1.25rem 1.5rem;border:1.5px dashed var(--line-strong);border-radius:14px;background:var(--sunk);text-align:center;cursor:pointer;transition:border-color .15s,background .15s}
.dropzone:hover{border-color:var(--accent)}
.dropzone.dragging{border-color:var(--accent);background:var(--accent-soft)}
.dz-icon{display:grid;place-items:center;width:52px;height:52px;margin-bottom:.5rem;border:1px solid var(--line-strong);border-radius:14px;background:var(--panel);color:var(--accent)}
.dz-icon svg{width:24px;height:24px}
.dropzone p{font-weight:600;font-size:1rem;line-height:1.35}
.dropzone .help-text{color:var(--muted);font-size:.82rem;font-weight:400}
.pickers{display:flex;justify-content:center;gap:.5rem;margin:1rem 0 0;flex-wrap:wrap}

.queue-wrap{margin-top:1rem}
.queue-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:.4rem;color:var(--muted);font-size:.82rem}
.queue-head strong{color:var(--text);font-weight:600}
.queue{list-style:none;max-height:240px;overflow-y:auto;border-top:1px solid var(--line);scrollbar-width:thin;scrollbar-color:var(--line-strong) transparent}
.queue li{display:flex;align-items:center;gap:.75rem;padding:.55rem 0;border-bottom:1px solid var(--line)}
.queue .ext{width:34px;height:38px;font-size:.56rem}
.queue .q-body{flex:1;min-width:0}
.q-name,.q-meta{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.q-name{font-size:.88rem;font-weight:500}
.q-meta{color:var(--faint);font-size:.74rem}
.q-state{font-size:.72rem;color:var(--muted)}
.q-state.ok{color:var(--ok)}
.send-row{margin-top:1rem}
.progress{height:4px;margin-top:1rem;border-radius:4px;background:var(--line);overflow:hidden}
.progress div{width:0;height:100%;background:var(--accent);transition:width .15s}
#upload-status{margin-top:.8rem;color:var(--muted);font-size:.84rem;text-align:center;overflow-wrap:anywhere}
#upload-status:empty{display:none}
#file-info,#file-preview{width:100%;margin-top:.8rem;padding:.7rem .8rem;border:1px solid var(--line);border-radius:10px;background:var(--sunk);color:var(--muted);overflow:auto;font:500 .72rem/1.6 "JetBrains Mono",ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
#file-preview{max-height:160px}

/* index */
.index-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:0 1.5rem}
h3{font-size:1.35rem;font-weight:600;letter-spacing:-.02em}
.summary{margin:.25rem 0 0;padding:0 1.5rem;color:var(--muted);font-size:.88rem}
.summary strong{color:var(--text);font-weight:600}
.summary-actions{display:flex;gap:.5rem;align-items:center}
.summary-actions form{display:contents}
.toolbar{display:flex;gap:.5rem;margin:1.25rem 0 .5rem;padding:0 1.5rem}
.toolbar input{flex:1;min-width:0;height:40px;padding-top:0;padding-bottom:0}
.items{max-height:640px;overflow-y:auto;border-top:1px solid var(--line);scrollbar-width:thin;scrollbar-color:var(--line-strong) transparent}
.item{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;column-gap:1rem;padding:.9rem 1.5rem;border-bottom:1px solid var(--line);transition:background .15s}
.item:last-child{border-bottom:0}
.item:hover{background:var(--hover)}
.ext{display:grid;place-items:center;width:42px;height:48px;border-radius:8px 14px 8px 8px;border:1px solid var(--line-strong);background:var(--sunk);color:var(--accent);font:700 .64rem "JetBrains Mono",ui-monospace,monospace;letter-spacing:.03em;text-transform:uppercase}
.item-body{min-width:0}
.filename{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.98rem;font-weight:600}
.metadata{display:block;margin-top:.1rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:.78rem}
.item-actions{display:flex;align-items:center;gap:.25rem}
.empty{padding:4rem 1.5rem;color:var(--muted);text-align:center}
.empty:not(.plain)::after{content:"Drop a file or a whole folder anywhere on this page to stage it.";display:block;margin-top:.35rem;color:var(--faint);font-size:.84rem}

.veil{position:fixed;inset:0;z-index:60;display:flex;padding:14px;opacity:0;pointer-events:none;background:color-mix(in srgb,var(--bg) 80%,transparent);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);transition:opacity .18s}
.veil.on{opacity:1}
.veil-box{flex:1;display:grid;place-content:center;gap:.5rem;border:2px dashed var(--accent);border-radius:26px;text-align:center;padding:1.5rem}
.veil-title{font-size:clamp(2rem,6vw,4rem);font-weight:700;letter-spacing:-.04em;line-height:1}
.veil-sub{color:var(--muted)}

dialog{margin:auto;padding:0;border:1px solid var(--line-strong);border-radius:18px;background:var(--panel);color:var(--text);box-shadow:var(--shadow)}
dialog::backdrop{background:rgba(5,6,8,.6);backdrop-filter:blur(4px)}
#viewer{width:min(780px,calc(100vw - 24px))}
.dlg-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.9rem 1.1rem;border-bottom:1px solid var(--line)}
.dlg-head strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.dlg-body{max-height:65vh;padding:1.1rem;overflow:auto;color:var(--muted)}
.dlg-body pre{color:var(--text);white-space:pre-wrap;word-break:break-word;font:500 .8rem/1.65 "JetBrains Mono",ui-monospace,Menlo,monospace}
.dlg-body img{display:block;max-width:100%;margin:0 auto;border-radius:10px}
.dlg-foot{display:flex;justify-content:flex-end;gap:.5rem;padding:.8rem 1.1rem;border-top:1px solid var(--line)}

/* centre popup */
#popup{width:min(480px,calc(100vw - 32px));overflow:hidden;text-align:center}
#popup[open]{animation:pop .24s cubic-bezier(.2,.9,.3,1.2) both}
@keyframes pop{from{opacity:0;transform:scale(.92) translateY(8px)}to{opacity:1;transform:none}}
.pop-inner{padding:2rem 1.75rem 1.4rem}
.pop-tag{display:inline-block;padding:.2rem .7rem;border:1px solid var(--line-strong);border-radius:999px;color:var(--muted);font-size:.74rem;font-weight:600}
.pop-tag.ok{color:var(--ok);border-color:var(--ok)}
.pop-tag.error{color:var(--bad);border-color:var(--bad)}
.pop-title{margin:.9rem 0 1rem;font-size:.9rem;color:var(--muted)}
.pop-line{font-size:clamp(1.3rem,4.6vw,1.65rem);font-weight:700;letter-spacing:-.025em;line-height:1.2}
.pop-tr{margin-top:.8rem;color:var(--muted);font-size:.95rem}
.pop-tr::before{content:"In English: ";color:var(--faint)}
.pop-actions{margin-top:1.4rem}
.pop-timer{height:3px;background:var(--accent);transform-origin:left;animation:drain 6s linear forwards}
#popup.paused .pop-timer{animation-play-state:paused}
@keyframes drain{to{transform:scaleX(0)}}

#toasts{position:fixed;right:1.25rem;bottom:calc(1.25rem + env(safe-area-inset-bottom,0px));z-index:80;display:flex;flex-direction:column;gap:.6rem;width:min(380px,calc(100vw - 2.5rem))}
.toast{display:flex;flex-direction:column;gap:.15rem;padding:.8rem 1rem;border:1px solid var(--line-strong);border-left:3px solid var(--accent);border-radius:12px;background:var(--panel);box-shadow:var(--shadow);font-size:.88rem;animation:pop .22s ease-out both}
.toast strong{font-weight:600}
.toast span{color:var(--muted);font-size:.84rem}
.toast.out{opacity:0;transform:translateY(6px);transition:opacity .25s,transform .25s}


body{background:radial-gradient(900px 420px at 12% -8%,var(--accent-soft),transparent 70%),var(--bg)}
.panel{box-shadow:0 1px 0 rgba(255,255,255,.03) inset,0 18px 40px -24px rgba(0,0,0,.5)}
.compose{padding:.5rem 1.6rem 1.7rem}
.editor{border-radius:14px;border-color:var(--line-strong);background:var(--sunk);box-shadow:0 1px 0 rgba(255,255,255,.03) inset}
.editor textarea{font-size:.9rem;line-height:1.75;caret-color:var(--accent)}
.editor-foot{padding:.6rem 1.1rem;background:color-mix(in srgb,var(--panel) 60%,var(--sunk))}
#filename{height:46px;margin-bottom:1.3rem;border-radius:12px}
.btn-primary{background:linear-gradient(180deg,var(--accent-strong),var(--accent));box-shadow:0 8px 20px -10px var(--accent)}
.btn-primary:hover:not(:disabled){transform:translateY(-1px)}
.dropzone{padding:2.6rem 1.25rem 1.8rem;border-radius:16px;background:radial-gradient(300px 120px at 50% 0,var(--accent-soft),transparent 80%),var(--sunk)}
.dz-icon{width:60px;height:60px;border-radius:16px;box-shadow:0 10px 24px -14px var(--accent)}
.item{position:relative}
.item::before{content:"";position:absolute;left:0;top:14px;bottom:14px;width:3px;border-radius:0 3px 3px 0;background:var(--accent);opacity:0;transition:opacity .15s}
.item:hover::before{opacity:1}
.pop-inner{padding:2.2rem 2rem 1.6rem}
.pop-line{font-size:clamp(1.25rem,4.2vw,1.55rem)}
.pop-tr{padding:.75rem 1rem;border:1px solid var(--line);border-radius:12px;background:var(--sunk)}
@media (max-width:960px){.layout{grid-template-columns:1fr}.compose{position:static}.index{min-height:0}}
@media (max-width:640px){
  .shell{padding-left:16px;padding-right:16px}
  .top{flex-direction:column;align-items:stretch;gap:1rem;margin-bottom:1.5rem}
  .top-side{justify-content:space-between}
  .compose{padding:.25rem 1rem 1.1rem}
  .tabs{gap:0}.tab-button{flex:1;text-align:center}
  .index-head,.summary,.toolbar{padding-left:1rem;padding-right:1rem}
  .index-head{flex-direction:column;align-items:flex-start;gap:.75rem}
  .item{grid-template-columns:auto minmax(0,1fr);padding:.85rem 1rem;row-gap:.6rem}
  .item-actions{grid-column:1/-1;flex-wrap:wrap}.item-actions .push{margin-left:auto}
  .btn-sm{min-height:36px}.pickers .btn{flex:1}
  #toasts{right:12px;left:12px;width:auto}
  .editor-foot kbd{display:none}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="veil" id="veil" aria-hidden="true"><div class="veil-box">
  <p class="veil-title">Release to stage</p><p class="veil-sub">Files and whole folders both work.</p>
</div></div>

<main class="shell">
  <header class="top">
    <div>
      <h1>Obsidian Relay</h1>
      <p class="subtitle">Aster packets, transient staging, and sealed retrieval</p>
    </div>
    <div class="top-side">
      <span class="badge">Drift Channel Active</span>
      <button type="button" id="theme-toggle" class="btn btn-icon" aria-label="Toggle theme">Theme</button>
    </div>
  </header>

  <section class="layout">
    <div class="panel compose">
      <div class="tabs" role="tablist">
        <button type="button" class="tab-button active" data-tab="text-tab" onclick="switchTab('text-tab', this)">Lumen Input</button>
        <button type="button" class="tab-button" data-tab="file-tab" onclick="switchTab('file-tab', this)">Quill Transfer</button>
      </div>

      <div id="text-tab">
        <form id="paste-form" action="{{ url_for('create_paste') }}" method="POST">
          <label for="filename">Filename</label>
          <input id="filename" type="text" name="filename" placeholder="notes.txt" autocomplete="off" />

          <label for="content">Content</label>
          <div class="editor">
            <textarea id="content" name="content" placeholder="Paste text, code, logs, or markdown..." spellcheck="false" required></textarea>
            <div class="editor-foot">
              <span id="char-count">0 characters &middot; 0 lines</span>
              <span><kbd>Ctrl</kbd> + <kbd>Enter</kbd> to commit</span>
            </div>
          </div>
          <button type="submit" class="btn btn-primary">Commit Lumen</button>
        </form>
      </div>

      <div id="file-tab" style="display:none">
        <div class="dropzone" id="dropzone" tabindex="0" role="button" aria-label="Select files">
          <div class="dz-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3"/></svg></div>
          <p>Drop files or folders here</p>
          <p class="help-text">Sent as a raw HTTP stream. No multipart/form-data.</p>
          <input id="file-input" class="sr" type="file" multiple tabindex="-1" />
          <input id="folder-input" class="sr" type="file" webkitdirectory directory multiple tabindex="-1" />
          <div class="pickers">
            <button type="button" id="pick-files" class="btn">Select files</button>
            <button type="button" id="pick-folder" class="btn">Select folder</button>
          </div>
        </div>

        <div class="queue-wrap" id="queue-wrap" hidden>
          <div class="queue-head">
            <span><strong id="queue-count">0</strong> queued <span id="queue-size"></span></span>
            <button type="button" id="queue-clear" class="btn btn-quiet btn-sm">Clear queue</button>
          </div>
          <ul class="queue" id="queue"></ul>
        </div>

        <div class="send-row"><button id="upload-button" type="button" class="btn btn-primary">Send Quill</button></div>
        <div class="progress" id="progress" hidden><div></div></div>
        <pre id="file-info" hidden></pre>
        <pre id="file-preview" hidden></pre>
        <p id="upload-status"></p>
      </div>
    </div>

    <div class="panel index">
      <div class="index-head">
        <h3>Aster Index</h3>
        <div class="summary-actions" id="summary-actions" {% if not items %}hidden{% endif %}>
          <a href="{{ url_for('download_zip') }}" class="btn btn-sm">Download all (ZIP)</a>
          <form id="clear-form" action="{{ url_for('clear_store') }}" method="POST">
            <button type="submit" class="btn btn-sm btn-danger">Reset Drift</button>
          </form>
        </div>
      </div>
      <p class="summary"><strong id="count">{{ items|length }}</strong> item(s) stored in RAM <strong id="total">({{ total_size }})</strong></p>

      <div class="toolbar">
        <input id="search" type="search" placeholder="Search files..." autocomplete="off" />
        <span class="select">
          <select id="sort" aria-label="Sort">
            <option value="new">Newest</option>
            <option value="old">Oldest</option>
            <option value="name">Name</option>
            <option value="size">Largest</option>
          </select>
        </span>
      </div>

      <div class="items"><div class="empty">The index is currently quiet.</div></div>
    </div>
  </section>
</main>

<dialog id="viewer">
  <div class="dlg-head"><strong id="viewer-title"></strong><button type="button" class="btn btn-sm" id="viewer-close">Close</button></div>
  <div class="dlg-body" id="viewer-body"></div>
  <div class="dlg-foot">
    <button type="button" class="btn btn-sm" id="viewer-copy">Copy</button>
    <button type="button" class="btn btn-sm" id="viewer-download">Retrieve</button>
  </div>
</dialog>

<dialog id="popup" aria-live="polite">
  <div class="pop-inner">
    <span class="pop-tag" id="pop-tag"></span>
    <p class="pop-title" id="pop-title"></p>
    <p class="pop-line" id="pop-line"></p>
    <p class="pop-tr" id="pop-tr"></p>
    <div class="pop-actions"><button type="button" class="btn btn-primary" id="pop-close">Fine, I accept</button></div>
  </div>
  <div class="pop-timer" id="pop-timer"></div>
</dialog>
<div id="toasts" aria-live="polite"></div>

<script>
function switchTab(tabId, btn) {
  document.getElementById("text-tab").style.display = tabId === "text-tab" ? "block" : "none";
  document.getElementById("file-tab").style.display = tabId === "file-tab" ? "block" : "none";
  document.querySelectorAll(".tab-button").forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
}

const fileInput = document.getElementById("file-input");
const folderInput = document.getElementById("folder-input");
const fileInfo = document.getElementById("file-info");
const filePreview = document.getElementById("file-preview");
const maxPreviewBytes = 4096;
const textFilePattern = /\.(txt|log|md|json|js|jsx|ts|tsx|py|java|c|cpp|h|css|html|xml|yaml|yml|csv|svg)$/i;
const state = { items: [], q: "", sort: "new", viewing: null, queue: [] };

/* ---------- helpers ---------- */
function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
function bytesToHex(bytes) { return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" "); }
function explainError(error) {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string" && error) return error;
  try { return JSON.stringify(error); } catch { return "Unknown browser error."; }
}
function formatSize(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function timeAgo(iso) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (isNaN(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function isText(m) { return (m.type || "").startsWith("text/") || textFilePattern.test(m.name || ""); }
function extOf(name) { const m = /\.([a-z0-9]{1,4})$/i.exec(name || ""); return m ? m[1] : "file"; }

/* ---------- Telugu / Hindi remarks (romanised): [language, line, English] ---------- */
const T = "Telugu", H = "Hindi";
const combo = {
  commit: {
    [T]: {
      a: [["Arey baboi!","Oh my!"],["Ayyo ramaa!","Oh my god!"],["Em ra idi!","What is this!"],["Chi siggu ledu ra miku!","Have you no shame!"],["Abba!","Wow!"],["Arre deva!","Oh lord!"],["Ayyayyo!","Oh no no!"],["Hmm, chala bagundi ra.","Hmm, very nice, man."]],
      b: [["Server ki kuda navvu aagatledu.","Even the server can't stop laughing."],["Idi content aa leka accident aa?","Is this content or an accident?"],["RAM ki kuda bhayam vestundi.","Even the RAM is getting scared."],["Nee confidence mundu Google kuda fail.","Google fails in front of your confidence."],["Idi chaduvthe doctor ki fees ivvali.","Reading this needs a doctor's fee."],["Ilanti paste chesi hero anukuntunnav.","Pasting stuff like this and thinking you're a hero."],["Next time alochinchi kottu ra.","Think before you type next time."],["Nee typing speed kante nee logic slow.","Your logic is slower than your typing."]]
    },
    [H]: {
      a: [["Arre bhai bhai bhai!","Bro bro bro!"],["Hey Bhagwan!","Oh God!"],["Kya kar diya tune!","What have you done!"],["Kuch toh sharam kar le!","Have some shame!"],["Wah wah wah!","Wow wow wow!"],["Abe yaar!","Oh come on!"],["Ho gaya tera?","Done with yours?"],["Haye re!","Oh dear!"]],
      b: [["Server bhi hans hans ke lot-pot ho gaya.","Even the server rolled over laughing."],["Ye content hai ya galti se daba diya?","Is this content or an accidental key press?"],["RAM ro rahi hai, CPU bol raha hai bas kar.","The RAM is crying, the CPU says stop."],["Tera confidence dekh ke WiFi bhi sharma gaya.","Seeing your confidence, even the WiFi blushed."],["Isse achha toh ration list likh leta.","You'd have been better off writing a grocery list."],["Itna bekaar, phir bhi save. Server bada dayalu hai.","So useless, yet saved. The server is generous."],["Agli baar sochke type kar, sochna free hai.","Think before typing next time, thinking is free."],["Sapne mein bhi koi ye read nahi karega.","Nobody will read this even in their dreams."]]
    }
  },
  upload: {
    [T]: {
      a: null,
      b: [["Ee files chusi folder ki kuda bore kottindi.","Even the folder got bored of these files."],["Final_v2_real_final ante nuvve ra.","Final_v2_real_final, that's you."],["Backup aa leka hoarding aa?","Backup or hoarding?"],["Anni files enduku ra, exam ledu kada.","Why so many files, there's no exam."],["Naming system chuste kallu tirugutunnayi.","Your naming system makes my eyes spin."],["Sort cheyyakunda pettav, hats off.","Uploaded without sorting, hats off."],["Mee desktop ki chaala kashtam ra.","Tough life for your desktop."],["Storage kante nee sahanam ekkuva.","Your patience is bigger than your storage."]]
    },
    [H]: {
      a: null,
      b: [["Itni files? Bhai godown khol raha hai kya?","So many files? Are you opening a warehouse?"],["Final_final_real_final wala insaan mil gaya.","Found the Final_final_real_final guy."],["Folder ka naam dekh ke dimaag ghoom gaya.","The folder name spun my head."],["Backup hai ya kabaad?","Backup or scrap?"],["Naming dekh ke sabziwala bhi pass kar dega.","Even the vegetable vendor would pass on this naming."],["Sab upload hua, bas tera time waste hua.","All uploaded, only your time was wasted."],["Storage bhar jayega, tera confidence nahi.","Storage will fill up, your confidence won't."],["Itna kuch rakh ke bhi kuch nahi mila na?","Kept all this and still found nothing, right?"]]
    }
  }
};
combo.upload[T].a = combo.commit[T].a;
combo.upload[H].a = combo.commit[H].a;
const fixed = {
  remove: [
    [T,"Poyindi poyindi, ex laga. Malli raadu.","Gone, like an ex. It won't come back."],
    [T,"Delete chesav ra. Ee dhairyam important decisions lo chupinchu.","Deleted. Show this courage in important decisions too."],
    [T,"Kaneesam oka funeral ayina pettu ra.","At least hold a funeral for it."],
    [T,"Ippudu santhosham aa? Nuvvu chesindi chusava?","Happy now? Did you see what you did?"],
    [T,"Delete ayyindi, kani nee tappulu inka unnai.","Deleted, but your mistakes are still here."],
    [T,"Aa file ki shanti kalagali ra.","May that file rest in peace."],
    [H,"Delete ho gaya, tere attendance ki tarah kisi ko fark nahi pada.","Deleted, like your attendance, nobody noticed."],
    [H,"Gaya, ab rone se kuch nahi hoga.","Gone, crying won't help now."],
    [H,"Ek click mein itni badi baat? Dil bada hai tera.","Such a big call in one click? You've got guts."],
    [H,"File ko shraddhanjali, 2 minute ka maun.","Tribute to the file, two minutes of silence."],
    [H,"Delete toh kar diya, ab backup ka sapna dekh.","You deleted it, now dream of a backup."],
    [H,"Itni bhi kya nafrat thi file se?","What hatred did you have for the file?"]
  ],
  reset: [
    [T,"Anni poyayi ra. Ippudu em chestav?","Everything's gone. What will you do now?"],
    [T,"Reset button nokkav, jeevithamlo kuda ilage cheyyi.","You pressed reset, do the same in life."],
    [T,"Mothham saaf. Nee manasu kante clean ga undi.","All clean. Cleaner than your conscience."],
    [T,"Server kuda fresh start kosam edustundi.","Even the server cries for a fresh start."],
    [T,"Boom! Anni gaayab. Magic chesav ra.","Boom! All vanished. You did magic."],
    [H,"Sab saaf. Kaash zindagi mein bhi reset button hota.","All wiped. If only life had a reset button."],
    [H,"Ek hi click mein sab khatam, tu bada khatarnak hai.","Everything gone in one click, you're dangerous."],
    [H,"Server ne kaha: bhai itna bhi kya gussa?","The server said: bro, why so angry?"],
    [H,"Sab gayab, jaise mahine ke aakhri din salary.","All gone, like salary at month end."],
    [H,"Safai abhiyan safal raha.","The cleanliness drive was a success."]
  ],
  copy: [
    [T,"Copy chesav, ippudu paste cheyyi. Aagaku.","Copied. Now paste it. Don't stop."],
    [T,"Copy kottav, kani credit evariki ivvav?","You copied it, but who gets the credit?"],
    [T,"Clipboard lo pettav, ippudu marchipoku ra.","Put it in the clipboard, now don't forget."],
    [T,"Copy-paste engineer ki salute.","Salute to the copy-paste engineer."],
    [H,"Copy ho gaya, ab paste karke dikha.","Copied, now go paste it and show us."],
    [H,"Ctrl+C ka jaadugar.","The wizard of Ctrl+C."],
    [H,"Copy kiya, par samajh bhi aaya kya?","You copied it, but did you understand?"],
    [H,"Copy-paste se hi ghar chalta hai, hai na?","Copy-paste pays the bills, right?"]
  ],
  fail: [
    [T,"Em ayyindi ra? Idi nee valla aa, network valla aa?","What happened? Is it your fault or the network's?"],
    [T,"Fail ayyindi. Nee luck laage.","It failed. Just like your luck."],
    [T,"Server cheppindi: nenu em cheyyali ra baboi.","The server said: what should I even do, dear."],
    [T,"Mari idi kuda nee tappe ani anukuntunna.","I'm guessing this is also your mistake."],
    [T,"Retry kottu ra, miracle jaragochu.","Hit retry, a miracle might happen."],
    [T,"Network ki kuda nee meeda nammakam ledu.","Even the network doesn't trust you."],
    [T,"Idi fail kaadu, server nee meeda prank chesindi.","This isn't failure, the server pranked you."],
    [H,"Arre yaar, kuch toh gadbad hai. Phir se try kar.","Oh man, something's off. Try again."],
    [H,"Fail ho gaya. Ab blame kisko karega, network ko?","It failed. Who will you blame, the network?"],
    [H,"Server bola: main chhutti pe hoon.","The server said: I'm on leave."],
    [H,"Ye error nahi, server ka mood off hai.","This isn't an error, the server's mood is off."],
    [H,"Dobara try kar, shayad is baar bhagwan sun le.","Try again, maybe God listens this time."],
    [H,"Kismat ka khel hai bhai, kabhi chalta hai kabhi nahi.","It's the game of luck, bro. Sometimes it works, sometimes not."],
    [H,"Tu jahan haath lagata hai wahan bug aa jata hai.","Wherever you touch, a bug appears."]
  ],
  welcome: [
    [T,"Lopaliki randi, Obsidian Relay ki swagatham.","Please come in, welcome to Obsidian Relay."],
    [T,"Lopaliki randi. Coffee ledu, kani storage undi.","Please come in. No coffee, but there's storage."],
    [T,"Lopaliki randi. Chappals bayata vadali ra.","Please come in. Leave your slippers outside."],
    [H,"Aaiye aaiye, padhariye. RAM khaali hai.","Come in, come in, the RAM is empty."],
    [H,"Swagat nahi karenge, kaam karo.","We won't welcome you, get to work."]
  ]
};
const lastRemark = {};
function remark(kind) {
  let pick, key;
  if (combo[kind]) {
    do {
      const lang = Math.random() < 0.5 ? T : H, c = combo[kind][lang];
      const a = c.a[Math.floor(Math.random() * c.a.length)], b = c.b[Math.floor(Math.random() * c.b.length)];
      pick = [lang, `${a[0]} ${b[0]}`, `${a[1]} ${b[1]}`]; key = pick[1];
    } while (key === lastRemark[kind]);
    lastRemark[kind] = key; return pick;
  }
  const pool = fixed[kind];
  do { pick = pool[Math.floor(Math.random() * pool.length)]; } while (pool.length > 1 && pick[1] === lastRemark[kind]);
  lastRemark[kind] = pick[1]; return pick;
}

/* ---------- centre popup ---------- */
const popup = document.getElementById("popup");
let popTimer = null;
function showPopup(kind, title, tone) {
  const [lang, line, tr] = remark(kind);
  const tag = document.getElementById("pop-tag");
  tag.textContent = lang; tag.className = "pop-tag " + (tone || "");
  document.getElementById("pop-title").textContent = title;
  document.getElementById("pop-line").textContent = line;
  document.getElementById("pop-tr").textContent = tr;
  const timer = document.getElementById("pop-timer");
  timer.style.animation = "none"; void timer.offsetWidth; timer.style.animation = "";
  if (!popup.open) popup.showModal();
  clearTimeout(popTimer);
  popTimer = setTimeout(() => popup.open && popup.close(), 6000);
}
document.getElementById("pop-close").addEventListener("click", () => popup.close());
popup.addEventListener("click", (e) => { if (e.target === popup) popup.close(); });
popup.addEventListener("close", () => clearTimeout(popTimer));
popup.addEventListener("mouseenter", () => { clearTimeout(popTimer); popup.classList.add("paused"); });
popup.addEventListener("mouseleave", () => { popup.classList.remove("paused"); popTimer = setTimeout(() => popup.open && popup.close(), 2500); });

function toast(message, line) {
  const node = document.createElement("div");
  node.className = "toast";
  const t = document.createElement("strong"); t.textContent = message; node.appendChild(t);
  if (line) { const s = document.createElement("span"); s.textContent = line; node.appendChild(s); }
  const holder = document.getElementById("toasts");
  holder.appendChild(node);
  while (holder.children.length > 3) holder.firstElementChild.remove();
  setTimeout(() => node.classList.add("out"), 3800);
  setTimeout(() => node.remove(), 4100);
}

/* ---------- theme ---------- */
document.getElementById("theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("relay-theme", next); } catch (e) {}
});

/* ---------- encryption (unchanged) ---------- */
function createEnvelope(fileMetadata, content) {
  return {
    version: 1,
    metadata: { ...fileMetadata, encrypted_at: new Date().toISOString() },
    content: bytesToBase64(content)
  };
}
async function cloakEnvelope(envelope) {
  const keyResponse = await fetch("/aurora/orbit", { credentials: "same-origin", cache: "no-store" });
  if (!keyResponse.ok) throw new Error(`Could not load encryption key (HTTP ${keyResponse.status}).`);
  const publicKey = await crypto.subtle.importKey("spki", await keyResponse.arrayBuffer(),
    { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const contentKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, contentKey,
    new TextEncoder().encode(JSON.stringify(envelope)));
  const rawKey = await crypto.subtle.exportKey("raw", contentKey);
  const wrappedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawKey);
  return JSON.stringify({
    version: 2,
    wrapped_key: bytesToBase64(new Uint8Array(wrappedKey)),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(sealed))
  });
}
function sendRaw(body, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/quasar/relay");
    xhr.withCredentials = true;
    xhr.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
    xhr.onload = () => {
      let result = {};
      try { result = JSON.parse(xhr.responseText); } catch (e) {}
      if (xhr.status >= 200 && xhr.status < 300) resolve(result);
      else reject(new Error(result.error || "Upload failed."));
    };
    xhr.onerror = () => reject(new TypeError("network"));
    xhr.send(body);
  });
}

/* ---------- file preview ---------- */
async function inspectFile(file) {
  const metadata = {
    name: file.name, type: file.type || "unknown", size_bytes: file.size,
    last_modified: new Date(file.lastModified).toISOString()
  };
  fileInfo.textContent = JSON.stringify(metadata, null, 2);
  fileInfo.hidden = false;
  const bytes = new Uint8Array(await file.slice(0, maxPreviewBytes).arrayBuffer());
  if (file.type.startsWith("text/") || textFilePattern.test(file.name)) {
    filePreview.textContent = `Text preview (first ${bytes.length} bytes):\n\n${new TextDecoder().decode(bytes)}`;
  } else {
    filePreview.textContent = `Binary preview (first ${bytes.length} bytes, hex):\n\n${bytesToHex(bytes)}`;
  }
  filePreview.hidden = false;
}

/* ---------- queue ---------- */
const queueWrap = document.getElementById("queue-wrap");
const queueList = document.getElementById("queue");

function renderQueue() {
  const total = state.queue.reduce((s, q) => s + q.file.size, 0);
  queueWrap.hidden = !state.queue.length;
  document.getElementById("queue-count").textContent = state.queue.length;
  document.getElementById("queue-size").textContent = state.queue.length ? `(${formatSize(total)})` : "";
  queueList.replaceChildren();
  state.queue.forEach((entry, index) => {
    const li = document.createElement("li");
    const ext = document.createElement("div"); ext.className = "ext"; ext.textContent = extOf(entry.file.name);
    const body = document.createElement("div"); body.className = "q-body";
    const name = document.createElement("span"); name.className = "q-name"; name.textContent = entry.file.name;
    const meta = document.createElement("span"); meta.className = "q-meta";
    meta.textContent = `${entry.path || "root"} | ${formatSize(entry.file.size)}`;
    body.append(name, meta);
    li.append(ext, body);
    if (entry.status) {
      const st = document.createElement("span"); st.className = "q-state"; st.textContent = entry.status;
      li.append(st);
    } else {
      const rm = document.createElement("button");
      rm.type = "button"; rm.className = "btn btn-danger btn-sm"; rm.textContent = "Remove";
      rm.addEventListener("click", () => { state.queue.splice(index, 1); renderQueue(); });
      li.append(rm);
    }
    queueList.appendChild(li);
  });
  if (!state.queue.length) { fileInfo.hidden = true; filePreview.hidden = true; }
}

async function addToQueue(entries) {
  if (!entries.length) return;
  const key = (q) => `${q.path}|${q.file.name}|${q.file.size}|${q.file.lastModified}`;
  const seen = new Set(state.queue.map(key));
  let last = null;
  for (const entry of entries) {
    if (seen.has(key(entry))) continue;
    seen.add(key(entry)); state.queue.push(entry); last = entry;
  }
  renderQueue();
  document.getElementById("upload-status").textContent = "";
  if (last) {
    try { await inspectFile(last.file); }
    catch (error) { filePreview.textContent = `Could not read a preview: ${error.message}`; filePreview.hidden = false; }
  }
}

function showFileTab() { switchTab("file-tab", document.querySelector('[data-tab="file-tab"]')); }

fileInput.addEventListener("change", () => {
  const picked = Array.from(fileInput.files).map((file) => ({ file, path: "" }));
  fileInput.value = ""; addToQueue(picked);
});
folderInput.addEventListener("change", () => {
  const picked = Array.from(folderInput.files).map((file) => ({ file, path: file.webkitRelativePath || "" }));
  folderInput.value = ""; addToQueue(picked);
});
document.getElementById("pick-files").addEventListener("click", (e) => { e.stopPropagation(); fileInput.click(); });
document.getElementById("pick-folder").addEventListener("click", (e) => { e.stopPropagation(); folderInput.click(); });
document.getElementById("queue-clear").addEventListener("click", () => { state.queue = []; renderQueue(); });

/* ---------- drag and drop ---------- */
const dropzone = document.getElementById("dropzone");
const veil = document.getElementById("veil");
let dragDepth = 0;
dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && e.target === dropzone) { e.preventDefault(); fileInput.click(); }
});
function hasFiles(e) { return !!(e.dataTransfer && Array.from(e.dataTransfer.types || []).includes("Files")); }
function endDrag() { dragDepth = 0; veil.classList.remove("on"); dropzone.classList.remove("dragging"); }
function readBatch(reader) { return new Promise((res, rej) => reader.readEntries(res, rej)); }
function entryToFile(entry) { return new Promise((res, rej) => entry.file(res, rej)); }
async function walkEntry(entry, prefix, out) {
  if (entry.isFile) {
    const file = await entryToFile(entry);
    out.push({ file, path: prefix ? prefix + entry.name : "" });
  } else if (entry.isDirectory) {
    const reader = entry.createReader(); let batch;
    do {
      batch = await readBatch(reader);
      for (const child of batch) await walkEntry(child, `${prefix}${entry.name}/`, out);
    } while (batch.length);
  }
}
window.addEventListener("dragenter", (e) => {
  if (!hasFiles(e)) return; e.preventDefault(); dragDepth++;
  veil.classList.add("on"); dropzone.classList.add("dragging");
});
window.addEventListener("dragover", (e) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; });
window.addEventListener("dragleave", (e) => {
  if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) endDrag();
});
window.addEventListener("drop", async (e) => {
  if (!hasFiles(e)) return; e.preventDefault();
  const dt = e.dataTransfer, entries = [];
  if (dt.items) for (const item of dt.items) {
    if (item.kind === "file" && item.webkitGetAsEntry) { const en = item.webkitGetAsEntry(); if (en) entries.push(en); }
  }
  const fallback = Array.from(dt.files || []);
  endDrag(); showFileTab();
  const status = document.getElementById("upload-status"), collected = [];
  try {
    if (entries.length) {
      status.textContent = "Reading dropped items...";
      for (const en of entries) await walkEntry(en, "", collected);
    } else fallback.forEach((file) => collected.push({ file, path: "" }));
    status.textContent = "";
    await addToQueue(collected);
  } catch (error) { status.textContent = `Could not read dropped items: ${explainError(error)}`; }
});

/* ---------- upload ---------- */
document.getElementById("upload-button").addEventListener("click", async () => {
  const uploadStatus = document.getElementById("upload-status");
  const uploadButton = document.getElementById("upload-button");
  const progress = document.getElementById("progress");
  const bar = progress.firstElementChild;
  const queue = state.queue.slice();
  if (!queue.length) { uploadStatus.textContent = "Please select a file first."; return; }

  uploadButton.disabled = true; progress.hidden = false;
  let done = 0;
  try {
    for (const entry of queue) {
      const file = entry.file;
      uploadStatus.textContent = `Uploading ${done + 1} of ${queue.length}: ${entry.path || file.name}`;
      bar.style.width = "0";
      entry.status = "Encrypting..."; renderQueue();
      const content = new Uint8Array(await file.arrayBuffer());
      const envelope = createEnvelope({
        name: file.name, type: file.type || "application/octet-stream", size_bytes: file.size,
        last_modified: file.lastModified, relative_path: entry.path || file.webkitRelativePath || ""
      }, content);
      const cloaked = await cloakEnvelope(envelope);
      await sendRaw(cloaked, (p) => {
        bar.style.width = `${Math.round(p * 100)}%`;
        entry.status = `${Math.round(p * 100)}%`; renderQueue();
      });
      done++;
      state.queue.shift(); renderQueue();
    }
    uploadStatus.textContent = ""; fileInfo.hidden = true; filePreview.hidden = true;
    showPopup("upload", `Stored ${done} encrypted item${done > 1 ? "s" : ""} in RAM.`, "ok");
    await loadEncryptedItems();
  } catch (error) {
    state.queue.forEach((q) => delete q.status); renderQueue();
    const message = error instanceof TypeError
      ? "The upload request was blocked before reaching the server. Check the network proxy or firewall."
      : explainError(error);
    uploadStatus.textContent = `Upload failed: ${message}`;
    showPopup("fail", "Upload failed", "error");
    if (done) await loadEncryptedItems();
  } finally {
    uploadButton.disabled = false; progress.hidden = true;
  }
});

/* ---------- text editor ---------- */
const contentField = document.getElementById("content");
function updateCount() {
  const v = contentField.value;
  const lines = v ? v.split("\n").length : 0;
  const bytes = new TextEncoder().encode(v).length;
  document.getElementById("char-count").textContent =
    `${v.length.toLocaleString()} characters \u00b7 ${lines.toLocaleString()} lines \u00b7 ${formatSize(bytes)}`;
  contentField.style.height = "auto";
  contentField.style.height = Math.min(Math.max(contentField.scrollHeight, 360), 600) + "px";
}
contentField.addEventListener("input", updateCount);
contentField.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    e.preventDefault(); document.getElementById("paste-form").requestSubmit();
  } else if (e.key === "Tab" && !e.shiftKey) {
    e.preventDefault();
    const s = contentField.selectionStart, en = contentField.selectionEnd;
    contentField.setRangeText("  ", s, en, "end"); updateCount();
  }
});
document.getElementById("paste-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector("button[type=submit]");
  const content = form.elements.content.value;
  const filename = form.elements.filename.value.trim() || "paste.txt";
  if (!content) return;
  submit.disabled = true;
  try {
    const plaintext = new TextEncoder().encode(content);
    const envelope = createEnvelope({
      name: filename, type: "text/plain", size_bytes: plaintext.length,
      last_modified: Date.now(), relative_path: ""
    }, plaintext);
    const cloaked = await cloakEnvelope(envelope);
    await sendRaw(cloaked);
    form.reset(); updateCount();
    showPopup("commit", "Committed to the index.", "ok");
    await loadEncryptedItems();
  } catch (error) {
    showPopup("fail", `Could not encrypt and store content: ${explainError(error)}`, "error");
  } finally { submit.disabled = false; }
});

/* ---------- index ---------- */
function renderItems() {
  const list = document.querySelector(".items");
  const q = state.q.trim().toLowerCase();
  const rows = state.items.filter((i) => !q || (i.name || "").toLowerCase().includes(q));
  const by = {
    new: (a, b) => new Date(b.encrypted_at) - new Date(a.encrypted_at),
    old: (a, b) => new Date(a.encrypted_at) - new Date(b.encrypted_at),
    name: (a, b) => (a.name || "").localeCompare(b.name || ""),
    size: (a, b) => b.size_bytes - a.size_bytes
  };
  rows.sort(by[state.sort]);
  list.replaceChildren();
  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "empty" + (state.items.length ? " plain" : "");
    empty.textContent = state.items.length ? "No files match your search." : "The index is currently quiet.";
    list.appendChild(empty); return;
  }
  for (const item of rows) {
    const article = document.createElement("article");
    article.className = "item";
    article.innerHTML = `
      <div class="ext"></div>
      <div class="item-body"><strong class="filename"></strong><span class="metadata"></span></div>
      <div class="item-actions">
        <button type="button" class="btn btn-sm" data-a="open">Open</button>
        <button type="button" class="btn btn-sm" data-a="get">Retrieve</button>
        <button type="button" class="btn btn-sm" data-a="copy">Copy</button>
        <button type="button" class="btn btn-sm btn-danger push" data-a="del">Delete</button>
      </div>`;
    article.querySelector(".ext").textContent = extOf(item.name);
    const nameNode = article.querySelector(".filename");
    nameNode.textContent = item.name; nameNode.title = item.name;
    article.querySelector(".metadata").textContent =
      `${formatSize(item.size_bytes)} | ${item.type || "unknown"} | ${timeAgo(item.encrypted_at)}`;
    if (!isText(item)) article.querySelector('[data-a="copy"]').remove();
    article.querySelector('[data-a="open"]').addEventListener("click", () => openViewer(item));
    article.querySelector('[data-a="get"]').addEventListener("click", () => clientDownloadById(item.id, false));
    const copyBtn = article.querySelector('[data-a="copy"]');
    if (copyBtn) copyBtn.addEventListener("click", () => copyItem(item));
    article.querySelector('[data-a="del"]').addEventListener("click", () => deleteItem(item));
    list.appendChild(article);
  }
}
function updateSummary() {
  const total = state.items.reduce((s, i) => s + (i.size_bytes || 0), 0);
  document.getElementById("count").textContent = state.items.length;
  document.getElementById("total").textContent = `(${formatSize(total)})`;
  document.getElementById("summary-actions").hidden = !state.items.length;
}
async function loadEncryptedItems() {
  const response = await fetch("/nebula/catalog", { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error("Could not load encrypted items.");
  state.items = await response.json();
  updateSummary(); renderItems();
}
async function fetchItemBlob(id) {
  const response = await fetch(`/ember/${encodeURIComponent(id)}`, { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error("Could not retrieve item.");
  return response.blob();
}
async function clientDownloadById(itemId, viewOnly) {
  if (viewOnly) window.open(`/ember/${encodeURIComponent(itemId)}`, "_blank", "noopener");
  else { const a = document.createElement("a"); a.href = `/ember/${encodeURIComponent(itemId)}`; a.click(); }
}
async function copyItem(item) {
  try {
    const text = await (await fetchItemBlob(item.id)).text();
    await navigator.clipboard.writeText(text);
    const [, line, tr] = remark("copy");
    toast("Copied to clipboard.", `${line} (${tr})`);
  } catch (error) { showPopup("fail", `Copy failed: ${explainError(error)}`, "error"); }
}
async function deleteItem(item) {
  try {
    const response = await fetch(`/delete/${encodeURIComponent(item.id)}`, { method: "POST", credentials: "same-origin" });
    if (!response.ok) throw new Error("Delete failed.");
    showPopup("remove", `Deleted ${item.name}.`);
    await loadEncryptedItems();
  } catch (error) { showPopup("fail", explainError(error), "error"); }
}
document.getElementById("clear-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!confirm("Delete all items from memory?")) return;
  try {
    await fetch("/clear", { method: "POST", credentials: "same-origin" });
    showPopup("reset", "Drift reset.");
    await loadEncryptedItems();
  } catch (error) { showPopup("fail", explainError(error), "error"); }
});
document.getElementById("search").addEventListener("input", (e) => { state.q = e.target.value; renderItems(); });
document.getElementById("sort").addEventListener("change", (e) => { state.sort = e.target.value; renderItems(); });

/* ---------- viewer ---------- */
const viewer = document.getElementById("viewer");
const viewerBody = document.getElementById("viewer-body");
let viewerUrl = null;
async function openViewer(item) {
  state.viewing = item;
  document.getElementById("viewer-title").textContent = item.name;
  viewerBody.textContent = "Loading...";
  document.getElementById("viewer-copy").hidden = !isText(item);
  viewer.showModal();
  try {
    const blob = await fetchItemBlob(item.id);
    viewerBody.replaceChildren();
    if (viewerUrl) { URL.revokeObjectURL(viewerUrl); viewerUrl = null; }
    if ((item.type || "").startsWith("image/")) {
      viewerUrl = URL.createObjectURL(blob);
      const img = document.createElement("img"); img.src = viewerUrl; img.alt = item.name;
      viewerBody.appendChild(img);
    } else if (isText(item)) {
      const pre = document.createElement("pre"); pre.textContent = await blob.text();
      viewerBody.appendChild(pre);
    } else {
      viewerBody.textContent = `No inline preview for this file type (${item.type || "unknown"}). Use Retrieve to download it.`;
    }
  } catch (error) { viewerBody.textContent = explainError(error); }
}
document.getElementById("viewer-close").addEventListener("click", () => viewer.close());
viewer.addEventListener("click", (e) => { if (e.target === viewer) viewer.close(); });
document.getElementById("viewer-download").addEventListener("click", () => { if (state.viewing) clientDownloadById(state.viewing.id, false); });
document.getElementById("viewer-copy").addEventListener("click", () => { if (state.viewing) copyItem(state.viewing); });

document.addEventListener("keydown", (e) => {
  if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) {
    e.preventDefault(); document.getElementById("search").focus();
  }
});

updateCount();
try { if (!sessionStorage.getItem("relay-welcomed")) { sessionStorage.setItem("relay-welcomed","1"); setTimeout(() => showPopup("welcome","Welcome to Obsidian Relay","ok"), 400); } } catch (e) {}
loadEncryptedItems().catch((error) => {
  document.querySelector(".items").textContent = `Could not decrypt stored items in this browser: ${error.message}`;
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
            f"File is too large. Maximum size is " f"{format_bytes(max_size)}."
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
                f"File is too large. Maximum size is " f"{format_bytes(max_size)}."
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
        if payload.get("version") != 1 or payload["metadata"]["size_bytes"] != len(
            content
        ):
            raise ValueError
        return payload
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
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
        return jsonify({"error": str(error)}), 413

    if not encrypted_bytes:
        return jsonify({"error": "The request body is empty."}), 400

    try:
        envelope = json.loads(encrypted_bytes.decode("utf-8"))
        if envelope.get("version") != 2:
            raise ValueError
        for field in ("wrapped_key", "iv", "ciphertext"):
            base64.b64decode(envelope[field], validate=True)
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        return jsonify({"error": "Invalid file envelope."}), 400

    item = create_storage_item(encrypted_bytes)

    return (
        jsonify(
            {
                "message": "Stored protected payload in RAM memory.",
                "item_id": item["id"],
            }
        ),
        201,
    )


@app.route("/aurora/orbit", methods=["GET"])
def public_orbit_key():
    """Publish only the public key used by browsers to encrypt envelopes."""
    return SERVER_PUBLIC_KEY_DER, 200, {"Content-Type": "application/octet-stream"}


@app.route("/nebula/catalog", methods=["GET"])
def api_get_items():
    """Return decrypted metadata for browser rendering."""
    summary = [
        {**unseal_item(item)["metadata"], "id": item["id"]} for item in STORAGE.values()
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

                archive_name = f"{name}_{used_names[original_name]}" f"{extension}"
            else:
                used_names[original_name] = 0

            archive.writestr(
                archive_name,
                base64.b64decode(payload["content"], validate=True),
            )

    memory_zip.seek(0)

    zip_name = "vault_" f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}" ".zip"

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
        return (
            jsonify(
                {
                    "error": "The uploaded file exceeds the 100 MB limit.",
                }
            ),
            413,
        )

    return "The uploaded file exceeds the 100 MB limit.", 413


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "").lower() == "true",
    )
