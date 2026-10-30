"""Local-only insecure demo page for DAST before/after framing and form scanning.

Never deploy this ASGI service; it has no database and no sensitive information.
Only the static insecure lab surface is exposed during isolated CI scanning.
"""
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html><html><head><title>Intentionally Insecure Lab</title></head>
    <body><h1>Vulnerable training form</h1><form action='/action' method='post'>
    <input name='action' value='change-setting'><button type='submit'>Change</button>
    </form><p>This demo intentionally has no anti-CSRF token or anti-framing headers.</p></body></html>"""

@app.post("/action", response_class=HTMLResponse)
def action():
    return "<html><body>Lab-only action accepted without CSRF token</body></html>"
