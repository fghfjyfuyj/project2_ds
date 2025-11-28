# app.py
import os, time, json, re, tempfile, base64
from urllib.parse import urljoin, urlparse
from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup
import pandas as pd
import pdfplumber
from playwright.sync_api import sync_playwright

app = Flask(__name__)
EXPECTED_SECRET = os.environ.get('QUIZ_SECRET', 'replace-with-your-secret')
GLOBAL_TIMEOUT = 180  # seconds

# --- Helpers -------------------------------------------------
def is_safe_url(url):
    # Basic SSRF mitigation: only allow http/https and deny private IPs/ranges
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        host = parsed.hostname
        # reject local hostnames
        if host in ('localhost', '127.0.0.1', '::1'):
            return False
        # further protections (could add IP checks)
        return True
    except Exception:
        return False

def decode_atob_from_html(html):
    matches = re.findall(r'atob\\(`([A-Za-z0-9+/=\\n\\r ]+)`\\)', html)
    decoded = []
    for m in matches:
        try:
            s = m.replace('\\n','').replace('\\r','').strip()
            decoded.append(base64.b64decode(s).decode('utf-8', errors='ignore'))
        except Exception:
            pass
    return decoded

def try_parse_json_from_text(text):
    try:
        return json.loads(text)
    except Exception:
        return None

def find_submit_url_in_text(text, base=None):
    # look for obvious submit endpoints
    m = re.search(r'(https?://\\S*submit\\S*)', text, re.IGNORECASE)
    if m:
        return m.group(1)
    # look for any https link that contains '/submit' segment
    urls = re.findall(r'(https?://\\S+)', text)
    for u in urls:
        if '/submit' in u:
            return u
    return None

# --- Solvers -------------------------------------------------
def sum_value_in_csv_bytes(content):
    df = pd.read_csv(pd.io.common.BytesIO(content))
    cols = [c for c in df.columns if c.lower() == 'value']
    if cols:
        return float(pd.to_numeric(df[cols[0]], errors='coerce').sum())
    return None

def sum_value_in_excel_bytes(content):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx')
    tmp.write(content); tmp.flush()
    df = pd.read_excel(tmp.name)
    cols = [c for c in df.columns if c.lower() == 'value']
    if cols:
        return float(pd.to_numeric(df[cols[0]], errors='coerce').sum())
    return None

def sum_value_in_pdf_bytes(content):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    tmp.write(content); tmp.flush()
    total = 0.0
    with pdfplumber.open(tmp.name) as pdf:
        for p in pdf.pages:
            try:
                tables = p.extract_tables()
                for t in tables:
                    if len(t) < 2: 
                        continue
                    df = pd.DataFrame(t[1:], columns=t[0])
                    for c in df.columns:
                        if c.lower() == 'value':
                            df[c] = pd.to_numeric(df[c], errors='coerce')
                            total += df[c].sum(skipna=True)
            except Exception:
                continue
    return total if total != 0.0 else None

# --- Main extraction & solve --------------------------------
def extract_payload_from_page(page):
    html = page.content()
    soup = BeautifulSoup(html, 'html.parser')

    # 1) <pre> with JSON
    pre = soup.find('pre')
    if pre:
        parsed = try_parse_json_from_text(pre.get_text())
        if parsed:
            return {'type': 'json', 'payload': parsed}

    # 2) decode atob base64 scripts
    decs = decode_atob_from_html(html)
    for d in decs:
        parsed = try_parse_json_from_text(d)
        if parsed:
            return {'type': 'json', 'payload': parsed}
        # fallback to text payload
        return {'type': 'text', 'payload': d}

    # 3) look for submit link
    for a in soup.find_all('a', href=True):
        if 'submit' in a['href'].lower():
            return {'type': 'submit_link', 'submit_url': urljoin(page.url, a['href'])}

    # 4) fallback to visible text
    return {'type': 'text', 'payload': page.inner_text('body')[:10000]}

def solve_payload_struct(payload, email=None, secret=None):
    # payload may be dict with 'url' / 'file' / 'submit' etc.
    result = {}
    if isinstance(payload, dict):
        # common shape: contains url to download
        file_url = payload.get('url') or payload.get('file') or payload.get('download')
        submit_url = payload.get('submit') or payload.get('submit_url')
        if file_url and is_safe_url(file_url):
            try:
                r = requests.get(file_url, timeout=30)
                r.raise_for_status()
                ct = r.headers.get('content-type','').lower()
                if 'csv' in ct or file_url.lower().endswith('.csv'):
                    s = sum_value_in_csv_bytes(r.content)
                    if s is not None:
                        result['answer'] = s
                elif 'excel' in ct or file_url.lower().endswith(('.xls','.xlsx')):
                    s = sum_value_in_excel_bytes(r.content)
                    if s is not None:
                        result['answer'] = s
                elif 'pdf' in ct or file_url.lower().endswith('.pdf'):
                    s = sum_value_in_pdf_bytes(r.content)
                    if s is not None:
                        result['answer'] = s
                else:
                    # unknown: attach as base64
                    result['answer'] = 'data:;base64,' + base64.b64encode(r.content).decode('utf-8')
            except Exception as e:
                result['error'] = str(e)
        # if payload included an answer already, use it
        if 'answer' in payload:
            result['answer'] = payload['answer']
        if submit_url:
            result['submit_url'] = submit_url
    else:
        # text heuristics: try to find file link in text
        text = str(payload)
        m = re.search(r'(https?://\\S+\\.(csv|xlsx|xls|pdf))', text, re.IGNORECASE)
        if m:
            file_url = m.group(1)
            return solve_payload_struct({'url': file_url}, email=email, secret=secret)
        # fallback: if a number appears, choose first number
        nums = re.findall(r'[-+]?[0-9]*\\.?[0-9]+', text)
        if nums:
            result['answer'] = float(nums[0])
    if email: result.setdefault('email', email)
    if secret: result.setdefault('secret', secret)
    return result

# --- Route ---------------------------------------------------
@app.route('/quiz', methods=['POST'])
def quiz_entry():
    start = time.time()
    if not request.is_json:
        return ('Invalid JSON', 400)
    body = request.get_json()
    email = body.get('email')
    secret = body.get('secret')
    url = body.get('url')
    if secret != EXPECTED_SECRET:
        return ('Forbidden', 403)

    # quick accept
    resp = {'status': 'accepted'}

    if not url:
        return jsonify(resp), 200

    if not is_safe_url(url):
        resp['error'] = 'unsafe url'
        return jsonify(resp), 400

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=30000)
            page.wait_for_load_state('networkidle', timeout=30000)
            info = extract_payload_from_page(page)
            solved = solve_payload_struct(info.get('payload') if 'payload' in info else info, email=email, secret=secret)

            submit_url = solved.get('submit_url')
            if not submit_url:
                # try to find submit URL in visible text
                submit_url = find_submit_url_in_text(page.inner_text('body'), base=url)

            if 'answer' in solved and submit_url and is_safe_url(submit_url):
                payload = {'email': email, 'secret': secret, 'url': url, 'answer': solved['answer']}
                r = requests.post(submit_url, json=payload, timeout=30)
                try:
                    jr = r.json()
                    resp['submission_response'] = jr
                except Exception:
                    resp['submission_status_code'] = r.status_code
            else:
                resp['info'] = {'extracted': info, 'solved': solved}

            browser.close()
    except Exception as e:
        resp['error'] = str(e)

    resp['elapsed'] = time.time() - start
    return jsonify(resp), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '7860')))

