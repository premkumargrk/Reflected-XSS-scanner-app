# app.py (relevant parts)
from flask import Flask, render_template, request
from core.scanner import XSSScanner
from core.payload_generator import PayloadGenerator
import json as pyjson

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url")
    method = request.form.get("method", "GET")
    params_raw = request.form.get("params", "")
    contexts = request.form.getlist("contexts") or None
    threads = int(request.form.get("threads", 10))
    json_body = request.form.get("json_body")=="on"
    headers_raw = request.form.get("headers", "")
    cookies_raw = request.form.get("cookies", "")

    # parse params: key=value&key2=value2
    params = {}
    if params_raw.strip():
        for p in params_raw.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v

    # parse headers/cookies as JSON or key:value lines
    def parse_kv_block(text):
        if not text.strip():
            return {}
        try:
            return pyjson.loads(text)  # try JSON
        except:
            out = {}
            for line in text.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
            return out

    headers = parse_kv_block(headers_raw)
    cookies = parse_kv_block(cookies_raw)

    payload_gen = PayloadGenerator(contexts)
    scanner = XSSScanner(target_url=url, params=params, method=method,
                         payload_generator=payload_gen,
                         headers=headers, cookies=cookies,
                         threads=threads, json_body=json_body)

    # results = scanner.run_scan()
    print("[+] Received scan request")
    results = scanner.run_scan()
    print("[+] Scan completed")

    return render_template("report.html", results=results, url=url)
if __name__ == "__main__":
    app.run(debug=True, port=5000)
