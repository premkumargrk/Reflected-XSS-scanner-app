# import requests

# class XSSScanner:

#     def __init__(self, target_url, params, method, payload_generator):
#         self.target_url = target_url
#         self.params = params
#         self.method = method.upper()
#         self.payload_generator = payload_generator

#     def run_scan(self):
#         results = []

#         payloads = self.payload_generator.get_payloads()

#         for param in self.params:
#             original_value = self.params[param]

#             for payload in payloads:

#                 # Inject payload
#                 test_params = self.params.copy()
#                 test_params[param] = payload

#                 # Send request
#                 if self.method == "GET":
#                     res = requests.get(self.target_url, params=test_params)
#                 else:
#                     res = requests.post(self.target_url, data=test_params)

#                 reflected = payload in res.text

#                 results.append({
#                     "parameter": param,
#                     "payload": payload,
#                     "reflected": reflected,
#                     "snippet": self._get_snippet(res.text, payload) if reflected else ""
#                 })

#         return results

#     def _get_snippet(self, text, payload, win=50):
#         index = text.find(payload)
#         if index == -1:
#             return ""
#         start = max(0, index - win)
#         end = min(len(text), index + len(payload) + win)
#         return text[start:end]


# core/scanner.py
# import requests
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from bs4 import BeautifulSoup
# import re
# import json

# class XSSScanner:
#     def __init__(self, target_url, params, method, payload_generator,
#                  headers=None, cookies=None, threads=10, json_body=False, timeout=15):
#         self.target_url = target_url
#         self.params = params or {}
#         self.method = method.upper()
#         self.payload_generator = payload_generator
#         self.headers = headers or {"User-Agent": "XSS-Scanner/1.0"}
#         self.cookies = cookies or {}
#         self.threads = threads
#         self.json_body = json_body
#         self.timeout = timeout
#         self.session = requests.Session()
#         self.session.headers.update(self.headers)
#         if self.cookies:
#             self.session.cookies.update(self.cookies)

#     def run_scan(self):
#         results = []
#         payloads = self.payload_generator.get_payloads()

#         tasks = []
#         with ThreadPoolExecutor(max_workers=10) as exe:
#             futures = []
#             for param in self.params:
#                 for payload in payloads:
#                     futures.append(exe.submit(self._test_single, param, payload))
#             for f in as_completed(futures):
#                 r = f.result()
#                 if r:
#                     results.append(r)
#         return results

#     def _test_single(self, param, payload):
#         test_params = self.params.copy()
#         test_params[param] = payload

#         try:
#             if self.method == "GET":
#                 resp = self.session.get(self.target_url, params=test_params, timeout=self.timeout)
#             else:
#                 # JSON body option: if json_body True, send the entire params as JSON
#                 if self.json_body:
#                     resp = self.session.post(self.target_url, json=test_params, timeout=self.timeout)
#                 else:
#                     resp = self.session.post(self.target_url, data=test_params, timeout=self.timeout)
#         except Exception as e:
#             return {"parameter": param, "payload": payload, "reflected": False, "error": str(e)}

#         text = resp.text or ""
#         reflected = payload in text

#         guessed = None
#         snippet = ""
#         if reflected:
#             snippet = self._get_snippet(text, payload)
#             guessed = self._guess_context(snippet)

#         return {
#             "parameter": param,
#             "payload": payload,
#             "reflected": reflected,
#             "status_code": resp.status_code,
#             "url": resp.url,
#             "snippet": snippet,
#             "guessed_context": guessed
#         }

#     def _get_snippet(self, text, payload, win=80):
#         idx = text.find(payload)
#         if idx == -1:
#             return ""
#         start = max(0, idx - win)
#         end = min(len(text), idx + len(payload) + win)
#         return text[start:end]

#     def _guess_context(self, snippet):
#         # simple heuristics + BeautifulSoup
#         s = snippet.lower()
#         # inside tag attribute pattern
#         if re.search(r'\w+\s*=\s*["\'].*' + re.escape(snippet.strip()), s):
#             return "attr-value"
#         # inside script tags?
#         if "<script" in s or "</script>" in s:
#             return "js"
#         # attribute-name guess (payload followed by = in tag)
#         if re.search(r'[<][^>]*' + re.escape(snippet.strip()) + r'\s*=', s):
#             return "attr-name"
#         # fallback: parse snippet for tag boundaries
#         try:
#             soup = BeautifulSoup(snippet, "html.parser")
#             # if the text appears as plain text node:
#             if soup.find() and soup.find().string and snippet.strip() in soup.find().string:
#                 return "text"
#         except Exception:
#             pass
#         return "unknown"


import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def merge_params(url, new_params):
        parsed = urlparse(url)
        existing = parse_qs(parsed.query)
        existing.update(new_params)
        new_query = urlencode(existing, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

class XSSScanner:
    def __init__(self, target_url, params, method, payload_generator,
                 headers=None, cookies=None, threads=3, json_body=False, timeout=8):
        self.target_url = target_url
        self.params = params or {}
        self.method = method.upper()
        self.payload_generator = payload_generator
        self.headers = headers or {"User-Agent": "XSS-Scanner/1.0"}
        self.cookies = cookies or {}
        self.threads = min(threads, 5)   # hard limit for stability
        self.json_body = json_body
        self.timeout = timeout


    def run_scan(self):
        payloads = self.payload_generator.get_payloads()
        results = []

        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = []

            for param in self.params:
                for payload in payloads:
                    futures.append(exe.submit(self._test_single, param, payload))

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout + 3)
                    if result:
                        results.append(result)
                except Exception:
                    # thread crashed or timeout
                    pass

        return results

    def _test_single(self, param, payload):
        test_params = self.params.copy()
        test_params[param] = payload

        try:
            if self.method == "GET":
                final_url = merge_params(self.target_url, test_params)
                resp = requests.get(
                    final_url,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout
                    )
            else:
                if self.json_body:
                    resp = requests.post(
                        self.target_url,
                        json=test_params,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout
                    )
                else:
                    resp = requests.post(
                        self.target_url,
                        data=test_params,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout
                    )
        except Exception as e:
            return {
                "parameter": param,
                "payload": payload,
                "reflected": False,
                "error": str(e)
            }

        body = resp.text or ""
        reflected = payload in body

        snippet = self._get_snippet(body, payload) if reflected else ""
        guessed = self._guess_context(snippet) if reflected else None

        return {
            "parameter": param,
            "payload": payload,
            "reflected": reflected,
            "status_code": resp.status_code,
            "url": resp.url,
            "snippet": snippet,
            "guessed_context": guessed
        }

    def _get_snippet(self, text, payload, win=60):
        idx = text.find(payload)
        if idx == -1:
            return ""
        return text[max(0, idx - win):idx + len(payload) + win]

    def _guess_context(self, snippet):
        s = snippet.lower()

        if "=" in s and "<" in s:
            return "attr-value"
        if "script" in s:
            return "js"
        if s.strip().startswith("on"):
            return "attr-name"
        return "text"
