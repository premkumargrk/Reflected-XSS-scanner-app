# # import requests
# # from concurrent.futures import ThreadPoolExecutor, as_completed
# # import re
# # from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# # def merge_params(url, new_params):
# #         parsed = urlparse(url)
# #         existing = parse_qs(parsed.query)
# #         existing.update(new_params)
# #         new_query = urlencode(existing, doseq=True)
# #         return urlunparse(parsed._replace(query=new_query))

# # class XSSScanner:
# #     def __init__(self, target_url, params, method, payload_generator,
# #                  headers=None, cookies=None, threads=3, json_body=False, timeout=8):
# #         self.target_url = target_url
# #         self.params = params or {}
# #         self.method = method.upper()
# #         self.payload_generator = payload_generator
# #         self.headers = headers or {"User-Agent": "XSS-Scanner/1.0"}
# #         self.cookies = cookies or {}
# #         self.threads = min(threads, 5)   # hard limit for stability
# #         self.json_body = json_body
# #         self.timeout = timeout


# #     def run_scan(self):
# #         payloads = self.payload_generator.get_payloads()
# #         results = []

# #         with ThreadPoolExecutor(max_workers=self.threads) as exe:
# #             futures = []

# #             for param in self.params:
# #                 for payload in payloads:
# #                     futures.append(exe.submit(self._test_single, param, payload))

# #             for future in as_completed(futures):
# #                 try:
# #                     result = future.result(timeout=self.timeout + 3)
# #                     if result:
# #                         results.append(result)
# #                 except Exception:
# #                     # thread crashed or timeout
# #                     pass

# #         return results

# #     def _test_single(self, param, payload):
# #         test_params = self.params.copy()
# #         test_params[param] = payload

# #         try:
# #             if self.method == "GET":
# #                 final_url = merge_params(self.target_url, test_params)
# #                 resp = requests.get(
# #                     final_url,
# #                     headers=self.headers,
# #                     cookies=self.cookies,
# #                     timeout=self.timeout
# #                     )
# #             else:
# #                 if self.json_body:
# #                     resp = requests.post(
# #                         self.target_url,
# #                         json=test_params,
# #                         headers=self.headers,
# #                         cookies=self.cookies,
# #                         timeout=self.timeout
# #                     )
# #                 else:
# #                     resp = requests.post(
# #                         self.target_url,
# #                         data=test_params,
# #                         headers=self.headers,
# #                         cookies=self.cookies,
# #                         timeout=self.timeout
# #                     )
# #         except Exception as e:
# #             return {
# #                 "parameter": param,
# #                 "payload": payload,
# #                 "reflected": False,
# #                 "error": str(e)
# #             }

# #         body = resp.text or ""
# #         reflected = payload in body

# #         snippet = self._get_snippet(body, payload) if reflected else ""
# #         guessed = self._guess_context(snippet) if reflected else None

# #         return {
# #             "parameter": param,
# #             "payload": payload,
# #             "reflected": reflected,
# #             "status_code": resp.status_code,
# #             "url": resp.url,
# #             "snippet": snippet,
# #             "guessed_context": guessed
# #         }

# #     def _get_snippet(self, text, payload, win=60):
# #         idx = text.find(payload)
# #         if idx == -1:
# #             return ""
# #         return text[max(0, idx - win):idx + len(payload) + win]

# #     def _guess_context(self, snippet):
# #         s = snippet.lower()

# #         if "=" in s and "<" in s:
# #             return "attr-value"
# #         if "script" in s:
# #             return "js"
# #         if s.strip().startswith("on"):
# #             return "attr-name"
# #         return "text"


# # core/scanner.py
# import requests
# from concurrent.futures import ThreadPoolExecutor, as_completed
# import re
# from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
# import html


# def merge_params(url, new_params):
#     """
#     Merge existing query string in URL with new_params (dict).
#     Returns final URL string.
#     """
#     parsed = urlparse(url)
#     existing = parse_qs(parsed.query)
#     # parse_qs gives lists. Flatten simple values:
#     for k, v in new_params.items():
#         existing[k] = [v]
#     new_query = urlencode(existing, doseq=True)
#     return urlunparse(parsed._replace(query=new_query))


# class XSSScanner:
#     def __init__(self, target_url, params, method, payload_generator,
#                  headers=None, cookies=None, threads=3, json_body=False, timeout=8):
#         self.target_url = target_url
#         self.params = params or {}
#         self.method = method.upper()
#         self.payload_generator = payload_generator
#         self.headers = headers or {"User-Agent": "XSS-Scanner/1.0"}
#         self.cookies = cookies or {}
#         # Keep threads small for web app stability
#         self.threads = max(1, min(threads, 6))
#         self.json_body = json_body
#         self.timeout = timeout

#     def run_scan(self):
#         payloads = self.payload_generator.get_payloads()
#         results = []

#         with ThreadPoolExecutor(max_workers=self.threads) as exe:
#             futures = []
#             for param in self.params:
#                 for payload in payloads:
#                     futures.append(exe.submit(self._test_single, param, payload))

#             for future in as_completed(futures):
#                 try:
#                     r = future.result(timeout=self.timeout + 3)
#                     if r:
#                         results.append(r)
#                 except Exception:
#                     # timeout or thread error -> skip
#                     pass

#         return results

#     def _test_single(self, param, payload):
#         # prepare param set for this test
#         test_params = self.params.copy()
#         test_params[param] = payload

#         try:
#             if self.method == "GET":
#                 final_url = merge_params(self.target_url, test_params)
#                 resp = requests.get(final_url,
#                                     headers=self.headers,
#                                     cookies=self.cookies,
#                                     timeout=self.timeout)
#             else:
#                 # POST: do not merge into URL automatically (this is POST body)
#                 if self.json_body:
#                     resp = requests.post(self.target_url,
#                                          json=test_params,
#                                          headers=self.headers,
#                                          cookies=self.cookies,
#                                          timeout=self.timeout)
#                 else:
#                     resp = requests.post(self.target_url,
#                                          data=test_params,
#                                          headers=self.headers,
#                                          cookies=self.cookies,
#                                          timeout=self.timeout)

#         except Exception as e:
#             return {
#                 "parameter": param,
#                 "payload": payload,
#                 "reflected": False,
#                 "error": str(e)
#             }

#         body = resp.text or ""

#         # Detect unsafe reflection (avoid JSON-safe and HTML-escaped false positives)
#         unsafe, reason = self._detect_unsafe_reflection(payload, body)

#         snippet = self._get_snippet(body, payload) if unsafe else ""
#         guessed = self._guess_context(snippet) if unsafe else None

#         return {
#             "parameter": param,
#             "payload": payload,
#             "reflected": unsafe,
#             "status_code": resp.status_code,
#             "url": resp.url,
#             "snippet": snippet,
#             "guessed_context": guessed,
#             "detection_reason": reason
#         }

#     def _get_snippet(self, text, payload, win=80):
#         idx = text.find(payload)
#         if idx == -1:
#             return ""
#         return text[max(0, idx - win): idx + len(payload) + win]

#     def _is_html_escaped(self, text, payload):
#         """Return True if payload appears only as HTML-escaped entities in the text."""
#         # Compare HTML-unescaped text: if unescaped version contains payload it's escaped in page.
#         unescaped = html.unescape(text)
#         return payload not in text and payload in unescaped

#     # def _is_json_safe(self, text, payload):
#     #     """
#     #     Heuristic: payload appears in JSON-like key:value pair, e.g.
#     #     "someKey":"payload"  or  'someKey':'payload'
#     #     If so, treat as safe (not immediate XSS).
#     #     """
#     #     # Look for "key": "payload" pattern (allow whitespace)
#     #     pat = re.compile(r'"\s*[\w\-]+"\s*:\s*"' + re.escape(payload) + r'"')
#     #     if pat.search(text):
#     #         return True
#     #     # single-quoted JS object style
#     #     pat2 = re.compile(r"'\s*[\w\-]+'\s*:\s*'" + re.escape(payload) + r"'")
#     #     if pat2.search(text):
#     #         return True
#     #     return False
#     def _is_json_safe(self, text, payload):
#     # only treat as JSON-safe if body STARTS with { or [
#         if not text.strip().startswith(("{", "[")):
#             return False

#     # then detect true JSON structure
#         pat = re.compile(r'"\s*[\w\-]+"\s*:\s*"' + re.escape(payload) + r'"')
#         return bool(pat.search(text))

#     def _detect_attr_name_injection(self, text, payload):
#         """
#         Detect if payload appears as attribute name (e.g. <img PAYLOAD=...>)
#         This is a strong signal of attribute-name injection possibility.
#         """
#         # look for pattern: <tag ... PAYLOAD[ = or >]
#         pat = re.compile(r'<[a-zA-Z0-9:_-]+[^>]*\b' + re.escape(payload) + r'\b\s*(=|\>)', re.IGNORECASE)
#         return bool(pat.search(text))

#     def _detect_unquoted_attr(self, snippet, payload):
#         """
#         If snippet contains payload inside a tag but not within quotes, it's more dangerous.
#         E.g. <input value=PAYLOAD>
#         """
#         # find nearest '<' before payload and '>' after
#         idx = snippet.find(payload)
#         if idx == -1:
#             return False
#         left = snippet[:idx]
#         right = snippet[idx + len(payload):]
#         if '<' in left and '>' in right:
#             # approximate: if there is a '=' before payload and no opening quote between '=' and payload
#             eq_idx = left.rfind('=')
#             if eq_idx != -1:
#                 between = left[eq_idx + 1:]
#                 if '"' not in between and "'" not in between:
#                     return True
#         return False

#     def _detect_unsafe_reflection(self, payload, body):
#         """
#         Returns (unsafe_bool, reason_string).
#         unsafe_bool True -> payload reflected in an unsafe (possibly exploitable) way.
#         """
#         if payload == "":
#             return False, "empty-payload"

#         # If payload not present at all -> safe
#         if payload not in body:
#             # but maybe server HTML-escaped it -> check unescape
#             unescaped = html.unescape(body)
#             if payload in unescaped:
#                 return False, "escaped-in-html"  # escaped shows up but not raw
#             return False, "not-present"

#         # If it appears inside JSON-like key:value -> treat as safe
#         if self._is_json_safe(body, payload):
#             return False, "json-safe-reflection"

#         # If it appears only as escaped entities -> safe
#         if self._is_html_escaped(body, payload):
#             return False, "html-escaped"

#         # Strong signal: appears as attribute name injection
#         if self._detect_attr_name_injection(body, payload):
#             return True, "attr-name-detected"

#         # For each occurrence, inspect small snippet
#         start = 0
#         while True:
#             idx = body.find(payload, start)
#             if idx == -1:
#                 break
#             # take snippet
#             s = body[max(0, idx - 80): idx + len(payload) + 80]
#             # if payload is inside a tag and not quoted => dangerous
#             if '<' in s and '>' in s:
#                 if self._detect_unquoted_attr(s, payload):
#                     return True, "unquoted-attr"
#                 # if appears inside an actual <script> block (not JSON), dangerous
#                 if re.search(r'<script[^>]*>.*' + re.escape(payload) + r'.*</script>', s, re.IGNORECASE | re.DOTALL):
#                     return True, "script-context"
#                 # if it ends up directly in HTML text between >payload<, treat as possible XSS (may need manual validation)
#                 if re.search(r'>[^<]*' + re.escape(payload) + r'[^<]*<', s):
#                     return True, "in-text-node"
#             else:
#                 # outside tags, plain text in body — typically safe, but still report as reflection only
#                 return True, "plain-body-reflection"
#             start = idx + len(payload)

#         # fallback: consider safe if nothing matched
#         return False, "unknown-but-present"


# core/scanner.py
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import html


def merge_params(url, new_params):
    """
    Merge existing query string in URL with new_params (dict).
    Returns final URL string.
    """
    parsed = urlparse(url)
    existing = parse_qs(parsed.query)
    # parse_qs returns lists; set each key to single-item list for urlencode
    for k, v in new_params.items():
        existing[k] = [v]
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
        self.threads = max(1, min(threads, 6))
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
                    r = future.result(timeout=self.timeout + 3)
                    if r:
                        results.append(r)
                except Exception:
                    # timeout or thread error -> skip
                    pass

        return results

    def _test_single(self, param, payload):
        # prepare param set for this test
        test_params = self.params.copy()
        test_params[param] = payload

        try:
            if self.method == "GET":
                final_url = merge_params(self.target_url, test_params)
                resp = requests.get(final_url, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
            else:
                if self.json_body:
                    resp = requests.post(self.target_url, json=test_params, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
                else:
                    resp = requests.post(self.target_url, data=test_params, headers=self.headers, cookies=self.cookies, timeout=self.timeout)
        except Exception as e:
            return {
                "parameter": param,
                "payload": payload,
                "reflected": False,
                "error": str(e)
            }

        body = resp.text or ""

        # Detect unsafe reflection (avoid JSON-safe and HTML-escaped false positives)
        unsafe, reason = self._detect_unsafe_reflection(payload, body)

        snippet = self._get_snippet(body, payload) if unsafe else ""
        guessed = self._guess_context(snippet) if unsafe else None

        return {
            "parameter": param,
            "payload": payload,
            "reflected": unsafe,
            "status_code": resp.status_code,
            "url": resp.url,
            "snippet": snippet,
            "guessed_context": guessed,
            "detection_reason": reason
        }

    def _get_snippet(self, text, payload, win=80):
        idx = text.find(payload)
        if idx == -1:
            return ""
        return text[max(0, idx - win): idx + len(payload) + win]

    def _is_html_escaped(self, text, payload):
        """Return True if payload appears only as HTML-escaped entities in the text."""
        unescaped = html.unescape(text)
        return payload not in text and payload in unescaped

    def _is_json_safe(self, text, payload):
        """
        Heuristic: treat as JSON-safe only if the occurrence looks like a JSON value
        and is not embedded in surrounding HTML tags.
        """
        # quick reject
        if payload not in text:
            return False

        # find occurrences of "someKey":"payload"
        pat = re.compile(r'"\s*[\w\-\$@]+"\s*:\s*"' + re.escape(payload) + r'"')
        for m in pat.finditer(text):
            start, end = m.start(), m.end()
            # context window around the match
            left = text[max(0, start - 60):start]
            right = text[end:end + 60]
            # if no '<' in left and no '>' in right, very likely JSON/JS object, treat safe
            if '<' not in left and '>' not in right:
                return True
        return False

    def _detect_attr_name_injection(self, text, payload):
        """
        Detect if payload appears as attribute name (e.g. <img PAYLOAD=...>)
        """
        pat = re.compile(r'<[a-zA-Z0-9:_-]+[^>]*\b' + re.escape(payload) + r'\b\s*(=|\>)', re.IGNORECASE)
        return bool(pat.search(text))

    def _detect_unquoted_attr(self, snippet, payload):
        """
        If snippet contains payload inside a tag but not within quotes, it's more dangerous.
        """
        idx = snippet.find(payload)
        if idx == -1:
            return False
        left = snippet[:idx]
        right = snippet[idx + len(payload):]
        if '<' in left and '>' in right:
            eq_idx = left.rfind('=')
            if eq_idx != -1:
                between = left[eq_idx + 1:]
                # no opening quote between '=' and payload -> unquoted attr
                if '"' not in between and "'" not in between:
                    return True
        return False

    def _detect_unsafe_reflection(self, payload, body):
        """
        Returns (unsafe_bool, reason_string).
        """
        if payload == "":
            return False, "empty-payload"

        # If payload not present at all -> safe
        if payload not in body:
            # but maybe server HTML-escaped it -> check unescape
            unescaped = html.unescape(body)
            if payload in unescaped:
                return False, "escaped-in-html"
            return False, "not-present"

        # If it appears inside JSON-like key:value and looks like JSON (and not embedded in HTML), treat as safe
        if self._is_json_safe(body, payload):
            return False, "json-safe-reflection"

        # If it appears only as escaped entities -> safe
        if self._is_html_escaped(body, payload):
            return False, "html-escaped"

        # Strong signal: attribute-name injection
        if self._detect_attr_name_injection(body, payload):
            return True, "attr-name-detected"

        # Look at occurrences to decide
        start = 0
        while True:
            idx = body.find(payload, start)
            if idx == -1:
                break
            s = body[max(0, idx - 120): idx + len(payload) + 120]
            # if payload is inside a tag and not quoted => dangerous
            if '<' in s and '>' in s:
                if self._detect_unquoted_attr(s, payload):
                    return True, "unquoted-attr"
                # appears inside <script> ... payload ... </script>
                if re.search(r'<script[^>]*>.*' + re.escape(payload) + r'.*</script>', s, re.IGNORECASE | re.DOTALL):
                    return True, "script-context"
                # appears between >payload< (plain text node)
                if re.search(r'>[^<]*' + re.escape(payload) + r'[^<]*<', s):
                    return True, "in-text-node"
            else:
                # outside tags, plain body text (could be dangerous in some contexts)
                return True, "plain-body-reflection"
            start = idx + len(payload)

        # fallback
        return False, "unknown-but-present"

    def _guess_context(self, snippet):
        s = (snippet or "").lower()
        if not s:
            return None
        if "<script" in s or "</script>" in s:
            return "js"
        if re.search(r'>[^<]*<', s):
            return "text"
        if re.search(r'\b(on\w+)\s*=', s):
            return "attr-value"
        # attribute-name style (payload followed by =)
        if re.search(r'\b[\w\-]+\b\s*=', s):
            return "attr-name"
        return "unknown"
