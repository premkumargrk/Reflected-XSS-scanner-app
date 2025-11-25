# 🔍 XSS Reflection Scanner  
A multithreaded reflected Cross-Site Scripting (XSS) scanner built with **Flask (backend)** and **HTML/JS (frontend)**.  
The tool automatically injects context-aware payloads, sends HTTP requests, detects reflections, and displays a structured report.

---

## ✨ Features

- ✔ **Reflection detection engine**  
- ✔ **PayloadGenerator** with context-specific payload selection  
- ✔ Supports **GET / POST** requests  
- ✔ **JSON or Standard Form** parameters  
- ✔ Optional **headers** & **cookies** injection  
- ✔ **Multithreading** for fast scanning  
- ✔ Clean browser UI with detailed scan results  
- ✔ Snippet-based reflection confirmation  

---

## 🧠 Assumptions

This scanner is designed for:

- Websites that **reflect query parameters** into the HTML response
- Testing for **Reflected XSS**, *not* DOM-based XSS
- Security research, education, and safe environments
- Clean HTML-response reflection detection (no JavaScript execution)

It does **not** execute payloads in a browser (no alert pop-ups).  
It only checks whether the payload **appears in the response** → indicating vulnerability.

---

## 🧩 How PayloadGenerator Works

`PayloadGenerator` automatically picks payloads based on **context selection**:

| Context | Description | Example Payload |
|---------|-------------|----------------|
| **Text Node** | Reflected inside plain text | `XSS_MARKER_ABC` |
| **Attribute Value** | Reflected inside HTML attribute | `" autofocus onfocus=alert(1) x="TEST` |
| **Attribute Name** | Reflected as HTML attribute name | `onerror=alert(2)` |
| **JavaScript Context** | Reflected inside `<script>` | `';alert(3);//` |

The scanner **only generates payloads for contexts you select** in the UI.

---

## 🔎 Reflection Detection Method

Reflection detection uses simple but reliable logic:

1. Payload is injected into the URL or body.
2. Response HTML is fetched.
3. Scanner checks:
   ```python
   if payload in response.text:
       reflected = True

Instructions: 

1.python app.py
2.http://127.0.0.1:5000

sample input to fill the form:

1.Target URL: https://xss-game.appspot.com/level1/frame
2.Parameters: query=test
3.Method: GET
4.Contexts Selected: Text Node, Attribute Value
5.Threads: 10
6. click start scan
