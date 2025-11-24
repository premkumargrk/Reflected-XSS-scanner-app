# Helper functions for reports (export HTML, save logs, etc.)

def save_html_report(results, filename="report.html"):
    with open(filename, "w") as f:
        f.write("<html><body><h1>XSS Report</h1>")
        for r in results:
            f.write(f"<p>{r}</p>")
        f.write("</body></html>")
