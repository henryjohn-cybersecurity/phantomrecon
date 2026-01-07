from weasyprint import HTML
import os


def export_html_to_pdf(html_path: str) -> str:
    if not os.path.exists(html_path):
        raise FileNotFoundError("HTML report not found")

    pdf_path = html_path.replace(".html", ".pdf")

    HTML(html_path).write_pdf(pdf_path)
    return pdf_path
