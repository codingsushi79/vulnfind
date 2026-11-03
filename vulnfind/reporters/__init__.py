from .formats import to_csv, to_cyclonedx, to_github, to_json, to_junit, to_markdown, to_sarif
from .html import to_html

FORMATTERS = {
    "json": to_json,
    "sarif": to_sarif,
    "markdown": to_markdown,
    "md": to_markdown,
    "html": to_html,
    "cyclonedx": to_cyclonedx,
    "sbom": to_cyclonedx,
    "github": to_github,
    "junit": to_junit,
    "csv": to_csv,
}

EXTENSIONS = {".json": "json", ".sarif": "sarif", ".md": "markdown", ".html": "html", ".htm": "html",
              ".xml": "junit", ".csv": "csv"}


def format_for_path(path: str):
    low = path.lower()
    if low.endswith((".cdx.json", "sbom.json", ".cdx")):
        return "sbom"
    import os
    return EXTENSIONS.get(os.path.splitext(low)[1])
