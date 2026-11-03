from .formats import to_cyclonedx, to_json, to_markdown, to_sarif
from .html import to_html

FORMATTERS = {
    "json": to_json,
    "sarif": to_sarif,
    "markdown": to_markdown,
    "md": to_markdown,
    "html": to_html,
    "cyclonedx": to_cyclonedx,
    "sbom": to_cyclonedx,
}

EXTENSIONS = {".json": "json", ".sarif": "sarif", ".md": "markdown", ".html": "html", ".htm": "html"}
