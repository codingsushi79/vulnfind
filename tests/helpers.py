import os
import tempfile

from vulnfind.walker import SourceFile


def source(name: str, text: str) -> SourceFile:
    """A SourceFile backed by in-memory text (rel path = name)."""
    f = SourceFile(path=os.path.join("/nonexistent", name), rel=name, size=len(text))
    f._text = text
    f._binary = False
    return f


def ids(findings):
    return sorted({f.rule_id for f in findings})


class TempProject:
    def __init__(self, files):
        self.files = files

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        for rel, content in self.files.items():
            path = os.path.join(self.tmp.name, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        return self.tmp.name

    def __exit__(self, *exc):
        self.tmp.cleanup()
