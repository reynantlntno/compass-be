import re
from urllib.parse import urlsplit


class RecoveryQueryRedactionFilter:
    """Remove bearer query strings from repository-controlled log records."""

    def filter(self, record):
        requestline = getattr(record, "requestline", "")
        if requestline:
            parts = requestline.split(" ", 2)
            if len(parts) == 3:
                path = urlsplit(parts[1]).path or "/"
                record.requestline = f"{parts[0]} {path} {parts[2]}"
        # Django's default server message is formatted from ``msg``/``args``;
        # replace that rendered value as well so the query cannot reappear.
        try:
            rendered = record.getMessage()
            if "?" in rendered:
                rendered = re.sub(r"\?[^\s]*", "", rendered)
            record.msg = rendered
            record.args = ()
        except Exception:
            pass
        return True
