"""PhishScan check modules."""

from phishscan.checks.attachments import check_attachments
from phishscan.checks.body import check_body
from phishscan.checks.headers import check_headers
from phishscan.checks.links import check_links

__all__ = [
    "check_headers",
    "check_body",
    "check_links",
    "check_attachments",
]
