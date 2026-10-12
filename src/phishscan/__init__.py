"""PhishScan - Rule-based email phishing detection and analysis engine."""

__version__ = "0.0.0"

from phishscan.models import AnalysisResult, Finding, ParsedEmail
from phishscan.parser import parse_eml
from phishscan.scoring import evaluate_email

__all__ = [
    "AnalysisResult",
    "Finding",
    "ParsedEmail",
    "parse_eml",
    "evaluate_email",
    "__version__",
]
