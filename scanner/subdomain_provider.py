import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SubdomainResult:
    subdomains: List[str]
    error_code: Optional[str] = None


class SubdomainProvider:
    """Optional adapter for external subdomain enumeration tools."""

    def __init__(self, tool_name: str = "subfinder"):
        self.tool_name = tool_name

    def enumerate(self, domain: str, timeout_seconds: int = 60) -> SubdomainResult:
        if shutil.which(self.tool_name) is None:
            return SubdomainResult(subdomains=[], error_code="tool_missing")

        try:
            proc = subprocess.run(
                [self.tool_name, "-d", domain, "-silent", "-timeout", "30"],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )

            if proc.returncode != 0:
                return SubdomainResult(subdomains=[], error_code="tool_error")

            subs = [s.strip() for s in proc.stdout.splitlines() if s.strip()]
            return SubdomainResult(subdomains=subs)
        except subprocess.TimeoutExpired:
            return SubdomainResult(subdomains=[], error_code="timeout")
        except OSError:
            return SubdomainResult(subdomains=[], error_code="tool_error")
