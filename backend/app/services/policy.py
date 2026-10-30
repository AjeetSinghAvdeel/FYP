from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from urllib.parse import urlparse


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    tool: str


class PolicyEngine:
    @staticmethod
    def target_is_allowed(target_url: str) -> tuple[bool, str]:
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False, "Targets must use an HTTP(S) URL with a hostname."
        if parsed.username or parsed.password:
            return False, "Target URLs must not contain credentials."
        if os.getenv("ALLOW_PUBLIC_TARGETS", "false").lower() == "true":
            return True, "Public target override is enabled by explicit operator configuration."
        hostname = parsed.hostname.lower().rstrip(".")
        if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".local"):
            return True, "Local lab target accepted."
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return False, "Only localhost, .local hostnames, or private IP targets are allowed by default."
        if address.is_private or address.is_loopback or address.is_link_local:
            return True, "Private or loopback target accepted."
        return False, "Public targets require explicit ALLOW_PUBLIC_TARGETS=true configuration."

    @staticmethod
    def check_tool(target_scope: str, allowed_tools: str, tool_name: str) -> PolicyDecision:
        scope_ok = target_scope.lower() in {"allowlisted", "authorized", "in-scope"}
        if not scope_ok:
            return PolicyDecision(False, "Target scope is not allowlisted or authorized for testing.", tool_name)
        allowed = [item.strip().lower() for item in allowed_tools.split(",") if item.strip()]
        if tool_name.lower() not in allowed:
            return PolicyDecision(False, f"{tool_name} is not in the approved tools list for this target.", tool_name)
        return PolicyDecision(True, "Authorized testing action passes policy controls.", tool_name)
