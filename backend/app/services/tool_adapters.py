from __future__ import annotations

import shutil
import subprocess
import os
import time
from typing import Any
from urllib.parse import urlparse
from pathlib import Path
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import re
import httpx
from app.services.policy import PolicyEngine

DEFAULT_WORDLIST = str(Path(__file__).resolve().parents[2] / "data" / "wordlist.txt")


class ToolAdapter:
    name: str
    install_hint: str

    def __init__(self, tool_name: str, install_hint: str):
        self.name = tool_name
        self.install_hint = install_hint

    def is_available(self) -> bool:
        return self.resolve_executable() is not None

    def resolve_executable(self) -> str | None:
        configured = os.getenv(f"{self.name.upper()}_PATH")
        if configured and os.path.isfile(configured) and os.access(configured, os.X_OK):
            return configured
        return shutil.which(self.name)

    def check_version(self) -> str:
        if not self.is_available():
            return "missing"
        executable = self.resolve_executable()
        if not executable:
            return "missing"
        result = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False, timeout=5)
        stdout = (result.stdout or "").strip() or (result.stderr or "").strip()
        return stdout.splitlines()[0] if stdout else "available"

    def execute(self, target: str, extra_args: list[str] | None = None, timeout: int = 30) -> dict[str, Any]:
        allowed, reason = PolicyEngine.target_is_allowed(target)
        if not allowed:
            return {"tool": self.name, "status": "blocked", "installed": self.is_available(), "target": target, "message": reason, "stderr": ""}
        validation_error = self.validate_inputs(target, extra_args or [])
        if validation_error:
            return {"tool": self.name, "status": "invalid", "installed": self.is_available(), "target": target, "message": validation_error}
        if os.getenv("PENTEST_EXECUTION_MODE", "mock").lower() == "mock":
            return self._mock_result(target)
        executable = self.resolve_executable()
        if not executable:
            return {
                "tool": self.name,
                "status": "missing",
                "message": f"{self.name} is not installed. {self.install_hint}",
                "installed": False,
            }
        args = self.build_command(target, extra_args or [])
        args[0] = executable
        started_at = datetime.utcnow()
        started_clock = time.perf_counter()
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {
                "tool": self.name,
                "status": "timeout",
                "installed": True,
                "target": target,
                "message": f"{self.name} exceeded the {timeout}s execution timeout.",
                "started_at": started_at.isoformat(),
                "finished_at": datetime.utcnow().isoformat(),
                "duration_ms": int((time.perf_counter() - started_clock) * 1000),
                "request_budget": self.request_budget(),
                "command_args": args[1:],
            }
        duration_ms = int((time.perf_counter() - started_clock) * 1000)
        raw_output = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        observations = self.parse_output(raw_output)
        return {
            "tool": self.name,
            "status": "ok" if result.returncode == 0 else "error",
            "installed": True,
            "return_code": result.returncode,
            "output": raw_output,
            "stderr": stderr,
            "observations": observations,
            "requests_made": self.actual_request_count(raw_output, observations),
            "target": target,
            "started_at": started_at.isoformat(),
            "finished_at": datetime.utcnow().isoformat(),
            "duration_ms": duration_ms,
            "request_budget": self.request_budget(),
            "command_args": args[1:],
        }

    def request_budget(self) -> int | None:
        return None

    def actual_request_count(self, output: str, observations: list[dict[str, Any]]) -> int | None:
        return None

    def build_command(self, target: str, extra_args: list[str]) -> list[str]:
        return [self.name, *extra_args, target]

    def parse_output(self, output: str) -> list[dict[str, Any]]:
        return [{"type": "output_line", "value": line.strip()} for line in output.splitlines() if line.strip()]

    @staticmethod
    def validate_inputs(target: str, extra_args: list[str]) -> str | None:
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return "Target must be an HTTP(S) URL with a hostname."
        if any(ord(char) < 32 for char in target):
            return "Target contains control characters."
        blocked_tokens = (";", "|", "&", "$", "`", "\n", "\r")
        if any(any(token in argument for token in blocked_tokens) for argument in extra_args):
            return "Tool arguments contain shell metacharacters."
        if any(argument in {"--script", "--exec", "--command"} for argument in extra_args):
            return "Script and command execution arguments are prohibited."
        return None

    def _mock_result(self, target: str) -> dict[str, Any]:
        return {
            "tool": self.name,
            "status": "ok",
            "installed": False,
            "mode": "mock",
            "return_code": 0,
            "output": f"MOCK {self.name} observation for authorized target {target}: HTTP service on port 443; /health endpoint found.",
            "stderr": "",
            "target": target,
        }


class NmapAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__("nmap", "Install Nmap: brew install nmap or apt-get install nmap")

    def build_command(self, target: str, extra_args: list[str]) -> list[str]:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return [self.name, "-n", "-Pn", "-sV", "--version-light", "--max-retries", "1", "--host-timeout", "30s", "-p", str(port), "-oX", "-", host]

    def parse_output(self, output: str) -> list[dict[str, Any]]:
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return super().parse_output(output)
        observations = []
        for host in root.findall("host"):
            address = host.find("address")
            address_value = address.get("addr") if address is not None else None
            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                service_name = service.get("name") if service is not None else None
                fingerprint = service.get("servicefp", "") if service is not None else ""
                if service_name == "ppp" and "HTTP/1" in fingerprint:
                    service_name = "http"
                observations.append({
                    "type": "service",
                    "address": address_value,
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol"),
                    "state": state.get("state") if state is not None else "unknown",
                    "name": service_name,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                })
        return observations

    def request_budget(self) -> int:
        return 1

    def check_version(self) -> str:
        executable = self.resolve_executable()
        if not executable:
            return "missing"
        result = subprocess.run([executable, "--version"], capture_output=True, text=True, check=False, timeout=10)
        output = result.stdout or result.stderr
        return output.splitlines()[0] if output else "available"


class FFUFAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__("ffuf", "Install FFUF: go install github.com/ffuf/ffuf@latest")

    def build_command(self, target: str, extra_args: list[str]) -> list[str]:
        return [self.name, "-u", f"{target.rstrip('/')}/FUZZ", "-w", os.getenv("FFUF_WORDLIST", DEFAULT_WORDLIST), "-mc", "200,204,301,302,307,401,403", "-t", "5", "-rate", "5", "-maxtime", "30", "-noninteractive", "-s", "-of", "json", "-o", "/dev/stdout", *extra_args]

    def execute(self, target: str, extra_args: list[str] | None = None, timeout: int = 35) -> dict[str, Any]:
        allowed, reason = PolicyEngine.target_is_allowed(target)
        if not allowed:
            return {"tool": self.name, "status": "blocked", "installed": self.is_available(), "target": target, "message": reason, "stderr": ""}
        if os.getenv("PENTEST_EXECUTION_MODE", "mock").lower() != "real":
            return super().execute(target, extra_args, timeout)
        if not self.resolve_executable():
            return super().execute(target, extra_args, timeout)
        try:
            response = httpx.get(target, timeout=3, follow_redirects=False)
            if 300 <= response.status_code < 400:
                return {"tool": self.name, "status": "blocked", "installed": True, "target": target, "message": "FFUF preflight refused an out-of-scope redirect.", "stderr": ""}
            wildcard_length = len(response.content)
        except httpx.HTTPError as error:
            return {"tool": self.name, "status": "error", "installed": True, "target": target, "message": f"FFUF preflight failed: {error}", "stderr": str(error)}
        result = super().execute(target, [*(extra_args or []), "-fs", str(wildcard_length)], timeout)
        result["request_budget"] = (result.get("request_budget") or 0) + 1
        result["preflight"] = {"status_code": response.status_code, "wildcard_length": wildcard_length, "redirect_followed": False}
        result.setdefault("observations", []).append({"type": "wildcard_preflight", **result["preflight"]})
        if result.get("status") == "ok":
            result["requests_made"] = None
        return result

    def parse_output(self, output: str) -> list[dict[str, Any]]:
        for marker in ('{"commandline"', '{"results"'):
            start = output.find(marker)
            if start >= 0:
                try:
                    data = json.loads(output[start:])
                    return [{"type": "path", "url": item.get("url"), "status": item.get("status"), "length": item.get("length"), "words": item.get("words")} for item in data.get("results", [])]
                except (json.JSONDecodeError, AttributeError):
                    break
        return super().parse_output(output)

    def request_budget(self) -> int | None:
        try:
            with open(os.getenv("FFUF_WORDLIST", DEFAULT_WORDLIST), encoding="utf-8") as wordlist:
                return sum(1 for line in wordlist if line.strip())
        except OSError:
            return None


class GobusterAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__("gobuster", "Install Gobuster: go install github.com/OJ/gobuster@latest")

    def build_command(self, target: str, extra_args: list[str]) -> list[str]:
        return [self.name, "dir", "-u", target, "-w", os.getenv("GOBUSTER_WORDLIST", DEFAULT_WORDLIST), "-q", "-t", "5", "--delay", "200ms", "--timeout", "10s", *extra_args]

    def execute(self, target: str, extra_args: list[str] | None = None, timeout: int = 30) -> dict[str, Any]:
        allowed, reason = PolicyEngine.target_is_allowed(target)
        if not allowed:
            return {"tool": self.name, "status": "blocked", "installed": self.is_available(), "target": target, "message": reason, "stderr": ""}
        if os.getenv("PENTEST_EXECUTION_MODE", "mock").lower() != "real":
            return super().execute(target, extra_args, timeout)
        if not self.resolve_executable():
            return super().execute(target, extra_args, timeout)
        try:
            response = httpx.get(target, timeout=3, follow_redirects=False)
            if 300 <= response.status_code < 400:
                return {"tool": self.name, "status": "blocked", "installed": True, "target": target, "message": "Gobuster preflight refused an out-of-scope redirect.", "stderr": ""}
            wildcard_length = len(response.content)
        except httpx.HTTPError as error:
            return {"tool": self.name, "status": "error", "installed": True, "target": target, "message": f"Gobuster preflight failed: {error}", "stderr": str(error)}
        command_args = [*(extra_args or []), "--exclude-length", str(wildcard_length)]
        result = super().execute(target, command_args, timeout)
        result["request_budget"] = (result.get("request_budget") or 0) + 1
        result["preflight"] = {"status_code": response.status_code, "wildcard_length": wildcard_length, "redirect_followed": False}
        result.setdefault("observations", []).append({"type": "wildcard_preflight", **result["preflight"]})
        return result

    def parse_output(self, output: str) -> list[dict[str, Any]]:
        observations = []
        for line in output.splitlines():
            value = line.strip()
            if not value:
                continue
            observations.append({"type": "path", "value": value})
        return observations

    def request_budget(self) -> int | None:
        try:
            with open(os.getenv("GOBUSTER_WORDLIST", DEFAULT_WORDLIST), encoding="utf-8") as wordlist:
                return sum(1 for line in wordlist if line.strip())
        except OSError:
            return None

    def actual_request_count(self, output: str, observations: list[dict[str, Any]]) -> int | None:
        return None


class NiktoAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__("nikto", "Install Nikto: apt-get install nikto or use a containerized deployment")

    def build_command(self, target: str, extra_args: list[str]) -> list[str]:
        return [self.name, "-h", target, "-nointeractive", "-nocheck", "-Plugins", "headers", "-maxtime", "25s", "-timeout", "5", "-Pause", "0.1", *extra_args]

    def request_budget(self) -> int:
        return 250

    def parse_output(self, output: str) -> list[dict[str, Any]]:
        observations = [{"type": "potential_server_issue", "value": line.strip().lstrip("+").strip()} for line in output.splitlines() if line.strip().startswith("+")]
        count = re.search(r"(\d+) requests:\s+(\d+) errors and (\d+) items reported", output)
        if count:
            observations.append({"type": "request_summary", "requests_made": int(count.group(1)), "errors": int(count.group(2)), "reported_items": int(count.group(3))})
        return observations

    def actual_request_count(self, output: str, observations: list[dict[str, Any]]) -> int | None:
        return next((int(item["requests_made"]) for item in observations if item.get("type") == "request_summary"), None)

    def check_version(self) -> str:
        executable = self.resolve_executable()
        if not executable:
            return "missing"
        result = subprocess.run([executable, "-Version"], capture_output=True, text=True, check=False, timeout=5)
        output = (result.stdout or result.stderr or "").strip()
        return output.splitlines()[0] if output else "available"
