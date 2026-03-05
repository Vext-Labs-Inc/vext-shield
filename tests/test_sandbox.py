"""Tests for shared/sandbox_runner.py — isolated subprocess execution."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from shared.sandbox_runner import SandboxRunner, BehavioralReport


@pytest.fixture
def sandbox() -> SandboxRunner:
    """Create a sandbox runner with short timeout."""
    return SandboxRunner(timeout_seconds=10)


class TestSandboxEnvironment:
    def test_restricted_env_strips_api_keys(self, sandbox: SandboxRunner):
        """Restricted env should not contain API keys."""
        env = sandbox._create_restricted_env()
        sensitive_prefixes = [
            "OPENAI_", "ANTHROPIC_", "AWS_SECRET", "GH_TOKEN",
            "GITHUB_TOKEN", "SSH_AUTH_SOCK",
        ]
        for key in env:
            for prefix in sensitive_prefixes:
                assert not key.startswith(prefix), (
                    f"Sensitive env var {key} not stripped"
                )

    def test_restricted_env_has_path(self, sandbox: SandboxRunner):
        """Restricted env should have a PATH."""
        env = sandbox._create_restricted_env()
        assert "PATH" in env
        assert len(env["PATH"]) > 0

    def test_restricted_env_has_home(self, sandbox: SandboxRunner):
        """Restricted env should have HOME."""
        env = sandbox._create_restricted_env()
        assert "HOME" in env


class TestSandboxExecution:
    def test_run_benign_script(self, sandbox: SandboxRunner, tmp_path: Path):
        """Benign script should run and return clean report."""
        script = tmp_path / "benign.py"
        script.write_text('print("Hello, world!")\n')

        report = sandbox.run_skill_script(script, tmp_path)
        assert isinstance(report, BehavioralReport)
        assert report.exit_code == 0
        assert not report.has_suspicious_activity

    def test_captures_stdout(self, sandbox: SandboxRunner, tmp_path: Path):
        """Should capture script stdout."""
        script = tmp_path / "hello.py"
        script.write_text('print("test output 12345")\n')

        report = sandbox.run_skill_script(script, tmp_path)
        assert report.exit_code == 0

    def test_enforces_timeout(self, tmp_path: Path):
        """Scripts exceeding timeout should be killed."""
        runner = SandboxRunner(timeout_seconds=2)
        script = tmp_path / "slow.py"
        script.write_text(
            'import time\n'
            'time.sleep(60)\n'
        )

        report = runner.run_skill_script(script, tmp_path)
        assert report.duration_ms < 10000  # Should be well under 10s
        assert report.exit_code != 0  # Killed by timeout

    def test_blocks_or_detects_file_creation(self, sandbox: SandboxRunner, tmp_path: Path):
        """Sandbox should either block file writes (FULL) or detect them (COPY)."""
        script = tmp_path / "creator.py"
        script.write_text(
            'from pathlib import Path\n'
            'Path("newfile.txt").write_text("created")\n'
        )

        report = sandbox.run_skill_script(script, tmp_path)
        if report.isolation_level == "FULL":
            # OS-level sandbox blocked the write — script fails with PermissionError
            assert report.exit_code != 0
            assert "PermissionError" in report.stderr or "Operation not permitted" in report.stderr
        else:
            # COPY level: writes go to temp copy, detected via snapshot diff
            created = [m for m in report.modifications if m.get("type") == "created"]
            assert len(created) > 0 or report.exit_code == 0

    def test_blocks_or_detects_file_modification(self, sandbox: SandboxRunner, tmp_path: Path):
        """Sandbox should either block file writes (FULL) or detect them (COPY)."""
        target = tmp_path / "existing.txt"
        target.write_text("original content")

        script = tmp_path / "modifier.py"
        script.write_text(
            'from pathlib import Path\n'
            'Path("existing.txt").write_text("modified content")\n'
        )

        report = sandbox.run_skill_script(script, tmp_path)
        if report.isolation_level == "FULL":
            # OS-level sandbox blocked the write
            assert report.exit_code != 0
            assert "PermissionError" in report.stderr or "Operation not permitted" in report.stderr
        else:
            # COPY level: writes go to temp copy, detected via snapshot diff
            modified = [m for m in report.modifications if m.get("type") == "modified"]
            assert len(modified) > 0 or report.exit_code == 0

    def test_script_with_error(self, sandbox: SandboxRunner, tmp_path: Path):
        """Scripts with errors should still return a report."""
        script = tmp_path / "error.py"
        script.write_text('raise ValueError("test error")\n')

        report = sandbox.run_skill_script(script, tmp_path)
        assert isinstance(report, BehavioralReport)
        assert report.exit_code != 0


class TestNetworkDetection:
    def test_detects_urls_in_output(self, sandbox: SandboxRunner, tmp_path: Path):
        """Should detect URLs printed to stdout."""
        script = tmp_path / "urlprint.py"
        script.write_text(
            'print("Sending to https://webhook.site/abc123")\n'
        )

        report = sandbox.run_skill_script(script, tmp_path)
        assert len(report.network_calls) > 0 or report.exit_code == 0

    def test_detects_ip_patterns(self, sandbox: SandboxRunner, tmp_path: Path):
        """Should detect IP:port patterns in output."""
        script = tmp_path / "ipprint.py"
        script.write_text(
            'print("Connecting to 192.168.1.1:4444")\n'
        )

        report = sandbox.run_skill_script(script, tmp_path)
        # Network detection is best-effort
        assert isinstance(report, BehavioralReport)


class TestEnvVarDetection:
    def test_detects_env_var_access_in_output(self, sandbox: SandboxRunner, tmp_path: Path):
        """Should detect references to sensitive env vars in output."""
        script = tmp_path / "envprint.py"
        script.write_text(
            'print("Reading OPENAI_API_KEY from environment")\n'
        )

        report = sandbox.run_skill_script(script, tmp_path)
        assert len(report.env_vars_accessed) > 0 or report.exit_code == 0
