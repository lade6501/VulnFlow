"""
src/vulnflow/sandbox/runner.py
Executes builds, tests, and patches within isolated ephemeral environments.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger("vulnflow.sandbox.runner")


class SandboxExecutionError(RuntimeError):
    """Raised when an isolated checkout cannot be prepared safely."""


class SandboxRunner:
    """Executes builds and tests in disposable, branch-specific worktrees."""

    def __init__(self, default_timeout: float = 60.0) -> None:
        self.default_timeout = default_timeout

    @staticmethod
    def checkout_revision(checkout: Path) -> str | None:
        if not (checkout / ".git").exists():
            return None
        return subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=checkout, check=True, capture_output=True, text=True, timeout=10,
        ).stdout.strip()

    def run_command(
        self,
        command: List[str],
        cwd: Path,
        timeout: Optional[float] = None,
        env_overrides: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """Execute repository code in an offline container with a disposable checkout."""
        exec_timeout = timeout or self.default_timeout
        docker = shutil.which("docker")
        image = os.getenv("VULNFLOW_BUILD_SANDBOX_IMAGE", "").strip()
        if not docker or not image or image.startswith("-"):
            return 1, "", "Build isolation requires Docker and VULNFLOW_BUILD_SANDBOX_IMAGE"
        container_name = f"vulnflow-check-{uuid.uuid4().hex}"
        container_env = {"HOME": "/tmp", "NODE_ENV": "test", "CI": "true"}
        if env_overrides:
            container_env.update(env_overrides)
        invocation = [
            docker, "run", "--rm", "--name", container_name, "--pull=never",
            "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--memory=1g", "--pids-limit=256", "--cpus=2",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
            "--mount", f"type=bind,source={cwd},target=/workspace",
            "--workdir", "/workspace",
        ]
        for key, value in container_env.items():
            invocation.extend(["--env", f"{key}={value}"])
        invocation.extend(["--entrypoint", command[0], image, *command[1:]])

        try:
            start_t = time.time()
            proc = subprocess.run(
                invocation,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=exec_timeout,
            )
            duration = time.time() - start_t
            logger.debug("Command %s finished in %.2fs (exit: %d)", command, duration, proc.returncode)
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            logger.warning("Command %s timed out after %ds", command, exec_timeout)
            try:
                subprocess.run(
                    [docker, "rm", "--force", container_name],
                    capture_output=True, timeout=5, check=False,
                )
            except (OSError, subprocess.SubprocessError):
                logger.warning("Could not stop timed-out build container %s", container_name)
            return -1, "", f"Command timed out after {exec_timeout} seconds"
        except Exception as exc:
            logger.error("Command %s execution error: %s", command, exc)
            return 1, "", str(exc)

    @contextmanager
    def isolated_checkout(
        self, repo_dir: Path, branch: str | None = None
    ) -> Iterator[Path]:
        """Create a disposable checkout without mutating the caller's working tree."""
        repo_dir = repo_dir.resolve()
        with tempfile.TemporaryDirectory(prefix="vulnflow-worktree-") as tmp_dir:
            checkout = Path(tmp_dir) / "checkout"
            is_git_repo = (repo_dir / ".git").exists()

            if is_git_repo:
                revision = branch or "HEAD"
                verify = subprocess.run(
                    ["git", "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}"],
                    cwd=str(repo_dir),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if verify.returncode != 0:
                    raise SandboxExecutionError(
                        f"Cannot verify remediation revision '{revision}': "
                        f"{verify.stderr.strip()}"
                    )
                add = subprocess.run(
                    [
                        "git", "-c", "core.hooksPath=/dev/null", "worktree", "add",
                        "--detach", str(checkout), verify.stdout.strip(),
                    ],
                    cwd=str(repo_dir),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if add.returncode != 0:
                    raise SandboxExecutionError(
                        f"Could not create isolated worktree: {add.stderr.strip()}"
                    )
            else:
                if branch:
                    raise SandboxExecutionError("A branch requires a Git checkout")
                shutil.copytree(
                    repo_dir,
                    checkout,
                    symlinks=True,
                    ignore=shutil.ignore_patterns(
                        ".git", ".vulnflow", "node_modules", ".venv", "dist", "build"
                    ),
                )

            try:
                yield checkout
            finally:
                if is_git_repo and checkout.exists():
                    subprocess.run(
                        ["git", "worktree", "remove", "--force", str(checkout)],
                        cwd=str(repo_dir),
                        capture_output=True,
                        check=False,
                    )
                    subprocess.run(
                        ["git", "worktree", "prune"],
                        cwd=str(repo_dir),
                        capture_output=True,
                        check=False,
                    )

    @staticmethod
    def _failure(message: str, *, status: str = "failed") -> Dict[str, Any]:
        return {
            "status": status,
            "build_clean": False,
            "passed": False,
            "verification_available": False,
            "tests_total": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "exit_code": 1,
            "output": message,
        }

    def npm_offline(self, checkout: Path, *args: str, timeout: float | None = None) -> Tuple[int, str, str]:
        return self.run_command(
            [
                "sh", "-ec",
                'if [ -d /opt/npm-cache ]; then cp -R /opt/npm-cache /tmp/.npm; fi; exec npm "$@"',
                "vulnflow-npm", *args,
            ],
            checkout, timeout=timeout,
        )

    def _execute_npm(self, checkout: Path, timeout: float | None) -> Dict[str, Any]:
        pkg_path = checkout / "package.json"
        if not pkg_path.exists():
            return self._failure("package.json not found in isolated checkout")
        try:
            package_data = json.loads(pkg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return self._failure(f"Invalid package.json: {exc}")

        scripts = package_data.get("scripts", {})
        commands: list[list[str]] = []
        if isinstance(scripts, dict) and scripts.get("build"):
            commands.append(["npm", "run", "build"])
        if isinstance(scripts, dict) and scripts.get("test"):
            commands.append(["npm", "test"])
        if not isinstance(scripts, dict) or not scripts.get("test"):
            return self._failure(
                "No npm test script is defined. Remediation is unverified.",
                status="unverified",
            )

        has_dependencies = any(
            package_data.get(section)
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
        )
        if has_dependencies:
            if not any((checkout / name).is_file() for name in ("package-lock.json", "npm-shrinkwrap.json")):
                return self._failure("A committed npm lockfile is required for dependency verification")
            code, stdout, stderr = self.npm_offline(
                checkout, "ci", "--offline", "--ignore-scripts", timeout=timeout,
            )
            if code != 0:
                return self._failure(f"Locked dependency installation failed: {stdout}{stderr}")
        outputs: list[str] = []
        for command in commands:
            code, stdout, stderr = self.run_command(command, checkout, timeout=timeout)
            outputs.append((stdout or "") + (stderr or ""))
            if code != 0:
                return {
                    **self._failure("\n".join(outputs)),
                    "verification_available": True,
                    "tests_total": len(commands),
                    "tests_failed": 1,
                    "exit_code": code,
                }
        return {
            "status": "success",
            "build_clean": True,
            "passed": True,
            "verification_available": True,
            "tests_total": len(commands),
            "tests_passed": len(commands),
            "tests_failed": 0,
            "exit_code": 0,
            "output": "\n".join(outputs),
        }

    def _execute_python(self, checkout: Path, timeout: float | None) -> Dict[str, Any]:
        test_roots = [checkout / "tests", checkout / "test"]
        if any(path.exists() for path in test_roots):
            code, stdout, stderr = self.run_command(
                ["python", "-m", "pytest", "-q"], checkout, timeout=timeout
            )
            return {
                "status": "success" if code == 0 else "failed",
                "build_clean": code == 0,
                "passed": code == 0,
                "verification_available": True,
                "tests_total": 1,
                "tests_passed": 1 if code == 0 else 0,
                "tests_failed": 0 if code == 0 else 1,
                "exit_code": code,
                "output": (stdout or "") + (stderr or ""),
            }
        return self._failure(
            "No Python test suite was found; remediation is unverified.",
            status="unverified",
        )

    def _execute_maven(self, checkout: Path, timeout: float | None) -> Dict[str, Any]:
        if not (checkout / "pom.xml").exists():
            return self._failure("pom.xml not found in isolated checkout")
        code, stdout, stderr = self.run_command(
            ["mvn", "test", "--offline", "--batch-mode", "-DfailIfNoTests=true"],
            checkout, timeout=timeout, env_overrides={"MAVEN_OPTS": "-Dmaven.repo.local=/opt/maven-repo"},
        )
        return {
            "status": "success" if code == 0 else "failed",
            "build_clean": code == 0,
            "passed": code == 0,
            "verification_available": True,
            "tests_total": 1,
            "tests_passed": 1 if code == 0 else 0,
            "tests_failed": 0 if code == 0 else 1,
            "exit_code": code,
            "output": (stdout or "") + (stderr or ""),
        }

    def execute_build_and_test(
        self,
        repo_dir: Path,
        ecosystem: str = "npm",
        timeout: Optional[float] = None,
        branch: str | None = None,
    ) -> Dict[str, Any]:
        """Execute the repository's real checks in an isolated branch checkout."""
        start_time = time.time()
        revision = None
        try:
            with self.isolated_checkout(repo_dir, branch=branch) as checkout:
                revision = self.checkout_revision(checkout)
                normalized = ecosystem.lower()
                if normalized == "npm":
                    result = self._execute_npm(checkout, timeout)
                elif normalized in {"pip", "pypi", "python"}:
                    result = self._execute_python(checkout, timeout)
                elif normalized == "maven":
                    result = self._execute_maven(checkout, timeout)
                else:
                    result = self._failure(
                        f"Unsupported ecosystem '{ecosystem}'; verification cannot run"
                    )
        except (OSError, SandboxExecutionError, subprocess.SubprocessError) as exc:
            result = self._failure(str(exc))

        result["duration_seconds"] = round(time.time() - start_time, 2)
        result["branch"] = branch or "HEAD"
        result["revision"] = revision
        result["isolated"] = True
        return result


# Shared default runner
default_sandbox = SandboxRunner()
