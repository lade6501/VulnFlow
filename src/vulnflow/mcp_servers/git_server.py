"""
src/vulnflow/mcp_servers/git_server.py
MCP tool server executing git operations, branch creation, commits, and PRs.
"""

from __future__ import annotations

import difflib
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

from vulnflow.mcp_servers.external import github_mcp_bridge
from vulnflow.mcp_servers.fastmcp import FastMCP

logger = logging.getLogger("vulnflow.mcp_servers.git")

# Initialize formal FastMCP server instance
mcp = FastMCP(
    name="vulnflow-git",
    description="MCP server executing isolated repository operations, branch creation, commits, and PR creation.",
)


class GitServer:
    """Tool server executing repository operations, branch creation, and PR management over MCP."""

    def __init__(self) -> None:
        self._open_prs: Dict[tuple[str, str, str], Dict[str, Any]] = {}
        self.mcp = mcp

    def _extract_repo_name(self, repo_dir: Optional[str] = None) -> str | None:
        """Extract the GitHub repository from the effective push URL."""
        if not repo_dir:
            return None
        repo_path = Path(repo_dir)
        if (repo_path / ".git").exists():
            try:
                res = subprocess.run(
                    ["git", "remote", "get-url", "--push", "--all", "origin"],
                    cwd=str(repo_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                url = res.stdout.strip()
                if url:
                    m = re.fullmatch(
                        r"(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)"
                        r"([\w-]+)/([\w.-]+?)(?:\.git)?/?",
                        url,
                        flags=re.ASCII,
                    )
                    if m:
                        return f"{m.group(1)}/{m.group(2)}"
            except Exception as exc:
                logger.debug("Could not read git remote in %s: %s", repo_dir, exc)
        return None

    def git_clone(self, repo_url: str, target_dir: str) -> Dict[str, Any]:
        """MCP tool: git_clone - Clones repo into target directory."""
        logger.info("Cloning %s into %s", repo_url, target_dir)
        target = Path(target_dir)
        if target.exists() and any(target.iterdir()):
            return {
                "status": "failed",
                "path": target_dir,
                "error": "Clone target already exists and is not empty",
            }
        result = subprocess.run(
            ["git", "clone", "--", repo_url, target_dir],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return {
                "status": "failed",
                "path": target_dir,
                "error": result.stderr.strip(),
            }
        return {"status": "cloned", "path": target_dir, "ref": "HEAD"}

    def git_branch(
        self, branch_name: str, repo_dir: str, base_branch: Optional[str] = None,
        *, replace_existing: bool = False,
    ) -> Dict[str, Any]:
        """MCP tool: git_branch - Creates or switches to remediation branch on disk."""
        logger.info("Creating branch %s in %s", branch_name, repo_dir)
        repo_path = Path(repo_dir)
        if (repo_path / ".git").exists():
            try:
                cmd = ["git", "-c", "core.hooksPath=/dev/null", "checkout", "-B" if replace_existing else "-b", branch_name]
                if base_branch:
                    cmd.append(base_branch)
                result = subprocess.run(
                    cmd,
                    cwd=str(repo_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if result.returncode != 0:
                    return {
                        "status": "failed",
                        "branch": branch_name,
                        "error": result.stderr.decode(errors="replace").strip(),
                    }
            except Exception as exc:
                logger.warning("Could not create branch %s in %s: %s", branch_name, repo_dir, exc)
                return {"status": "failed", "branch": branch_name, "error": str(exc)}
            return {"status": "created", "branch": branch_name}
        return {
            "status": "failed",
            "branch": branch_name,
            "error": "Repository is not a git checkout",
        }

    def git_checkout(self, branch_name: str, repo_dir: str) -> Dict[str, Any]:
        """Switch working tree back to specified branch."""
        repo_path = Path(repo_dir)
        if (repo_path / ".git").exists():
            try:
                result = subprocess.run(
                    ["git", "-c", "core.hooksPath=/dev/null", "checkout", branch_name],
                    cwd=str(repo_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                if result.returncode != 0:
                    return {
                        "status": "failed",
                        "branch": branch_name,
                        "error": result.stderr.decode(errors="replace").strip(),
                    }
            except Exception as exc:
                logger.warning("Could not checkout %s in %s: %s", branch_name, repo_dir, exc)
                return {"status": "failed", "branch": branch_name, "error": str(exc)}
            return {"status": "checked_out", "branch": branch_name}
        return {
            "status": "failed",
            "branch": branch_name,
            "error": "Repository is not a git checkout",
        }

    def git_has_branch(self, branch_name: str, repo_dir: str) -> bool:
        """Check if branch exists in the repository."""
        repo_path = Path(repo_dir)
        if (repo_path / ".git").exists():
            try:
                res = subprocess.run(
                    ["git", "branch", "--list", branch_name],
                    cwd=str(repo_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                return bool(res.stdout.strip())
            except Exception:
                pass
        return False

    def git_cleanup_branch(
        self, branch_name: str, repo_dir: str, force: bool = True
    ) -> Dict[str, Any]:
        """
        MCP tool: git_cleanup_branch - Cleans up an orphan branch after failure or cancellation.
        Safely switches to default branch and deletes branch_name.
        """
        logger.info("Cleaning up orphan branch %s in %s", branch_name, repo_dir)
        repo_path = Path(repo_dir)
        deleted = False
        if (repo_path / ".git").exists():
            try:
                current = subprocess.run(
                    ["git", "branch", "--show-current"], cwd=repo_path,
                    capture_output=True, text=True, check=True,
                ).stdout.strip()
                if current == branch_name:
                    for fallback in ("main", "master"):
                        res = self.git_checkout(fallback, str(repo_path))
                        if res.get("status") == "checked_out":
                            break
                # 2. Delete branch
                del_cmd = ["git", "branch", "-D" if force else "-d", branch_name]
                del_res = subprocess.run(
                    del_cmd,
                    cwd=str(repo_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                deleted = del_res.returncode == 0
            except Exception as exc:
                logger.warning("Error deleting branch %s: %s", branch_name, exc)
        return {"status": "deleted" if deleted else "not_found", "branch": branch_name}

    def git_patch(self, file_path: str, diff: str, repo_dir: str) -> Dict[str, Any]:
        """Record an already-applied adapter change only when git can observe it."""
        logger.info("Validating patch to %s in %s", file_path, repo_dir)
        repo_path = Path(repo_dir)
        if not (repo_path / ".git").exists():
            return {
                "status": "failed",
                "file": file_path,
                "error": "Repository is not a git checkout",
            }
        result = subprocess.run(
            ["git", "diff", "--", file_path],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return {
                "status": "failed",
                "file": file_path,
                "error": result.stderr.strip(),
            }
        if not result.stdout.strip():
            return {
                "status": "noop",
                "file": file_path,
                "error": "No working-tree change was detected",
            }
        return {"status": "applied", "file": file_path, "hunks": diff.count("@@") or 1}

    def git_commit(self, message: str, repo_dir: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """MCP tool: git_commit - Commits staged changes on disk."""
        logger.info("Committing in %s with message: %s", repo_dir, message)
        repo_path = Path(repo_dir)
        commit_sha: str | None = None
        if (repo_path / ".git").exists():
            try:
                add_args = ["--", file_path] if file_path else ["-u"]
                subprocess.run(
                    ["git", "add", *add_args], cwd=repo_path,
                    capture_output=True, text=True, check=True,
                )
                env = os.environ.copy()
                env.setdefault("GIT_AUTHOR_NAME", "VulnFlow Bot")
                env.setdefault("GIT_AUTHOR_EMAIL", "bot@vulnflow.dev")
                env.setdefault("GIT_COMMITTER_NAME", "VulnFlow Bot")
                env.setdefault("GIT_COMMITTER_EMAIL", "bot@vulnflow.dev")
                commit_result = subprocess.run(
                    ["git", "-c", "core.hooksPath=/dev/null", "commit", "-m", message],
                    cwd=str(repo_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    text=True,
                    check=False,
                )
                if commit_result.returncode != 0:
                    return {
                        "status": "failed",
                        "commit_sha": None,
                        "error": commit_result.stderr.strip()
                        or commit_result.stdout.strip(),
                    }
                rev_res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(repo_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if rev_res.returncode == 0 and rev_res.stdout.strip():
                    commit_sha = rev_res.stdout.strip()
            except Exception as exc:
                logger.warning("Could not execute git commit in %s: %s", repo_dir, exc)
                return {"status": "failed", "commit_sha": None, "error": str(exc)}
            if not commit_sha:
                return {
                    "status": "failed",
                    "commit_sha": None,
                    "error": "Commit completed without a verifiable revision",
                }
            return {"status": "committed", "commit_sha": commit_sha}
        return {
            "status": "failed",
            "commit_sha": None,
            "error": "Repository is not a git checkout",
        }

    def git_replace_text(
        self,
        repo_dir: str,
        branch: str,
        file_path: str,
        old_text: str,
        new_text: str,
        commit_message: str,
    ) -> Dict[str, Any]:
        """Apply one exact source replacement on a checked-out remediation branch."""
        repo_path = Path(repo_dir).resolve()
        target = repo_path / file_path
        if Path(file_path).is_absolute() or not target.resolve().is_relative_to(repo_path):
            return {
                "status": "failed",
                "file": file_path,
                "error": "Target path escapes the repository or is a symlink",
            }
        if not (repo_path / ".git").exists():
            return {
                "status": "failed",
                "file": file_path,
                "error": "Repository or target file does not exist",
            }
        current = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=False,
        )
        current_branch = current.stdout.strip() if current.returncode == 0 else ""
        if branch and current_branch != branch:
            checkout = self.git_checkout(branch, str(repo_path))
            if checkout.get("status") != "checked_out":
                return {"status": "failed", "file": file_path, "error": checkout.get("error")}
        try:
            if target != target.resolve() or not target.is_file():
                return {"status": "failed", "file": file_path, "error": "Target is not a regular repository file"}
            content = target.read_text(encoding="utf-8")
            if not old_text or old_text == new_text or content.count(old_text) != 1:
                return {
                    "status": "failed",
                    "file": file_path,
                    "error": "Expected source text was not found exactly once",
                }
            new_content = content.replace(old_text, new_text, 1)
            target.write_text(new_content, encoding="utf-8")
            diff = "".join(
                difflib.unified_diff(
                    content.splitlines(keepends=True),
                    new_content.splitlines(keepends=True),
                    fromfile=f"a/{file_path}",
                    tofile=f"b/{file_path}",
                )
            )
            commit = self.git_commit(commit_message, str(repo_path), file_path=file_path)
            if commit.get("status") != "committed":
                return {
                    "status": "failed",
                    "file": file_path,
                    "error": commit.get("error"),
                }
            return {
                "status": "applied",
                "file": file_path,
                "diff": diff,
                "commit_sha": commit.get("commit_sha"),
            }
        except OSError as exc:
            return {"status": "failed", "file": file_path, "error": str(exc)}
        finally:
            if current_branch and current_branch != branch:
                self.git_checkout(current_branch, str(repo_path))

    def pr_create(
        self,
        branch: str,
        body: str,
        title: Optional[str] = None,
        repo_dir: Optional[str] = None,
        expected_revision: str | None = None,
    ) -> Dict[str, Any]:
        """
        MCP tool: pr_create - Opens pull request targeting the concerned repository.
        Guarantees idempotency: reruns on the same branch do not duplicate PRs.
        """
        repo_slug = self._extract_repo_name(repo_dir)

        if not repo_dir or not (Path(repo_dir) / ".git").exists():
            return {
                "status": "preview",
                "branch": branch,
                "repo": repo_slug,
                "title": title or f"fix(deps): automated remediation on {branch}",
                "body": body,
                "pr_url": None,
                "error": "A real git repository is required to create a pull request",
            }
        if not github_mcp_bridge.token:
            return {
                "status": "preview",
                "branch": branch,
                "repo": repo_slug,
                "title": title or f"fix(deps): automated remediation on {branch}",
                "body": body,
                "pr_url": None,
                "error": "GitHub credentials are not configured",
            }
        if not repo_slug:
            return {"status": "failed", "branch": branch, "error": "Expected one GitHub origin push URL"}

        repo_path = Path(repo_dir)
        try:
            ref = f"refs/heads/{branch}"
            revision = subprocess.run(
                ["git", "rev-parse", "--verify", "--end-of-options", ref],
                cwd=repo_path, capture_output=True, text=True, check=True,
            ).stdout.strip()
            if expected_revision is not None and revision != expected_revision:
                return {"status": "failed", "branch": branch, "error": "Branch moved after verification"}
            cache_key = (repo_slug.lower(), branch, revision)
            if cache_key in self._open_prs:
                return dict(self._open_prs[cache_key])
            push_res = subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", "push", "origin", f"{revision}:{ref}"],
                timeout=60,
                cwd=str(repo_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"status": "failed", "branch": branch, "error": str(exc)}
        if push_res.returncode != 0:
            return {
                "status": "failed",
                "branch": branch,
                "error": push_res.stderr.strip(),
            }

        # 2. Attempt to open real PR via GitHub MCP server or API if configured
        if "/" in repo_slug:
            parts = repo_slug.split("/")
            gh_res = github_mcp_bridge.create_pull_request(
                owner=parts[0],
                repo=parts[1],
                title=title or f"fix(deps): automated remediation on {branch}",
                head=branch,
                base="main",
                body=body,
            )
            if gh_res and gh_res.get("status") == "opened" and gh_res.get("pr_url"):
                gh_res["branch"] = branch
                gh_res["repo"] = repo_slug
                gh_res["title"] = title or f"fix(deps): automated remediation on {branch}"
                self._open_prs[cache_key] = dict(gh_res)
                return gh_res

        return {
            "status": "failed",
            "branch": branch,
            "repo": repo_slug,
            "error": "GitHub did not confirm pull request creation",
        }


# Global instance
git_server = GitServer()


# Register tools on FastMCP server instance
@mcp.tool(name="git_clone", description="Clones repository into target directory.")
def git_clone(repo_url: str, target_dir: str) -> Dict[str, Any]:
    return git_server.git_clone(repo_url, target_dir)


@mcp.tool(name="git_branch", description="Creates or switches to remediation branch on disk.")
def git_branch(branch_name: str, repo_dir: str, base_branch: Optional[str] = None) -> Dict[str, Any]:
    return git_server.git_branch(branch_name, repo_dir, base_branch=base_branch)


@mcp.tool(name="git_checkout", description="Switch working tree back to specified branch.")
def git_checkout(branch_name: str, repo_dir: str) -> Dict[str, Any]:
    return git_server.git_checkout(branch_name, repo_dir)


@mcp.tool(name="git_patch", description="Applies unified diff patch to target file.")
def git_patch(file_path: str, diff: str, repo_dir: str) -> Dict[str, Any]:
    return git_server.git_patch(file_path, diff, repo_dir)


@mcp.tool(name="git_commit", description="Commits staged manifest changes on disk.")
def git_commit(message: str, repo_dir: str, file_path: Optional[str] = None) -> Dict[str, Any]:
    return git_server.git_commit(message, repo_dir, file_path=file_path)


@mcp.tool(
    name="git_replace_text",
    description="Applies one exact source replacement and commits it on a remediation branch.",
)
def git_replace_text(
    repo_dir: str,
    branch: str,
    file_path: str,
    old_text: str,
    new_text: str,
    commit_message: str,
) -> Dict[str, Any]:
    return git_server.git_replace_text(
        repo_dir, branch, file_path, old_text, new_text, commit_message
    )


@mcp.tool(name="pr_create", description="Opens pull request targeting the concerned repository.")
def pr_create(
    branch: str, body: str, title: Optional[str] = None, repo_dir: Optional[str] = None,
    expected_revision: str | None = None,
) -> Dict[str, Any]:
    return git_server.pr_create(branch, body, title, repo_dir=repo_dir, expected_revision=expected_revision)


@mcp.tool(name="git_cleanup_branch", description="Deletes an orphan remediation branch.")
def git_cleanup_branch(
    branch_name: str, repo_dir: str, force: bool = True
) -> Dict[str, Any]:
    return git_server.git_cleanup_branch(branch_name, repo_dir, force=force)


@mcp.tool(name="git_has_branch", description="Checks if branch exists in the repository.")
def git_has_branch(branch_name: str, repo_dir: str) -> bool:
    return git_server.git_has_branch(branch_name, repo_dir)


if __name__ == "__main__":
    mcp.run()
