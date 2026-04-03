import dataclasses
import functools
import logging
import os
import pathlib
import subprocess
from argparse import ArgumentParser
from collections.abc import Callable

import pygit2
from pygit2 import Repository

logger = logging.getLogger(__name__)


def get_main(remote_name: str | None = None) -> str | None:
    """Find what is the main branch."""
    repo = require_repository()
    if remote_name is not None:
        remote = find_remote(repo, remote_name)
    else:
        remote = best_remote(repo)

    gitflow_main = get_git_flow_main()
    default_branch = get_default_branch()
    local_branches = get_local_branches()
    if remote is not None and remote.name is not None:
        if remote_name is None:
            remote_name = remote.name
        remote_head = get_remote_head(remote.name)
    else:
        remote_head = None
    if remote_head is not None:
        if remote_name is not None:
            remote_head_branch = remote_head.removeprefix(f"{remote_name}/")
        else:
            remote_head_branch = remote_head
    else:
        remote_head_branch = None
    if gitflow_main is not None:
        if remote_head_branch is not None and gitflow_main != remote_head_branch:
            logger.warning(
                "gitflow.branch.main=%s does not equal %s/HEAD %s %s",
                gitflow_main,
                remote_name,
                remote_head,
                remote_head_branch,
            )
        if gitflow_main not in local_branches:
            logger.warning("gitflow.branch.main=%s does not exist", gitflow_main)
        else:
            return gitflow_main

    if remote_head_branch is not None:
        if remote_head_branch in local_branches:
            return remote_head_branch
        logger.warning("%s/HEAD %s %s does not exist locally", remote.name, remote_head, remote_head_branch)

    if remote_name is not None:
        remote_branches = get_remote_branches(remote_name)
        maybe_main = find_first(remote_branches, ALLOWED_BRANCHES, remote)
    else:
        maybe_main = None
    if maybe_main is not None:
        return maybe_main

    if default_branch is not None and default_branch in local_branches:
        return default_branch

    maybe_main = find_first(local_branches, ALLOWED_BRANCHES, None)
    if maybe_main is not None:
        return maybe_main
    if len(local_branches) == 1:
        return local_branches[0]
    return "main"


@dataclasses.dataclass
class GitRev:
    name: str
    resolver: str | Callable[..., str | None] = None

    def __str__(self):
        return self.name

    @functools.cached_property
    def resolved(self):
        if self.resolver is None:
            return None
        if isinstance(self.resolver, str):
            resolved = rev_parse_short(self.resolver)
            if resolved is not None:
                return resolved
            return self.resolver
        return self.resolver()


HEAD = GitRev("HEAD", "HEAD")
WORKING_TREE = GitRev("working tree")
STAGED = GitRev("--staged")
UPSTREAM = GitRev("upstream", "@{u}")
MAIN = GitRev("MAIN", get_main)


def get_repository() -> pygit2.Repository | None:
    current_working_directory = os.getcwd()
    repository_path = pygit2.discover_repository(current_working_directory)
    if repository_path is not None:
        return pygit2.Repository(repository_path)
    return None


def require_repository() -> pygit2.Repository:
    repo = get_repository()
    if repo is None:
        logger.debug("Not in a git repository")
        exit(1)
    return repo


def run(*args: str) -> list[str]:
    if (len(args)) == 1 and " " in args[0]:
        return run(*(args[0].split(" ")))
    logger.debug("Running %s", " ".join(args))
    with subprocess.Popen(args, stdout=subprocess.PIPE) as proc:
        if proc.stdout is not None:
            return proc.stdout.read().decode("UTF8").strip().split("\n")
    return []


def first(strings: list[str]) -> str:
    for line in strings or []:
        if len(line):
            return line
    return ""


def first_empty_as_none(strings: list[str]) -> str | None:
    first_string = first(strings)
    if first_string is None:
        return None
    first_string = first_string.strip()
    if not len(first_string):
        return None
    return first_string


def dump_reference(message: str, reference: pygit2.Reference):
    logger.debug(f"""{message}
            {reference.name=}
            {reference.shorthand=}
            {reference.target=}
        """)


@dataclasses.dataclass
class CommitCounts:
    rev_from: str | None
    rev_to: str | None
    behind: int
    ahead: int


@dataclasses.dataclass
class LineCounts:
    deletes: int
    adds: int

    @property
    def total(self) -> int:
        return self.adds + self.deletes


def as_rev(rev: GitRev | str) -> str:
    if isinstance(rev, GitRev) and rev.resolved is not None:
        return rev.resolved
    return f"{rev}"


def count_commits(rev_from: str, rev_to: str) -> CommitCounts:
    """Git rev-list --left-right "$FROM...$TO" | grep '^<' | wc -l | awk '{print $1}'"""
    if rev_from is None or rev_to is None or rev_from == rev_to:
        return CommitCounts(rev_from, rev_to, 0, 0)
    command = ["git", "rev-list", "--left-right", f"{as_rev(rev_from)}...{as_rev(rev_to)}"]
    lines = run(*command)
    behind = 0
    ahead = 0
    for line in lines:
        if line is None or len(line) < 1:
            continue
        if line[0] == "<":
            ahead += 1
        elif line[0] == ">":
            behind += 1
    return CommitCounts(rev_from, rev_to, behind, ahead)


def count_lines(from_rev: str, to_rev: str) -> LineCounts:
    """Git rev-list --left-right "$FROM...$TO" | grep '^<' | wc -l | awk '{print $1}'"""
    command = ["git", "diff", "--numstat", f"{as_rev(from_rev)}", f"{as_rev(to_rev)}"]
    lines = run(*command)
    adds = 0
    deletes = 0
    for line in lines:
        if line is None or len(line) < 1:
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3:
            logger.debug("Got weird line with %s parts: %s", len(parts), line)
            continue
        try:
            adds += int(parts[0])
            deletes += int(parts[1])
        except Exception:
            logger.debug("Could not turn line into change counts: %s", line, exc_info=True)
            continue
    return LineCounts(deletes, adds)


def rev_parse_short(ref_name: str) -> str | None:
    return first(run("git", "rev-parse", "--abbrev-ref", ref_name))


def rev_parse_full(ref_name: str) -> str | None:
    return first(run("git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", ref_name))


def get_local_branches() -> list[str]:
    return run("git", "branch", "--format", "%(refname:short)")


def get_branch_trackings() -> dict[str, str]:
    lines = run("git", "for-each-ref", "--format=%(refname:short)\t%(upstream:short)", "refs/heads/")
    mappings = {}
    for line in lines:
        line = line.strip()
        if len(line) == 0 or "\t" not in line:
            logger.debug("Bad branch mapping line (no tab) %s", line)
        else:
            short, upstream = line.split("\t", 1)
            if "\t" in upstream:
                logger.warning("Bad branch mapping line (extra tab) %s", line)
            mappings[short] = upstream
    return mappings


ALLOWED_BRANCHES = ["main", "master"]


def fetch_all() -> list[str]:
    return run("git", "fetch", "--all")


def fetch_remote(remote_name: str) -> list[str]:
    return run("git", "fetch", remote_name)


def get_remote_branches(remote: str) -> list[str]:
    return run("git", "for-each-ref", "--format=%(refname:short)", f"refs/remotes/{remote}")


def get_default_branch() -> str | None:
    """Ask git what branch is configured as the default."""
    return first_empty_as_none(run("git", "config", "--get", "init.defaultBranch"))


def get_remote_head(remote: str) -> str | None:
    """Try to find the HEAD of the remote (the main branch)."""
    return rev_parse_full(f"refs/remotes/{remote}/HEAD")


def find_first(candidates: list[str], allowed: list[str], remote: str | None) -> str | None:
    """Find the first string that matches one of the allowed strings.

    If a remote is passed in, fall back to one of the candidates if it is
    prefixed with the remote.
    """
    if remote is not None:
        remote_prefix = f"{remote}/"
    else:
        remote_prefix = None
    for allowed_branch in allowed:
        for candidate in candidates:
            if candidate == allowed_branch:
                return candidate

            if remote_prefix is not None and candidate.startswith(remote_prefix):
                stripped = candidate.removeprefix(remote_prefix)
                if stripped == allowed_branch:
                    return candidate
    return None


def find_remote(repository: pygit2.Repository, remote_name: str) -> pygit2.Remote | None:
    """Given a remote name, see if it is in the repository."""
    if remote_name is None:
        return None
    for remote_candidate in repository.remotes:
        logger.debug(f"Examining {remote_candidate.name}")
        if remote_candidate.name == remote_name:
            logger.debug(f"Found remote {remote_candidate.name}")
            return remote_candidate
    return None


def best_remote(repository: pygit2.Repository) -> pygit2.Remote | None:
    """Find the probable main remote (origin, or upstream)."""
    for remote_name in ["origin", "upstream"]:
        remote = find_remote(repository, remote_name)
        if remote is not None:
            return remote
    return None


def get_heads(repository: pygit2.Repository) -> list[str]:
    """Find the heads that git knows about."""
    heads = []
    refs_heads_path = pathlib.Path(repository.path) / "logs" / "refs" / "heads"
    if refs_heads_path.is_dir():
        for file_path in refs_heads_path.rglob("*"):
            if file_path.is_file():
                heads.append(file_path.relative_to(refs_heads_path).as_posix())
    return heads


def add_remote_argument(parser: ArgumentParser, repository: pygit2.Repository | None = None) -> None:
    """Tack a remote option to the parser."""
    if repository is None:
        repository = get_repository()
    if repository is not None:
        remote_names = None
        default = None
        remotes = repository.remotes
        if remotes:
            remote_names = [remote.name for remote in remotes]
            if "origin" in remote_names:
                default = "origin"
            else:
                default = first(remote_names)
        parser.add_argument("--remote", dest="remote", default=default, choices=remote_names, help="use this remote")


def get_git_flow_main() -> str | None:
    """Try to find what branch has been configured as main."""
    return first_empty_as_none(run("git", "config", "--get", "gitflow.branch.main"))


def get_git_flow_develop() -> str | None:
    """Try to find what branch has been configured as develop."""
    return first_empty_as_none(run("git", "config", "--get", "gitflow.branch.develop"))


def refresh_remote_head(remote_name: str):
    if remote_name is None:
        logger.warning("Cannot refresh no remote")
        exit(1)
    fetch_remote(remote_name)

    logger.debug(f"Refreshing the main branch from {remote_name}")
    remote_head = rev_parse_full(f"refs/remotes/{remote_name}/HEAD")
    if remote_head is not None and len(remote_head) > 0:
        logger.debug(f"Found remote head {remote_head}")
        run("git", "remote", "set-head", f"{remote_name}", "-a")


def fast_forward(repository: Repository, branch_ref: GitRev | str):
    if isinstance(branch_ref, GitRev):
        resolved = branch_ref.resolved
    else:
        resolved = branch_ref
    if resolved is None:
        logger.error("Could not resolve %s", branch_ref)
        return
    branch = repository.branches.get(resolved)
    if not branch:
        logger.error("Could not find branch ref %s when resolved to %s", branch_ref, resolved)
        return
    upstream = branch.upstream
    if not branch.upstream:
        logger.warning("Cannot fast forward branch ref %s branch %s since it has no upstream", branch_ref, resolved)
        return

    remote_name = upstream.remote_name
    upstream_branch: str | None = None
    if remote_name:
        remote = find_remote(repository, remote_name)
        if remote is not None:
            remote_prefix = f"{remote.name}/"
            if upstream.shorthand.startswith(remote_prefix):
                upstream_branch = upstream.shorthand.removeprefix(remote_prefix)
            else:
                logger.error("Got remote branch but could not resolve upstream branch")
                return
    else:
        remote_name = "."
        upstream_branch = upstream.upstream_name

    if upstream_branch is None:
        logger.error("Could not determine upstream branch for %s", branch_ref)
        return
    head = HEAD.resolved
    if head == resolved:
        run("git", "pull", "--ff-only")
    else:
        run("git", "fetch", remote_name, f"{resolved}:{upstream_branch}")
