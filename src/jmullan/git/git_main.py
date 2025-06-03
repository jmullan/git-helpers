#!/usr/bin/env python3.13
import logging
import pygit2

import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging
from jmullan.git.utils import first, get_repository, rev_parse, run

logger = logging.getLogger(__name__)

GITFLOW_MAIN = "git config --get gitflow.branch.main"
ALLOWED_BRANCHES = [
    "main",
    "master"
]

def fetch_all():
    return run(f"git fetch --all")

def get_remote_branches(remote: str):
    return run(f"git for-each-ref --format=%(refname:short) refs/heads refs/remotes/{remote}")


def get_remote_head(remote: str):
    # git rev-parse --abbrev-ref --symbolic-full-name refs/remotes/{remote}/HEAD
    return rev_parse(f"refs/remotes/{remote}/HEAD")


def refresh(remote: str):
    fetch_all()

    logger.debug(f"Refreshing the main branch from {remote}")
    remote_head = rev_parse(f"refs/remotes/{remote}/HEAD")
    if len(remote_head):
        logger.debug(f"Found remote head {remote_head}")
        run(f"git remote set-head {remote} -a")


def find_first(candidates: list[str], allowed: list[str], remote: str):
    remote_prefix = f"{remote}/"
    for allowed_branch in allowed:
        for candidate in candidates:
            if candidate == allowed_branch:
                return candidate

            if candidate.startswith(remote_prefix):
                stripped = candidate.removeprefix(remote_prefix)
                if stripped == allowed_branch:
                    return candidate
    return ""


class GitMainMain(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument(
            "--refresh",
            action="store_true",
            default=False,
            help='Check for a new main branch'

        )
        self.parser.add_argument(
            "--remote",
            default="origin",
            help="use this remote"
        )

    def setup(self):
        super().setup()
        if self.args.verbose:
            easy_logging.easy_initialize_logging("DEBUG", stream=sys.stderr)
        elif self.args.quiet:
            easy_logging.easy_initialize_logging("WARNING", stream=sys.stderr)
        else:
            easy_logging.easy_initialize_logging("INFO", stream=sys.stderr)

    def main(self):
        try:
            super().main()
            self._main()
        except Exception:
            logger.exception("Unexpected error")
            exit(1)
        exit(0)

    def _main(self):
        repo = get_repository()
        if repo is None:
            logger.debug("Not in a git repository")
            exit(0)
        logger.debug(f"Found a repo {repo=}")
        remote: str | None = None
        for remote_candidate in repo.remotes:
            logger.debug(f"Examining {remote_candidate.name}")
            if remote_candidate.name == self.args.remote:
                logger.debug(f"Found remote {remote_candidate.name}")
                remote = self.args.remote
                break
        if remote is None:
            logger.warning("Could not find a remote")
            exit(1)
        if self.args.refresh:
            refresh(remote)
        gitflow_main = first(run(GITFLOW_MAIN))
        remote_head = get_remote_head(remote)
        if len(gitflow_main) and len(remote_head) and gitflow_main != remote_head:
            logger.warning(f"gitflow.branch.main={gitflow_main} does not equal {remote}/head {remote_head}")
        if len(gitflow_main):
            print(gitflow_main)
            exit(0)
        if len(remote_head):
            branch_only = remote_head.removeprefix(f"{remote}/")
            if len(branch_only):
                print(branch_only)
            else:
                print(remote_head)
            exit(0)
        remote_branches = get_remote_branches(remote)
        logger.debug(f"{remote_branches=}")
        maybe_main = find_first(remote_branches, ALLOWED_BRANCHES, remote)
        if maybe_main:
            print(maybe_main)
        print("main")


def main():
    GitMainMain().main()


if __name__ == "__main__":
    main()
