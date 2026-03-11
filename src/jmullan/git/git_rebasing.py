#!/usr/bin/env python3.13
import logging
import pathlib
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import count_commits, get_repository

logger = logging.getLogger(__name__)


def get_rebasing() -> str | None:
    repository = get_repository()
    if repository is None:
        logger.debug("No repository found")
        return None
    repo_path = pathlib.Path(repository.path)
    if (repo_path / "rebase-merge").exists():
        if (repo_path / "rebase-merge" / "interactive").exists():
            return "INTERACTIVE REBASING"
        return "MERGING REBASE"
    if (repo_path / "rebase-apply").exists():
        if (repo_path / "rebase-apply" / "rebasing").exists():
            PROGRESS = count_commits("HEAD", "rebase-apply/onto").ahead
            TOTAL = count_commits("HEAD", "rebase-apply/orig-head").behind
            return f"REBASING ({PROGRESS}/{TOTAL})"
        if (repo_path / "rebase-apply" / "applying").exists():
            return "APPLYING REBASE"
        return "REBASING"
    logger.debug("Not rebasing")
    return None


class GitRebasingMain(cmd.Main):
    def __init__(self):
        super().__init__()

    def setup(self):
        super().setup()
        if self.args.verbose:
            easy_logging.easy_initialize_logging("DEBUG", stream=sys.stderr)
        elif self.args.quiet:
            easy_logging.easy_initialize_logging("WARNING", stream=sys.stderr)
        else:
            easy_logging.easy_initialize_logging("INFO", stream=sys.stderr)

    def main(self):
        super().main()

        rebasing = get_rebasing()
        if rebasing is not None:
            print(rebasing)


def main():
    GitRebasingMain().main()


if __name__ == "__main__":
    main()
