#!/usr/bin/env python3.13
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import get_repository, HEAD, MAIN, refresh_remote_head, \
    fast_forward, GitRev

logger = logging.getLogger(__name__)


class GitFFMain(cmd.Main):
    def __init__(self):
        super().__init__()

        self.parser.add_argument(
            "branches",
            nargs="*",
            default=(HEAD, MAIN),
            help="Fast-forward these branches"
        )
        self.completed: set[str] = set()

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
        repository = get_repository()
        if repository is None:
            logger.error("No repository found")
            exit(1)
        for remote in repository.remotes:
            refresh_remote_head(remote.name)
        fast_forwarded: set[str] = set()
        branches: list[GitRev | str] = self.args.branches
        for branch_name in branches:
            if isinstance(branch_name, GitRev):
                resolved = branch_name.resolved
            else:
                resolved = branch_name
            if resolved in fast_forwarded:
                if resolved and resolved != branch_name:
                    logger.debug("Skipping %s since it was already fast-forwarded via %s", branch_name, resolved)
                else:
                    logger.debug("Skipping already fast-forwarded branch %s", branch_name)
            else:
                if resolved and resolved != branch_name:
                    logger.info("Fast forwarding %s as %s", branch_name, resolved)
                else:
                    logger.info("Fast forwarding %s", branch_name)
                fast_forward(repository, branch_name)
                if resolved:
                    fast_forwarded.add(resolved)
                fast_forwarded.add(str(branch_name))


def main():
    GitFFMain().main()


if __name__ == "__main__":
    main()
