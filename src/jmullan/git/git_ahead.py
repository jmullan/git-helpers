#!/usr/bin/env python3.13
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import get_repository, HEAD, UPSTREAM, WORKING_TREE, \
    STAGED, count_commits

logger = logging.getLogger(__name__)


def git_ahead(from_rev: str, to_rev: str):
    return count_commits(from_rev, to_rev).ahead


class GitAheadMain(cmd.Main):
    def __init__(self):
        super().__init__()
        group = self.parser.add_argument_group()

        group.add_argument(
            "to_rev",
            default=UPSTREAM,
            help="use this remote."
        )

        group.add_argument(
            "from_rev",
            nargs="?",
            default=HEAD,
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
        super().main()
        repo = get_repository()
        if repo is None:
            logger.debug("Not in a git repository")
            exit(1)
        if self.args.from_rev in (WORKING_TREE, STAGED):
            logger.error("from_rev must be a valid rev")
            exit(1)
        if self.args.to_rev in (WORKING_TREE, STAGED):
            logger.error("to_rev must be a valid rev")
            exit(1)
        print(git_ahead(self.args.from_rev, self.args.to_rev))


def main():
    GitAheadMain().main()


if __name__ == "__main__":
    main()
