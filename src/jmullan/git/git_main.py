#!/usr/bin/env python3.13
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import add_remote_argument, find_remote, get_main, refresh_remote_head, require_repository

logger = logging.getLogger(__name__)


class GitMainMain(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument(
            "--refresh",
            dest="refresh_remote_head",
            action="store_true",
            default=False,
            help="Check for a new main branch",
        )
        add_remote_argument(self.parser)

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
        if self.args.refresh_remote_head:
            repo = require_repository()
            logger.debug(f"Found a repo {repo=}")
            remote = find_remote(repo, self.args.remote)
            logger.debug(f"Found a remote {remote=}")
            refresh_remote_head(remote.name)

        main_branch = get_main(self.args.remote)
        if main_branch is None:
            logger.error("No main found.")
            exit(1)
        print(main_branch)


def main():
    GitMainMain().main()


if __name__ == "__main__":
    main()
