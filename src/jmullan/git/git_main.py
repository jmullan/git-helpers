#!/usr/bin/env python3.13
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import rev_parse, run, \
    require_repository, add_remote_argument, \
    get_main, find_remote, fetch_all

logger = logging.getLogger(__name__)



def refresh(remote: str):
    if remote is None:
        logger.warning("Cannot refresh no remote")
        exit(1)
    fetch_all()

    logger.debug(f"Refreshing the main branch from {remote}")
    remote_head = rev_parse(f"refs/remotes/{remote}/HEAD")
    if len(remote_head):
        logger.debug(f"Found remote head {remote_head}")
        run(f"git", "remote", "set-head",  f"{remote}", "-a")


class GitMainMain(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument(
            "--refresh",
            action="store_true",
            default=False,
            help='Check for a new main branch'
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
        if self.args.refresh:
            repo = require_repository()
            logger.debug(f"Found a repo {repo=}")
            remote = find_remote(repo, self.args.remote)
            logger.debug(f"Found a remote {remote=}")
            refresh(remote.name)

        main_branch = get_main(self.args.remote)
        if main_branch is None:
            logger.error("No main found.")
            exit(1)
        print(main_branch)


def main():
    GitMainMain().main()


if __name__ == "__main__":
    main()
