#!/usr/bin/env python3.13
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import first, run

logger = logging.getLogger(__name__)


def get_last_message():
    return first(run("git log -1 --pretty=%B"))


def amend_last_commit(message: str):
    logger.info(f"Amending last commit: {message}")
    return run("git commit -a --amend  --no-edit --no-verify")


def make_new_wip_commit():
    logger.info("Making a new WIP commit")
    return run("git commit -a -m WIP --no-verify")


class GitStepMain(cmd.Main):
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


def main():
    GitStepMain().main()


if __name__ == "__main__":
    main()
