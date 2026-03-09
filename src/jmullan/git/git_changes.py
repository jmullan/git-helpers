#!/usr/bin/env python3.13
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import run, HEAD

logger = logging.getLogger(__name__)


class GitChangesMain(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument(
            "rev",
            default=HEAD,
            nargs="?",
            help="Changes included in this revision"
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
        if self.args.rev is not None:
            diff = run("git", "diff", f"{self.args.rev}^", f"{self.args.rev}")
            print("\n".join(diff))


def main():
    GitChangesMain().main()


if __name__ == "__main__":
    main()
