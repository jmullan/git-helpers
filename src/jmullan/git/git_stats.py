#!/usr/bin/env python3.13
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import UPSTREAM, HEAD, count_lines

logger = logging.getLogger(__name__)


class GitStatsMain(cmd.Main):
    def __init__(self):
        super().__init__()
        group = self.parser.add_argument_group()

        group.add_argument(
            "to_rev",
            nargs="?",
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
        line_counts = count_lines(self.args.from_rev, self.args.to_rev)
        print(f"{line_counts.adds} {line_counts.deletes}")

def main():
    GitStatsMain().main()


if __name__ == "__main__":
    main()
