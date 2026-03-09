#!/usr/bin/env python3.13
import logging
import sys

from colorist import Color
from jmullan.cmd import cmd
from jmullan.cmd.auto_config import add_color_arguments
from jmullan.logging import easy_logging

from jmullan.git.utils import count_lines, UPSTREAM, HEAD

logger = logging.getLogger(__name__)


def build_graph(symbol: str, left_pad: int, width: int, right_pad: int):
    return " " * left_pad + symbol * width + " " * right_pad


class GitDiffGraphMain(cmd.Main):
    def __init__(self):
        super().__init__()
        add_color_arguments(self.parser)

        self.parser.add_argument(
            "to_rev",
            nargs="?",
            default=UPSTREAM,
            help="use this remote."
        )

        self.parser.add_argument(
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
        size = 10
        if line_counts.total is None or line_counts.total == 0:
            exit(0)

        scale = line_counts.total // size

        add_width = line_counts.adds // scale
        add_pad_left = size - add_width
        adds = build_graph("+", add_pad_left, add_width, 0)

        deletes_width = line_counts.deletes // scale
        deletes_pad_right = size - deletes_width
        deletes = build_graph("-", 0, deletes_width, deletes_pad_right)

        if self.args.colors:
            print(f"{Color.GREEN}{adds}{Color.RED}{deletes}{Color.OFF}")
        else:
            print(f"{adds}{deletes}")






def main():
    GitDiffGraphMain().main()


if __name__ == "__main__":
    main()
