#!/usr/bin/env python3.13
import difflib
import itertools
import logging
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import HEAD, UPSTREAM, get_main, run

logger = logging.getLogger(__name__)


def short_log(rev: str) -> list[str]:
    return run("git", "log", "--first-parent", "--pretty=format:%h %ad %s", "--date=short", f"{rev}")

def print_columns(left: str | None, right: str | None) -> None:
    if left is None:
        left = ""
    if right is None:
        right = ""
    print(f"{left[:40]:<40} {right[:40]:<40}")

def git_logdiff(from_rev: str, to_rev: str) -> None:
    from_lines = short_log(from_rev)
    to_lines = short_log(to_rev)

    last_common = None
    for i, (a, b) in enumerate(zip(reversed(from_lines), reversed(to_lines)), 1):
        if a != b:
            break
        last_common = i
    if last_common is None:
        return

    common_start_from = len(from_lines) - last_common
    common_start_to = len(to_lines) - last_common

    unique_from = reversed(from_lines[:common_start_from])
    unique_to = reversed(to_lines[:common_start_to])

    zipped_unique = list(itertools.zip_longest(unique_from, unique_to))
    print_columns(from_rev, to_rev)
    for a, b in reversed(zipped_unique):
        print_columns(a, b)
    if last_common is not None:
        print("=" * 81)
        common = from_lines[-last_common:][:3]
        for line in common:
            print(line)


class GitLogDiffMain(cmd.Main):
    def __init__(self):
        super().__init__()
        best_main = get_main()
        self.parser.add_argument(
            "from_rev",
            nargs="?",
            default=HEAD,
            help="use this remote"
        )
        if best_main is not None:
            default_to = best_main
        else:
            default_to = UPSTREAM
        self.parser.add_argument(
            "to_rev",
            nargs="?",
            default=default_to,
            help="use this remote."
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
        git_logdiff(self.args.from_rev, self.args.to_rev)

def main():
    GitLogDiffMain().main()


if __name__ == "__main__":
    main()
