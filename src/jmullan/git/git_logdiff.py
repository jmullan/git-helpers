#!/usr/bin/env python3.13
import logging
import os
import shutil
import sys
from collections.abc import Iterable

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import HEAD, UPSTREAM, get_main, git_log_diff

logger = logging.getLogger(__name__)


def get_terminal_width() -> int:
    terminal_size = shutil.get_terminal_size()
    if terminal_size is not None and terminal_size.columns is not None:
        return terminal_size.columns
    else:
        return 80


def optimize_column_widths(padding: int, max_widths: dict[int, int], available_width: int) -> dict[int, int]:
    new_max_widths = max_widths.copy()
    width = padding + sum(new_max_widths.values())
    if width <= available_width:
        return new_max_widths
    item_count = len(new_max_widths)
    remaining_width = available_width - padding
    if remaining_width < 0 or remaining_width < item_count:
        # there isn't enough room, so just print everything
        return new_max_widths

    min_width = (available_width - padding) // item_count
    while width > available_width:
        max_index = None
        max_width = min_width
        for index, item_width in new_max_widths.items():
            if item_width > max_width:
                max_index = index
                max_width = item_width
        if max_index is not None:
            new_max_widths[max_index] -= 1
        else:
            break
        width = padding + sum(new_max_widths.values())
    return new_max_widths


class Columnist:
    def __init__(
        self,
        heading: list[str],
        data: list[tuple[str | None, ...]],
        terminal_width: int
    ) -> None:
        self.heading = heading
        self.data = data
        self.width = terminal_width

        self.left = "| "
        self.middle = " | "
        self.right = " |"
        max_widths = {}
        for datum in data:
            for index, item in enumerate(datum):
                if max_widths.get(index) is None:
                    max_widths[index] = 0
                if item is not None:
                    item = item.rstrip()
                    len_item = len(item)
                    max_widths[index] = max(max_widths.get(index, 0), len_item)
        column_count = len(max_widths)
        if column_count == 0:
            return
        separator_count = column_count - 1
        padding = len(self.left) + len(self.right) + (separator_count * len(self.middle))
        self.column_widths = optimize_column_widths(padding, max_widths, self.width)


    def print_data(self) -> None:
        if self.heading:
            self.print_datum(self.heading)
            heading_end = [
                "-" * v
                for v in self.column_widths.values()
            ]
            self.print_datum(heading_end)
        for datum in self.data:
            self.print_datum(datum)

    def print_datum(self, datum: Iterable[str | None]) -> None:
        fields = []
        for index, item in enumerate(datum):
            if item is None:
                item = ""
            column_width = self.column_widths[index]
            fields.append(f"{item[:column_width]:<{column_width}}")
        middle = self.middle.join(fields)
        print(f"{self.left}{middle}{self.right}")


class GitLogDiffMain(cmd.Main):
    def __init__(self):
        super().__init__()
        best_main = get_main()
        self.parser.add_argument("from_rev", nargs="?", default=HEAD, help="use this remote")
        if best_main is not None:
            default_to = best_main
        else:
            default_to = UPSTREAM
        self.parser.add_argument("to_rev", nargs="?", default=default_to, help="use this remote.")

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
        log_diff = git_log_diff(self.args.from_rev, self.args.to_rev)
        terminal_width = get_terminal_width()
        data = []
        for a, b in reversed(log_diff.zipped_unique):
            if a is not None and " " in a:
                sha_a, comment_a = a.split(" ", 1)
            else:
                sha_a = None
                comment_a = a
            if b is not None and " " in b:
                sha_b, comment_b = b.split(" ", 1)
            else:
                sha_b = None
                comment_b = b
            data.append((sha_a, comment_a, sha_b, comment_b))
        heading = [
            "sha",
            self.args.from_rev,
            "sha",
            self.args.to_rev,
        ]
        columnist = Columnist(
            heading=heading,
            data=data,
            terminal_width=terminal_width
        )
        columnist.print_data()


        common = [(x, ) for x in log_diff.from_lines[-log_diff.last_common:][:3]]  # type: list[tuple[str | None, ...]]

        common.insert(0, ("-" * terminal_width, "-" * terminal_width))
        common_lines_printer = Columnist(
            heading=[],
            data=common,
            terminal_width=terminal_width
        )
        common_lines_printer.print_data()


def main():
    GitLogDiffMain().main()


if __name__ == "__main__":
    main()
