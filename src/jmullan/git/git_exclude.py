#!/usr/bin/env python3.13
import logging
import pathlib
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import require_repository

logger = logging.getLogger(__name__)


def git_exclude(patterns: list[str]) -> None:
    if patterns is None or not patterns:
        logger.debug("Nothing to exclude")
        exit(0)
    repo = require_repository()
    repo_path = pathlib.Path(repo.path)
    if not repo_path.exists():
        logger.error("Repo does not exist?")
        exit(1)
    info_dir = repo_path / "info"
    info_dir.mkdir(exist_ok=True)
    exclude_file =  info_dir / "exclude"
    needs_new_line = False
    if exclude_file.is_file():
        text = exclude_file.read_text(encoding="utf-8")
        if len(text) and not text.endswith("\n"):
            needs_new_line = True
    else:
        text = ""
    lines = set(text.split("\n"))
    logger.debug("%s", lines)
    with exclude_file.open("a", encoding="utf-8") as handle:
        if needs_new_line:
            handle.write("\n")
        for pattern in patterns:
            if pattern not in lines:
                handle.write(f"{pattern}\n")


class GitExcludeMain(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument("exclusions", nargs="+")

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
        git_exclude(self.args.exclusions)


def main():
    GitExcludeMain().main()


if __name__ == "__main__":
    main()
