#!/usr/bin/env python3.13
import logging
import pathlib
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import GitRev, require_repository, run

logger = logging.getLogger(__name__)


def get_names(rev: str | None, only_exists: bool, only_missing: bool):
    repo = require_repository()
    logger.debug(f"Found a repo {repo=}")
    if rev is not None:
        if isinstance(rev, GitRev):
            rev = rev.shortcut
        args = ["git", "diff", "--name-only", rev]
    else:
        args = ["git", "diff", "--name-only"]
    lines = run(*(f"{arg}" for arg in args))
    if not only_exists and not only_missing:
        for line in lines:
            print(line)
        exit(0)
    work_dir = pathlib.Path(repo.workdir)
    if work_dir.is_dir():
        for changed_file in lines:
            file_path = work_dir / changed_file
            if file_path.exists() and only_exists:
                print(changed_file)
            if not file_path.exists() and only_missing:
                print(changed_file)
    exit(0)


class GitNamesMain(cmd.Main):
    def __init__(self):
        super().__init__()
        filter_files = self.parser.add_mutually_exclusive_group()
        filter_files.add_argument("--only-exists", dest="only_exists", action="store_true", default=False)
        filter_files.add_argument("--only-missing", dest="only_missing", action="store_true", default=False)
        self.parser.add_argument("rev", nargs="?", default=None, help="Against this")

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
        get_names(self.args.rev, self.args.only_exists, self.args.only_missing)


def main():
    GitNamesMain().main()


if __name__ == "__main__":
    main()
