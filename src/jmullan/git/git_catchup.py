#!/usr/bin/env python3.13
import logging
import subprocess
import sys

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import UPSTREAM, git_log_diff, HEAD

logger = logging.getLogger(__name__)


class GitCatchupMain(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument("to_rev", default=UPSTREAM, help="Catch up to this branch")

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
        need_line_count = None
        limit = 10000
        while limit > 0:
            limit = limit - 1
            log_diff = git_log_diff(HEAD, self.args.to_rev)
            if not log_diff.zipped_unique:
                logger.info("Branches are the same.")
                exit(0)

            if need_line_count is None:
                need_line_count = sum(
                    1
                    for line in log_diff.zipped_unique
                    if line[1] is not None
                )
                limit = need_line_count
            have_line, need_line = log_diff.zipped_unique[0]
            if need_line is None:
                logger.info("Nothing to catch up")
                exit(0)
            else:
                need_rev, date, message = need_line.split(" ", 2)
                print(f"Rebasing against {need_rev} from {date}: {message}")
                command = ("git", "rebase", f"{need_rev}")
                print(command)
                result = subprocess.run(command)
                if result.returncode != 0:
                    abort_command = ("git", "rebase", "--abort")
                    subprocess.run(abort_command)
                    logger.error(f"Cannot rebase past {need_rev}")
                    exit(1)


def main():
    GitCatchupMain().main()


if __name__ == "__main__":
    main()
