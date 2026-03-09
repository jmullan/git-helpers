#!/usr/bin/env python3.13
import logging
import pathlib
import sys
from datetime import datetime

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import get_repository, first_empty_as_none, run

logger = logging.getLogger(__name__)


class GitTimeCard(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument("extras", nargs="*")


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

        """GIT_CLONE_DIR=$(dirname $GIT_DIR)
        DATE=$(date "+%F %H:%M:%S")
        HEADNAME="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
        LOGFILE=$(git config timecard.filename)
        if [ -n "${LOGFILE}" ] ; then
            echo "${DATE} $(basename ${GIT_CLONE_DIR}) ${HEADNAME} ${@}" >> "${LOGFILE}"
        fi
        """

        repo = get_repository()
        if repo is None:
            exit(0)
        log_file_setting = first_empty_as_none(run("git", "config", "timecard.filename"))
        if log_file_setting is None:
            return
        log_file_path = pathlib.Path(log_file_setting)
        work_dir_name = pathlib.Path(repo.workdir).name
        head_name = first_empty_as_none(run("git", "rev-parse", "--abbrev-ref", "HEAD"))
        today = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        extras = self.args.extras or []
        line = " ".join(f"{x}" for x in (work_dir_name, head_name, today, *extras))
        with log_file_path.open("a") as handle:
            handle.write(f"{line}")

def main():
    GitTimeCard().main()


if __name__ == "__main__":
    main()
