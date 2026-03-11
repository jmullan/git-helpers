#!/usr/bin/env python3.13
import logging
import pathlib
import sys

from pygit2 import Repository

from jmullan.cmd import cmd
from jmullan.logging import easy_logging

from jmullan.git.utils import (
    count_commits,
    first_empty_as_none,
    get_branch_trackings,
    get_git_flow_develop,
    get_local_branches,
    get_main,
    require_repository,
    run,
)

logger = logging.getLogger(__name__)


def get_remote_to_branches(repository: Repository) -> dict[str, list[str]]:
    remote_to_branches: dict[str, list[str]] = {}
    refs_remotes_path = pathlib.Path(repository.path) / "logs" / "refs" / "remotes"
    for remote in repository.remotes:
        if remote.name not in remote_to_branches:
            remote_to_branches[remote.name] = []
        remote_path = refs_remotes_path / remote.name
        if remote_path.is_dir():
            for file_path in remote_path.rglob("*"):
                if file_path.is_file():
                    remote_to_branches[remote.name].append(file_path.relative_to(refs_remotes_path).as_posix())
    return remote_to_branches


def get_ref_date(ref: str) -> str | None:
    return first_empty_as_none(run("git", "log", f"{ref}", "--pretty=format:%ad", "--date=short"))


def branches(show_remotes: bool):
    """_MAIN=$(git main)
    MAIN=$(git for-each-ref --format='%(refname:short)' refs/heads refs/remotes/origin | grep '^'"${_MAIN}"'$')
    DEVELOP=$(git for-each-ref --format='%(refname:short)' refs/heads refs/remotes/origin | grep '^develop$')
    IFS=$'\n'
    for branch in $BRANCHES; do
        FEATURE=$(echo "${branch}" | grep feature/)
        if [ -n "${FEATURE}" ] && [ -n "${DEVELOP}" ] ; then
            FROM="${DEVELOP}"
        else
            FROM="${MAIN}"
        fi
        if [ "${branch}" = "${FROM}" ] ; then
            FROM=$(git for-each-ref --format='%(refname:short)' refs/heads refs/remotes/origin | grep "^origin/${FROM}"'$')
        fi
        AHEAD=$(git ahead "${branch}" "$FROM")
        BEHIND=$(git behind "${branch}" "$FROM")
        COMMIT_DATE=$(git log "${branch}" --pretty=format:"%ad" --date=short | head -1)
        TRACKING=$(git rev-parse --abbrev-ref --symbolic-full-name "${branch}@{u}" 2>/dev/null)
        if [ $? != 0 ] ; then
            TRACKING=" Upstream gone"
        else
            TRACKING=""
        fi
        echo "${branch}	-${BEHIND}	+${AHEAD} ${COMMIT_DATE} (${FROM})${TRACKING}"
    done

    """
    repository = require_repository()
    local_branches = get_local_branches()
    trackings = get_branch_trackings()
    all_branches = local_branches
    filtered_branches = local_branches
    bare_remote_branches: dict[str, str] = {}

    remote_to_branches = get_remote_to_branches(repository)
    for remote_name, remote_branches in remote_to_branches.items():
        all_branches = all_branches + remote_branches
        prefix = f"{remote_name}/"
        for remote_branch in remote_branches:
            bare_remote_branches[remote_branch] = remote_branch.removeprefix(prefix)
        if show_remotes:
            filtered_branches = filtered_branches + remote_branches
    remote_branches = list(bare_remote_branches.keys())
    main = get_main()
    if main is None:
        main = "main"
    develop = get_git_flow_develop()
    if develop is None or develop not in local_branches:
        develop = main
    for branch in filtered_branches:
        branch_from = None
        bare_branch = bare_remote_branches.get(branch, branch)
        if bare_branch != branch:
            branch_from = None
        elif bare_branch.startswith("feature/") and bare_branch != develop:
            branch_from = develop
        elif branch in trackings:
            branch_from = trackings[branch]
        elif bare_branch in trackings:
            branch_from = trackings[bare_branch]
        ahead: str | int | None = None
        behind: str | int | None = None
        if branch_from is None or branch_from not in all_branches:
            ahead = ""
            behind = ""
        else:
            commit_counts = count_commits(branch, branch_from)
            behind = commit_counts.behind
            ahead = commit_counts.ahead
        commit_date = get_ref_date(branch)
        if branch_from is None:
            if branch_from in remote_branches:
                branch_from = ""
            else:
                branch_from = "upstream gone"
        elif branch_from not in all_branches:
            branch_from = f"{branch_from} : upstream gone!"
        print(f"{branch}\t-{behind}\t+{ahead}\t{commit_date}\t({branch_from})")


class GitBranchesMain(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument(
            "--include-remote",
            dest="include_remote",
            action="store_true",
            default=False,
            help="Also look at remotes for branches",
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
        branches(self.args.include_remote)


def main():
    GitBranchesMain().main()


if __name__ == "__main__":
    main()
