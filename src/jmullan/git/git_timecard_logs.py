#!/usr/bin/env python3.13
import logging
import pathlib
import re
import sys
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from jmullan.cmd import cmd
from jmullan.logging import easy_logging
from pygit2.enums import SortMode

from jmullan.git.utils import first_empty_as_none, get_repository, run

logger = logging.getLogger(__name__)

OK_EMAILS = {
    "jmullan@rdio.com",
    "jesse.mullan@rd.io",
    "jmullan@pandora.com",
    "jmullan@siriusxm.com",
    "jesse.mullan@siriusxm.com"
}


def last_two_segments(url: str | None) -> str | None:
    if url is None:
        return None
    if "://" in url:
        path = urlparse(url).path
    else:
        # git@host:owner/repo.git
        path = "/" + url.split(":", 1)[1]

    parts = pathlib.PurePosixPath(path.removesuffix(".git")).parts
    return "/".join(parts[-2:])


def clean_message(message):
    if message is None:
        return ""
    message = message.strip()
    message = re.sub(r"pull request", "PR", message, flags=re.IGNORECASE)
    message = re.sub(r"\*? *commit '[a-f0-9]+'", "", message, flags=re.IGNORECASE)
    message = re.sub(r"(Merge PR #[0-9]+) in [-_/A-Za-z0-9]+ ", r"\1 ", message, flags=re.IGNORECASE)
    if message == "":
        return ""
    first_line = None
    for line in message.splitlines():
        stripped_line = line.strip()
        line_words = re.split(r"\s+", stripped_line)
        if len(line_words) == 0:
            continue
        first_line = " ".join(line_words)
    if first_line is not None and len(first_line) > 100:
        return first_line

    words = re.split(r"\s+", message)
    message = ""
    for word in words:
        if len(message) + len(word) < 160:
            message = f"{message} {word}".strip()
        else:
            break
    return message


class GitTimeCard(cmd.Main):
    def __init__(self):
        super().__init__()
        self.parser.add_argument("--email")

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

        candidates = []
        for name in ("origin/main", "origin/master", "main", "master"):
            try:
                ref = repo.lookup_reference(f"refs/heads/{name}")
            except KeyError:
                continue

            commit = repo[ref.target]
            candidates.append((commit.commit_time, ref))
        if candidates:
            _, tip = max(candidates)
        else:
            tip = repo.head

        try:
            remote_url = repo.remotes["origin"].url
            repo_name = last_two_segments(remote_url)
        except KeyError:
            repo_name = None
        if repo_name is None:
            repo_name = pathlib.Path(repo.workdir).name

        logger.info(repo_name)
        branch_name = tip.shorthand
        # log_file_setting = first_empty_as_none(run("git", "config", "timecard.filename"))
        log_file_setting = "~/.git_history.commits"
        if log_file_setting is None:
            return
        log_file_path = pathlib.Path(log_file_setting).expanduser()
        commit_count = 0
        for commit in repo.walk(tip.target, SortMode.TIME | SortMode.REVERSE):
            author_email = commit.author.email.lower()
            if author_email not in OK_EMAILS:
                continue
            tz = timezone(timedelta(minutes=commit.author.offset))
            dt = datetime.fromtimestamp(commit.author.time, tz)

            match = re.match(
                r"Merge pull request #(?P<PR>[0-9]+) in [^ ]+ from (?P<from_branch>[^ ]+) to (?P<to_branch>[^ ]+)",
                commit.message
            )
            if match:
                pull_request_number = match.group("PR")
                from_branch = match.group("from_branch")
                to_branch = match.group("to_branch")
                branch_name = from_branch
                prefix = f"Merge PR #{pull_request_number} to {to_branch}"
                message = commit.message.replace(match.group(0), "")
                message = f"{prefix} {message}"
            else:
                message = commit.message


            message = clean_message(message)

            line = f"{dt:%Y-%m-%d %H:%M:%S} {repo_name} {branch_name} commit-msg {message}"

            commit_count += 1
            # print(line)
            with log_file_path.open("a") as handle:
                handle.write(f"{line}\n")
        logger.info(f"Found {commit_count} commit messages")

def main():
    GitTimeCard().main()


if __name__ == "__main__":
    main()
