import logging
import os
import subprocess

import pygit2

logger = logging.getLogger(__name__)


def get_repository() -> pygit2.Repository | None:
    current_working_directory = os.getcwd()
    repository_path = pygit2.discover_repository(current_working_directory)
    if repository_path is not None:
        return pygit2.Repository(repository_path)
    else:
        return None


def run(*args: str) -> list[str]:
    if (len(args)) == 1 and " " in args[0]:
        return run(*(args[0].split(" ")))
    logger.debug("Running %s", " ".join(args))
    with subprocess.Popen(args, stdout=subprocess.PIPE) as proc:
        return proc.stdout.read().decode("UTF8").strip().split("\n")


def first(strings: list[str]) -> str:
    for line in (strings or []):
        if len(line):
            return line
    return ""


def dump_reference(message: str, reference: pygit2.Reference):
    logger.debug(f"""{message}
            {reference.name=}
            {reference.shorthand=}
            {reference.target=}
        """)



def rev_parse(ref_name: str) -> str | None:
    return first(run(f"git rev-parse --abbrev-ref --symbolic-full-name {ref_name}"))
