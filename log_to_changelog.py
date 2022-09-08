#!python3.10
import re
import sys
from argparse import ArgumentParser
from typing import List, Optional, Tuple

_ignores = [
    '* commit',
    '[Gradle Release Plugin] - new version commit:',
    '[Gradle Release Plugin] - pre tag commit',
    'Merge pull request #',
    'git-p4',
    'integrating changelist',
    'integrate changelist',
    'Integrate changelist',
    'Squashed commit',
    'Merge master',
    'merge to master'
]

_ignore_matches = [
    r'^ *This reverts commit *[a-z0-9]{40}\. *$',
    r'^ *commit *[a-z0-9]{40} *$',
    r'^ *Author: .*',
    r'^ *Date: .*',
    r'^ *Merge: [a-z0-9]+ [a-z0-9]+ *$',
    r'^ *Merge branch .* into .*',
    r"Merge branch '[^']+' of",
    r'^ *\.\.\. *$',
    r'^ *\.\.\. and [0-9]+ more commits *$',
    r'Merge in'
]


STDERR_ENABLED = False


def stderr(line: Optional) -> None:
    if not STDERR_ENABLED:
        return
    if line is None:
        print("None\n", file=sys.stderr)
    else:
        print(f"{line}\n", file=sys.stderr)


def include_line(line: Optional[str]) -> bool:
    return (
        line is not None and
        not any(x in line for x in _ignores) and
        not any(re.search(regex, line) for regex in _ignore_matches)
    )


def test_include_line():
    includes = [
        "yes", "me", ""
    ]
    for line in includes:
        assert include_line(line)

    not_includes = [
        None, "", "* commit to ignore", "git-p4"
    ]
    for line in not_includes:
        assert not include_line(line)


def format_for_tag_only(commit: dict) -> str:
    line = commit["subject"]
    line = strip_line(line)
    for x in _ignores:
        line = line.replace(x, ' ')
    for x in _ignore_matches:
        line = re.sub(x, ' ', line)
    tags = commit["tags"] or []
    tags.sort(key=len, reverse=True)
    for tag in commit["tags"] or []:
        line = line.replace(tag, '')
    if not re.match(r"\w", line):
        line = ""
    line = re.sub(r'\s+', ' ', line)
    line = line.strip()
    line = add_jiras(line, commit["jiras"])
    return line


def strip_line(line: str) -> str:
    if line:
        line = line.strip()
        line = re.sub(r'^(\** *)*', '', line)
        line = re.sub(r'^(-* *)*', '', line)
        line = re.sub(r'^Pull request #[0-9]+: +', '', line, flags=re.IGNORECASE)
        line = re.sub(r'^feature/', '', line, flags=re.IGNORECASE)
        line = re.sub(r'^bugfix/', '', line, flags=re.IGNORECASE)
        return line


def add_star(line: Optional[str]) -> Optional[str]:
    line = strip_line(line)
    if line:
        return '* %s' % line


def format_jira(line) -> Optional[str]:
    if line:
        line = re.sub(r'\*\s*([A-Z]{4,}-[0-9]+)\s*[-:]?\s*', r'* \1 : ', line)
    return line


def test_include_line():
    expectations = {
        "* FOOBAR-1637 last": "* FOOBAR-1637 : last",
        "* BAZZ-2733 :     ": "* BAZZ-2733 : ",
        "* PIRATE-6206 - New ": "* PIRATE-6206 : New ",
        "* PIRATE-6206- New ": "* PIRATE-6206 : New ",
        "* PIRATE-6206 -New ": "* PIRATE-6206 : New ",
        "* PIRATE-6206-New ": "* PIRATE-6206 : New ",
    }
    for line, expected in expectations.items():
        assert expected == format_jira(line)



def extract_jiras(body):
    return list(set(re.findall("[A-Z]+-[0-9]+", body) or []))


def add_jiras(line: str, jiras: List[str]) -> str:
    if not line:
        return line
    has_jiras = extract_jiras(line)
    if has_jiras:
        return line
    missing_jiras = list(set([jira for jira in jiras if jira not in line]))
    if missing_jiras:
        jiras = ", ".join(missing_jiras)
        line = f"{jiras} : {line}"
    return line


def unique(items: List) -> List:
    seen = set()
    output = []
    for item in items or []:
        if item not in seen:
            output.append(item)
            seen.add(item)
    return output


def format_tags(tags: List[str]) -> str:
    if not tags:
        return ""
    tags = sorted(tags, key=best_tag)
    tags_line = ", ".join([f"`{tag}`" for tag in tags])
    return f"### tags: {tags_line}"


def best_tag(tag: str) -> Tuple[bool, bool, bool, int, str]:
    if tag is None:
        tag = ""
    has_snapshot = "SNAPSHOT" in tag
    has_semantic_version = bool(re.match(r'^[0-9]+(\.[0-9]+){1,2}$', tag))
    has_semantic_subversion = bool(re.match(r'^[0-9]+(\.[0-9]+){1,2}(-.*)?$', tag))
    return has_snapshot, not has_semantic_version, not has_semantic_subversion , len(tag), tag


def tags_to_release_version(tags: List[str], found_version) -> Optional[str]:
    semantic_versions = []
    semantic_subversions = []
    other_tags = []
    for tag in tags:
        if found_version and "SNAPSHOT" in tag:
            return None
        if re.match(r'^[0-9]+(\.[0-9]+){1,2}$', tag):
            semantic_versions.append(tag)
        elif re.match(r'^[0-9]+(\.[0-9]+){1,2}(-.*)?$', tag):
            semantic_subversions.append(tag)
        else:
            other_tags.append(tag)
    for candidates in [semantic_versions, semantic_subversions, other_tags]:
        if candidates:
            candidates.sort(key=best_tag)
            return candidates[0]


def format_body(body: Optional[str], jiras: List[str]) -> Optional[str]:
    if body is None:
        return None
    lines = body.rstrip().split("\n")
    lines = [line for line in lines if line is not None]
    lines = [add_jiras(line, jiras) for line in lines]
    lines = [add_star(line) for line in lines]
    lines = [format_jira(line) for line in lines]
    lines = [line for line in lines if line is not None]
    return "\n".join(lines)


def make_notes(release_version, commits):
    version_string = f'v {release_version}'.strip()

    release_note = []
    if commits:
        date = commits[0]["date"]
        if date:
            version_string = f'## {version_string} - {date}'.strip()
    release_note.append(version_string)
    # release_note.append('-' * len(version_string))

    release_notes = []
    tags = []
    for commit in commits:
        # release_notes.append(f"{commit['sha']} {commit['parents']}")
        subject = commit["subject"]
        tags.extend(commit["tags"])
        if tags:
            if not include_line(subject):
                commit_line = format_for_tag_only(commit)
                if commit_line and commit_line not in release_notes:
                    release_notes.append(format_tags(tags))
                    tags = []
                    release_notes.append(commit_line)
                continue
            else:
                release_notes.append(format_tags(tags))
                tags = []
        else:
            if not include_line(subject):
                stderr(f"- skipping {commit['subject']}")
                continue
        # release_notes.append(f"{commit['jiras']}")
        # release_notes.append(f"+ using {commit['subject']}")
        commit_line = format_body(subject, commit["jiras"])
        if commit_line and commit_line not in release_notes:
            release_notes.append(commit_line)
        body = format_body(commit["body"], commit["jiras"])
        if body:
            release_notes.append(body)
    if tags:
        release_notes.append(format_tags(tags))
    if release_notes:
        release_notes = '\n'.join(release_notes).split("\n")
        release_notes = unique(release_notes)
        release_note.append('\n'.join(release_notes))
        release_note.append('')
        return '\n'.join(release_note)


def clean_body(body: str):
    body = body.strip("\n")
    lines = body.split("\n")
    lines = [line.rstrip() for line in lines]
    lines = [line.strip("\n") for line in lines]
    lines = [line for line in lines if include_line(line)]
    output = "\n".join(lines)
    output = re.sub(r"\n+", "\n", output)
    return output.strip("\n")


def get_version(subject: str) -> Optional[str]:
    matches = re.search(r"pre tag commit.*'(.*)'", subject)
    if matches:
        return matches.group(1)


def main():
    """Turn a pandora git release log into a changelog"""
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose',
                        action='store_true', default=False,
                        help='verbose is more verbose')
    parser.add_argument('-t', '--tags', dest='tags',
                        action='store_true', default=False,
                        help='Use tags and other found versions')
    parser.add_argument('version', default='Current', nargs='?')
    args = parser.parse_args()
    options = args.__dict__

    content = sys.stdin.read()
    commits = content.split('\x00')
    commits_by_sha = {}
    for commit in commits:
        commit_data = {}
        if commit is None:
            continue
        if "\nbody" not in commit:
            continue
        header, body = commit.split("\nbody", 1)
        for line in header.split("\n"):
            key, value = line.split(" ", 1)
            commit_data[key] = value
        if not commit_data.get("sha"):
            continue
        tags = []
        heads = []
        refnames = commit_data.get("refnames")
        if refnames:
            refs = refnames.split(", ")
            for refname in refs:
                if refname.startswith("tag: "):
                    tags.append(refname[5:])
                else:
                    heads.append(refname)
        parents = commit_data.get("parents")
        if parents:
            commit_data["parent_shas"] = parents.split(" ")
        commit_data["tags"] = tags
        commit_data["heads"] = heads
        commit_data["jiras"] = extract_jiras(body)
        commit_data["maybe_jiras"] = []
        if "\n" in body:
            subject, body = body.split("\n", 1)
        else:
            subject, body = body, ""
        subject = subject.strip()
        body = clean_body(body)
        commit_data["subject"] = subject
        commit_data["body"] = body
        commit_data["full_body"] = f"{subject}\n{body}".strip()
        commits_by_sha[commit_data["sha"]] = commit_data

    for sha, commit_data in commits_by_sha.items():
        commit_data["parent_commits"] = []
        parent_shas = commit_data.get("parent_shas") or []
        is_merge_to_master = bool(re.search('Merge.*to master', commit_data["subject"]))
        if is_merge_to_master and len(parent_shas) in (1, 2):
            parent_sha = parent_shas[-1]
            parent = commits_by_sha.get(parent_sha)

            if parent is not None:
                shares_subject = commit_data["subject"] in parent["full_body"]

                if not parent["jiras"]:
                    if is_merge_to_master or shares_subject:
                        # print(f"adding {commit_data['jiras']} from child {sha} to {parent_sha}")
                        parent["jiras"].extend(commit_data["jiras"])
                    else:
                        parent["maybe_jiras"].extend(commit_data["jiras"])
                elif not commit_data["jiras"]:

                    # print(f"adding {commit_data['jiras']} from parent {parent_sha} to {sha}")
                    if is_merge_to_master or shares_subject:
                        commit_data["jiras"].extend(parent["jiras"])
                    else:
                        commit_data["maybe_jiras"].extend(parent["jiras"])
                commit_data["parent_commits"].append(parent)

    release_commits = {}
    releases = []
    release_version = options.get('version') or 'Unknown'
    release_commits[release_version] = []
    releases.append(release_version)

    use_tags = options.get("tags") or False
    found_version = False
    for sha, commit in commits_by_sha.items():
        version = get_version(commit["subject"])
        commit_tags = commit["tags"]
        if version:
            release_version = version
            releases.append(release_version)
            release_commits[release_version] = []
            found_version = True
        elif use_tags and commit_tags:
            candidate_version = tags_to_release_version(commit_tags, found_version)
            if candidate_version:
                release_version = candidate_version
                releases.append(release_version)
                release_commits[release_version] = []

        release_commits[release_version].append(commit)

    changes = []
    for release_version in releases:
        commits = release_commits.get(release_version) or []
        if not commits:
            continue
        notes = make_notes(release_version, commits)
        if notes:
            changes.append(notes)

    if changes:
        # changes = reversed(changes)
        print('\n'.join(changes))


if __name__ == "__main__":
    main()
