#!/usr/bin/env python3.11
import re
import sys
from argparse import ArgumentParser
from typing import Dict, List, Optional, Tuple

_ignores = [
    "* commit",
    "[Gradle Release Plugin] - new version commit:",
    "[Gradle Release Plugin] - pre tag commit",
    "Merge pull request #",
    "git-p4",
    "integrating changelist",
    "integrate changelist",
    "Integrate changelist",
    "Squashed commit",
    "Merge master",
    "merge to master",
]

_ignore_matches = [
    r"^ *This reverts commit *[a-z0-9]{40}\. *$",
    r"^ *commit *[a-z0-9]{40} *$",
    r"^ *Author: .*",
    r"^ *Date: .*",
    r"^ *Merge: [a-z0-9]+ [a-z0-9]+ *$",
    r"^ *Merge branch .* into .*",
    r"^ *Merge branch '.*'$",
    r"Merge branch '[^']+' of",
    r"^ *\.\.\. *$",
    r"^ *\.\.\. and [0-9]+ more commits *$",
    r"Merge in",
]

STDERR_ENABLED = False
INVALID_NAMES = {"jenkins", "mobileautomation"}


def stderr(line: Optional) -> None:
    if not STDERR_ENABLED:
        return
    if line is None:
        print("None\n", file=sys.stderr)
    else:
        print(f"{line}\n", file=sys.stderr)


def include_line(line: Optional[str]) -> bool:
    return (
        line is not None
        and not any(x in line for x in _ignores)
        and not any(re.search(regex, line) for regex in _ignore_matches)
    )


def test_include_line():
    includes = ["yes", "me", ""]
    for line in includes:
        assert include_line(line)

    not_includes = [
        None,
        "* commit to ignore",
        "git-p4",
        "Merge branch 'CONTIN-5792-refactor-backfill'",
    ]
    for line in not_includes:
        assert not include_line(line)


def format_for_tag_only(commit: dict) -> str:
    line = commit["subject"]
    line = strip_line(line)
    for x in _ignores:
        line = line.replace(x, " ")
    for x in _ignore_matches:
        line = re.sub(x, " ", line)
    tags = commit["tags"] or []
    tags.sort(key=len, reverse=True)
    for tag in commit["tags"] or []:
        line = line.replace(tag, "")
    if not re.match(r"\w", line):
        line = ""
    line = re.sub(r"\s+", " ", line)
    line = line.strip()
    line = add_jiras(line, commit["jiras"])
    return line


def strip_line(line: str) -> str:
    if line:
        line = line.strip()
        line = re.sub(r"^(\** *)*", "", line)
        line = re.sub(r"^(-* *)*", "", line)
        line = re.sub(r"^Pull request #[0-9]+: +", "", line, flags=re.IGNORECASE)
        line = re.sub(r"^feature/", "", line, flags=re.IGNORECASE)
        line = re.sub(r"^bugfix/", "", line, flags=re.IGNORECASE)
        return line


def add_star(line: Optional[str]) -> Optional[str]:
    line = strip_line(line)
    if line:
        return "* %s" % line


def format_jira(line) -> Optional[str]:
    if line:
        jiras = extract_jiras(line)
        if jiras:
            for jira in jiras:
                line = line.replace(jira, "")
            line = re.sub(r"^\W+", "", line)
            jiras = ", ".join(sorted(jiras))
            if len(line):
                line = f"* {jiras} : {line}"
            else:
                line = f"* {jiras}"
    return line


def test_format_jira():
    expectations = {
        "* FOOBAR-1637 last": "* FOOBAR-1637 : last",
        "* BAZZ-2733 :     ": "* BAZZ-2733",
        "* PIRATE-6206 - New ": "* PIRATE-6206 : New ",
        "* PIRATE-6206- New ": "* PIRATE-6206 : New ",
        "* PIRATE-6206 -New ": "* PIRATE-6206 : New ",
        "* PIRATE-6206-New ": "* PIRATE-6206 : New ",
        "* LEAF-5410, LEAF-5316 :   More cleanup, tests": "* LEAF-5316, LEAF-5410 : More cleanup, tests",
        "* A-5316, B-5316 : sorting": "* A-5316, B-5316 : sorting",
        "* B-5316, A-5316 : sorting": "* A-5316, B-5316 : sorting",
        "* LEAF-5410 :   More cleanup, LEAF-5316 ,tests": "* LEAF-5316, LEAF-5410 : More cleanup,  ,tests",
    }
    for line, expected in expectations.items():
        assert format_jira(line) == expected


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
    has_semantic_version = bool(re.match(r"^[0-9]+(\.[0-9]+){1,2}$", tag))
    has_semantic_subversion = bool(re.match(r"^[0-9]+(\.[0-9]+){1,2}(-.*)?$", tag))
    return (
        has_snapshot,
        not has_semantic_version,
        not has_semantic_subversion,
        len(tag),
        tag,
    )


def tags_to_release_version(tags: List[str], found_version) -> Optional[str]:
    semantic_versions = []
    semantic_sub_versions = []
    other_tags = []
    for tag in tags:
        if found_version and "SNAPSHOT" in tag:
            return None
        if re.match(r"^[0-9]+(\.[0-9]+){1,2}$", tag):
            semantic_versions.append(tag)
        elif re.match(r"^[0-9]+(\.[0-9]+){1,2}(-.*)?$", tag):
            semantic_sub_versions.append(tag)
        else:
            other_tags.append(tag)
    for candidates in [semantic_versions, semantic_sub_versions, other_tags]:
        if candidates:
            candidates.sort(key=best_tag)
            return candidates[0]


def format_body(body: Optional[str], jiras: List[str]) -> Optional[str]:
    if body is None:
        return None
    lines = body.rstrip().split("\n")
    lines = [line for line in lines if include_line(line)]
    lines = [line for line in lines if line is not None]
    lines = [add_jiras(line, jiras) for line in lines]
    lines = [add_star(line) for line in lines]
    lines = [format_jira(line) for line in lines]
    lines = [line for line in lines if line is not None]
    return "\n".join(lines)


def valid_name(name: Optional[str]) -> bool:
    if name is None:
        return False
    name = name.strip()
    if len(name) < 1:
        return False
    name = name.lower()
    if "jenkins builder" in name:
        return False
    if name in INVALID_NAMES:
        return False
    return True


def format_names(commits: List) -> Optional[str]:
    if not commits:
        return None
    names = set(commit["name"] for commit in commits if valid_name(commit["name"]))
    if not names:
        return None
    return ", ".join(sorted(names))


def make_version_line(release_version: str, commits: List) -> str:
    version_string = f"{release_version}".strip()

    if commits:
        first_commit = commits[0]
        date = first_commit["date"]
        if not date.startswith(version_string):
            return f"## v {version_string} ({date})".strip()
        else:
            return f"### {version_string}"


def format_commit(commit: Dict) -> List[str]:
    subject = commit["subject"]
    if not include_line(subject):
        return []

    commit_lines = []
    subject_line = format_body(subject, commit["jiras"])
    if subject_line:
        commit_lines.append(subject_line)
    body = format_body(commit["body"], commit["jiras"])
    if body:
        commit_lines.append(body)
    return commit_lines


def make_notes(release_version: str, commits: List[Dict]):
    release_note = [make_version_line(release_version, commits)]
    tags_notes = []

    commits_by_tag = {}
    current_tag = ""
    for commit in commits:
        if commit["tags"]:
            current_tag = format_tags(commit["tags"])
        if current_tag not in commits_by_tag:
            commits_by_tag[current_tag] = []
        commits_by_tag[current_tag].append(commit)

    for tags, tag_commits in commits_by_tag.items():
        if len(tags):
            tags_notes.append(tags)
        formatted_names = format_names(tag_commits)
        if formatted_names is not None:
            tags_notes.append(formatted_names)
        for commit in tag_commits:
            commit_lines = format_commit(commit)
            if len(commit_lines):
                tags_notes.extend(commit_lines)

    if tags_notes:
        tags_notes = "\n".join(tags_notes).split("\n")
        tags_notes = unique(tags_notes)
        release_note.append("\n".join(tags_notes))
        release_note.append("")
        return "\n".join(release_note)


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


def is_merge_to_main(commit_data):
    return bool(re.search("Merge.*to (master|main)", commit_data["subject"]))


def prune_heads(heads: List[str]) -> List[str]:
    new_heads = []
    for head in heads:
        if head.startswith("HEAD ->"):
            head = head[8:]
        elif head.endswith("/HEAD"):
            head = head[:-5]
        if head:
            new_heads.append(head)
    return new_heads


def extract_refs(commit_data: Dict) -> Dict[str, List[str]]:
    sha = commit_data["sha"]
    parent_shas = commit_data.get("parent_shas") or []
    heads = commit_data.get("heads") or []
    heads = prune_heads(heads)
    shas_to_refs = {sha: heads}

    merge_matches = re.search(
        r"Merge .* from ([^ ]+) to ([^ ]+)$", commit_data["subject"]
    )
    if merge_matches:
        from_ref = merge_matches.group(1)
        to_ref = merge_matches.group(2)
        if parent_shas and len(parent_shas) == 2:
            left, right = parent_shas
            stderr(f"{sha} : {right} {from_ref} + {left} {to_ref}")
            if right not in shas_to_refs:
                shas_to_refs[right] = []
            shas_to_refs[right].append(from_ref)
            if left not in shas_to_refs:
                shas_to_refs[left] = []
            shas_to_refs[left].append(to_ref)
    return shas_to_refs


def test_extract_refs():
    commit_data = {"sha": "abcd", "subject": ""}
    refs = extract_refs(commit_data)
    assert {"abcd": []} == refs

    commit_data = {
        "sha": "abcd",
        "parent_shas": ["aaaa", "bbbb"],
        "tags": [],
        "heads": [],
        "subject": "Pull request #21: anything",
    }
    refs = extract_refs(commit_data)
    assert {"abcd": []} == refs

    commit_data = {
        "sha": "abcd",
        "parent_shas": [
            "aaaa",
            "bbbb",
        ],
        "tags": [],
        "heads": [],
        "subject": "Merge branch 'feature/branch_name'",
    }
    refs = extract_refs(commit_data)
    assert {"abcd": []} == refs

    commit_data = {
        "sha": "abcd",
        "parent_shas": [
            "aaaa",
            "bbbb",
        ],
        "tags": [],
        "heads": [],
        "subject": "Merge pull request #1 in anything from branch_name to master",
    }
    refs = extract_refs(commit_data)
    assert {"abcd": []} == refs


def print_tree(commits_by_sha: Dict[str, Dict], refs_by_sha: Dict[str, List[str]]):
    if not commits_by_sha:
        return
    head = list(commits_by_sha.keys())[0]
    current_branches = [head]
    seen = set()
    while current_branches:
        new_current_branches = []
        line = []
        for head in current_branches:
            if head in seen:
                continue
            seen.add(head)
            commit_data = commits_by_sha.get(head) or {}
            refs = refs_by_sha.get(head) or []
            node = ",".join(refs) or head[:8]
            line.append(node)
            new_current_branches.extend(commit_data.get("parent_shas") or [])
        current_branches = sorted(
            new_current_branches,
            key=lambda sha: commits_by_sha.get(sha, {}).get("date"),
        )
        print(" ".join(line))


def main():
    """Turn a pandora git release log into a changelog"""
    parser = ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="verbose is more verbose",
    )
    parser.add_argument(
        "-t",
        "--tags",
        dest="tags",
        action="store_true",
        default=False,
        help="Use tags and other found versions",
    )
    parser.add_argument(
        "-m",
        "--months",
        dest="months",
        action="store_true",
        default=False,
        help="Use months and other found versions",
    )
    parser.add_argument("version", default="Current", nargs="?")
    args = parser.parse_args()
    options = args.__dict__

    content = sys.stdin.read()
    commits = content.split("\x00")
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
            for reference_name in refs:
                if reference_name.startswith("tag: "):
                    tags.append(reference_name[5:])
                else:
                    heads.append(reference_name)
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

    shas_to_refs = {}
    child_shas = {}
    for sha, commit_data in commits_by_sha.items():
        if sha not in child_shas:
            child_shas[sha] = []
        for parent_sha in commit_data["parent_shas"]:
            if parent_sha not in child_shas:
                child_shas[parent_sha] = []
            child_shas[parent_sha].append(sha)
        commit_shas_to_refs = extract_refs(commit_data)
        for commit_sha, refs in commit_shas_to_refs.items():
            if refs:
                if commit_sha not in shas_to_refs:
                    shas_to_refs[commit_sha] = []
                shas_to_refs[commit_sha].extend(refs)
    for sha, commit_data in commits_by_sha.items():
        refs = shas_to_refs.get(sha) or []
        children = child_shas.get(sha) or []
        walked = []
        while not refs and len(children) == 1:
            child_sha = children[0]
            walked.append(child_sha)
            refs = shas_to_refs.get(child_sha)
            children = child_shas.get(child_sha) or []
        if refs:
            for child_sha in walked:
                if not shas_to_refs.get(child_sha):
                    shas_to_refs[child_sha] = refs
        parent_shas = commit_data.get("parent_shas") or []
        walked = []
        while not refs and len(parent_shas) == 1:
            parent_sha = parent_shas[0]
            walked.append(parent_sha)
            refs = shas_to_refs.get(parent_sha) or []
            parent = commits_by_sha.get(parent_sha) or {}
            parent_shas = parent.get("parent_shas") or []
        if refs:
            for parent_sha in walked:
                if not shas_to_refs.get(parent_sha):
                    shas_to_refs[parent_sha] = refs
        shas_to_refs[sha] = refs

    # print_tree(commits_by_sha, shas_to_refs)

    for sha, commit_data in commits_by_sha.items():
        commit_data["parent_commits"] = []
        parent_shas = commit_data.get("parent_shas") or []
        is_merge_to_master = is_merge_to_main(commit_data)
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
    release_version = options.get("version") or "Unknown"
    release_commits[release_version] = []
    releases.append(release_version)

    release_dates = {}

    use_tags = options.get("tags") or False
    use_months = options.get("months") or False
    found_version = False
    current_month = None
    for sha, commit in commits_by_sha.items():
        version = get_version(commit["subject"])
        commit_tags = commit["tags"]
        if version:
            release_version = version
            found_version = True
        elif use_tags and commit_tags:
            candidate_version = tags_to_release_version(commit_tags, found_version)
            if candidate_version:
                release_version = candidate_version
        elif use_months:
            candidate_version = commit["date"][:7]
            if candidate_version != current_month:
                # If there is an existing version, and we are after it, but in the same month
                # we do not want to change to a month
                release_version = candidate_version

        if release_version not in release_commits:
            releases.append(release_version)
            release_commits[release_version] = []
        release_commits[release_version].append(commit)
        current_month = commit["date"][:7]
        release_month = release_dates.get(release_version)
        if release_month is None or current_month > release_month:
            release_dates[release_version] = current_month

    changes = []
    for release_version in sorted(
        releases, key=lambda v: release_dates.get(v) or v, reverse=True
    ):
        commits = release_commits.get(release_version) or []
        if not commits:
            continue
        notes = make_notes(release_version, commits)
        if notes:
            changes.append(notes)

    if changes:
        # changes = reversed(changes)
        print("\n".join(changes))


if __name__ == "__main__":
    main()
