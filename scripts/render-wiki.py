"""Render the tracked protocol and project guides into a GitHub Wiki checkout."""

import argparse
import json
import posixpath
import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote, urlsplit


CLIENTS = {"HyphenMiner": "Miner operations", "HyphenPool": "Pool accounting and payouts", "HyphenWallet": "Wallet operations"}
MANIFEST = ".hyphen-wiki-pages.json"
# Match inline code first so that examples of Markdown links remain literal.
INLINE = re.compile(r"(?P<ticks>`+).*?(?P=ticks)|(?P<start>!?\[[^\]\n]*\]\()(?P<url><[^>\n]+>|[^\s()]+)(?P<end>(?:\s+\"[^\"]*\")?\))")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def tracked_files(root):
    result = subprocess.check_output(["git", "-C", root, "ls-files", "-z"])
    return set(result.decode("utf-8").split("\0")) - {""}


def is_page(path):
    return PurePosixPath(path).parent == PurePosixPath("wiki") and path.endswith(".md")


def render_page(text, source, files, source_repo, wiki_base, names):
    def resolve(match):
        url = match["url"]
        if not url:
            return match[0]
        parts = urlsplit(url.strip("<>"))
        if parts.scheme or parts.netloc or not parts.path:
            return match[0]
        path = posixpath.normpath(posixpath.join("wiki", unquote(parts.path)))
        if path not in files:
            raise ValueError(f"{source_repo}/{source}: missing tracked link target {url}")
        if path in names:
            target = wiki_base + "/" + quote(names[path][:-3])
        else:
            target = f"https://github.com/HyphenTeam/{source_repo}/blob/main/{quote(path)}"
        if parts.query:
            target += "?" + parts.query
        if parts.fragment:
            target += "#" + parts.fragment
        return match["start"] + target + match["end"]

    lines = []
    fence = ""
    for line in text.splitlines(keepends=True):
        delimiter = FENCE.match(line)
        if fence:
            if delimiter and delimiter[1].startswith(fence) and not delimiter[2].strip():
                fence = ""
        elif delimiter:
            fence = delimiter[1]
        else:
            line = INLINE.sub(resolve, line)
        lines.append(line)
    if fence:
        raise ValueError(f"{source_repo}/{source}: unclosed code fence")
    return "".join(lines)


def publish_tree(protocol, client, project, output):
    base = f"https://github.com/HyphenTeam/{project}/wiki"
    sources = [("Hyphen", protocol)]
    if project in CLIENTS:
        sources.append((project, client))
    rendered = {}
    for repo, root in sources:
        files = tracked_files(root)
        names = {path: PurePosixPath(path).name for path in sorted(files) if is_page(path)}
        if "wiki/Home.md" not in names:
            raise ValueError(f"{repo} has no tracked wiki/Home.md")
        if project in CLIENTS and repo == "Hyphen":
            names["wiki/Home.md"] = "Protocol-Overview.md"
        for path, name in names.items():
            if name.casefold() in {existing.casefold() for existing in rendered}:
                raise ValueError(f"Duplicate wiki page: {name}")
            text = (root / path).read_text(encoding="utf-8")
            rendered[name] = render_page(text, path, files, repo, base, names)

    if project in CLIENTS:
        if "Operations.md" not in rendered:
            raise ValueError(f"{project} has no operations guide")
        rendered["_Sidebar.md"] = (
            f"### {project}\n\n- [Overview]({base}/Home)\n"
            f"- [{CLIENTS[project]}]({base}/Operations)\n\n" + rendered["_Sidebar.md"]
        )

    manifest = output / MANIFEST
    previous = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else []
    if not isinstance(previous, list) or not all(
        isinstance(n, str) and re.fullmatch(r"[\w-]+\.md", n) for n in previous
    ):
        raise ValueError(f"Invalid page inventory in {manifest}")
    for name in rendered:
        if not re.fullmatch(r"[\w-]+\.md", name):
            raise ValueError(f"Unsupported wiki page name: {name}")
    output.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (output / name).write_text(text, encoding="utf-8", newline="\n")
    for name in set(previous) - rendered.keys():
        (output / name).unlink(missing_ok=True)
    manifest.write_text(json.dumps(sorted(rendered), indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, choices=["Hyphen", *CLIENTS])
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--client", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.project in CLIENTS and args.client is None:
        parser.error("--client must point to the project's source checkout")
    publish_tree(args.protocol, args.client, args.project, args.output)
