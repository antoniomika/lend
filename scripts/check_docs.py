#!/usr/bin/env python3
"""Check the generated docs without contacting external sites."""

import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []
        self.errors = []
        self.has_title = False
        self.has_description = False
        self.h1_count = 0
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            if attrs["id"] in self.ids:
                self.errors.append(f'duplicate ID: {attrs["id"]}')
            self.ids.add(attrs["id"])
        if tag == "title":
            self.has_title = True
        if tag == "h1":
            self.h1_count += 1
        if tag == "meta" and attrs.get("name") == "description":
            self.has_description = bool(attrs.get("content"))
        for key in ("href", "src"):
            if attrs.get(key):
                self.links.append(attrs[key])


def main():
    root = Path(__file__).resolve().parents[1] / "docs/public"
    files = sorted(root.glob("*.html"))
    if not (root / "index.html").is_file() or len(files) < 2:
        raise SystemExit("Build the docs with make ssg before checking them.")
    pages = {path: Page(path.read_text()) for path in files}
    errors = []
    links = 0
    for path, page in pages.items():
        problems = page.errors[:]
        if not page.has_title or not page.has_description:
            problems.append("missing page title or description")
        if page.h1_count != 1:
            problems.append(f"expected one h1, found {page.h1_count}")
        if "main" not in page.ids:
            problems.append("missing main content target")
        for link in page.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            links += 1
            relative = unquote(url.path)
            if not relative:
                target = path
            elif relative.startswith("/"):
                target = root / relative.lstrip("/")
            else:
                target = path.parent / relative
            target = target.resolve()
            if not target.is_relative_to(root):
                problems.append(f"link leaves site: {link}")
                continue
            if target.is_dir():
                target /= "index.html"
            if not target.is_file():
                problems.append(f"missing local target: {link}")
                continue
            if url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
                problems.append(f"missing fragment: {link}")
        errors.extend(f"{path.name}: {problem}" for problem in problems)
    for path in (root / "examples").glob("*.json"):
        json.loads(path.read_text())
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Checked {len(pages)} pages and {links} local links, including fragments and assets.")


if __name__ == "__main__":
    main()
