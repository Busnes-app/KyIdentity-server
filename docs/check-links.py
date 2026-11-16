#!/usr/bin/env python3
"""Check the built mdBook's local links and fragments using only the standard library."""

from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Page(HTMLParser):
    def __init__(self, path):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []
        self.feed(path.read_text(encoding="utf-8"))

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("name"):
            self.ids.add(attrs["name"])
        for attr in ("href", "src"):
            if attrs.get(attr):
                self.links.append(attrs[attr])


def main():
    book = Path(__file__).resolve().parent / "book"
    pages = {path.resolve(): Page(path) for path in book.rglob("*.html")}
    if not pages:
        raise SystemExit("No built documentation: run `mdbook build docs` first")

    errors = []
    checked = 0
    for source, page in pages.items():
        for link in page.links:
            try:
                url = urlsplit(link)
                if url.scheme or url.netloc:
                    continue
                path = unquote(url.path)
                target = ((book / path.lstrip("/")) if path.startswith("/") else source.parent / path).resolve() if path else source
                target.relative_to(book)
                if target.is_dir():
                    target /= "index.html"
                if not target.is_file():
                    raise ValueError("file does not exist")
                fragment = unquote(url.fragment)
                if fragment and target in pages and fragment not in pages[target].ids:
                    raise ValueError("fragment does not exist")
                checked += 1
            except ValueError as error:
                errors.append(f"{source.relative_to(book)}: {link}: {error}")

    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Documentation: {len(pages)} HTML pages, {checked} local links and fragments checked")


if __name__ == "__main__":
    main()
