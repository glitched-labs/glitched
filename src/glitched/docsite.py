"""
The docs site: docs/*.md as a static website - a section navigation on the left, the
page in the middle, "On this page" on the right, and search (press /).

    python -m glitched.docsite build [--out site] [--base /docs/]   # write the site
    python -m glitched.docsite serve [--port 8001]                  # preview it, rebuilt on each page load

The pages and their order come from docs/nav.toml. Links between Markdown files become
links between pages; links to anything else in the repository go to it on GitHub (`repo`
in nav.toml). It's built with --base /docs/ by default, so another app can serve it under
/docs. Everything it needs is in the output folder: no fonts, scripts or styles from
anywhere else, so it works under a strict Content-Security-Policy.
"""

from __future__ import annotations

import argparse
import html
import json
import posixpath
import re
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
ASSETS = Path(__file__).resolve().parent / "docsite_assets"
FONT = ASSETS / "InterVariable.woff2"
REPO = "https://github.com/glitched-labs/glitched/blob/main"  # unless nav.toml says otherwise (repo = "...")


@dataclass
class Page:
    file: str            # relative to docs/, e.g. "decisions/0001-....md"
    title: str
    section: str
    slug: str            # "" for the home page, else e.g. "cli" or "decisions/0001-..."
    html: str = ""
    toc: list[dict] = field(default_factory=list)
    heading: str = ""

    def url(self, base: str) -> str:
        return f"{base}{self.slug}/" if self.slug else base


def repo_url(docs: Path = DOCS) -> str:
    """Where "View this page's source" and links to other repository files go (nav.toml's `repo`)."""
    return tomllib.loads((docs / "nav.toml").read_text()).get("repo", REPO).rstrip("/")


def load_nav(docs: Path = DOCS) -> list[Page]:
    nav = tomllib.loads((docs / "nav.toml").read_text())
    pages = []
    for section in nav["section"]:
        for entry in section["pages"]:
            file = entry["file"]
            slug = "" if file == "index.md" else file.removesuffix(".md")
            pages.append(Page(file, entry.get("title", ""), section["title"], slug))
    return pages


def _markdown():
    import markdown

    return markdown.Markdown(extensions=["extra", "sane_lists", "toc", "codehilite", "admonition"], extension_configs={
        "toc": {"permalink": "#", "permalink_class": "anchor", "permalink_title": "Link to this section", "toc_depth": "2-3"},
        "codehilite": {"guess_lang": False, "css_class": "highlight"},
    })


def _rewrite_links(body: str, page: Page, by_file: dict[str, Page], base: str, repo: str = REPO) -> str:
    """Links to other Markdown pages become site links; anything else in the repository, a GitHub link."""
    here = posixpath.dirname(page.file)

    def fix(match: re.Match) -> str:
        href = html.unescape(match[1])
        if re.match(r"^[a-z][a-z0-9+.-]*:|^#|^/", href):
            return match[0]  # absolute, another site, or this page
        path, _, frag = href.partition("#")
        target = posixpath.normpath(posixpath.join("docs", here, path))
        doc = target.removeprefix("docs/")
        if doc in by_file:
            url = by_file[doc].url(base)
        else:
            url = f"{repo}/{target}"
        return f'href="{html.escape(url + (f"#{frag}" if frag else ""), quote=True)}"'

    return re.sub(r'href="([^"]+)"', fix, body)


def render_pages(pages: list[Page], base: str, docs: Path = DOCS) -> None:
    by_file = {p.file: p for p in pages}
    repo = repo_url(docs)
    for page in pages:
        md = _markdown()
        text = (docs / page.file).read_text()
        body = md.convert(text)
        heading = re.search(r"^#\s+(.+)$", text, re.M)
        page.heading = heading[1].strip().replace("`", "") if heading else page.title
        page.title = page.title or page.heading
        page.toc = [{"id": t["id"], "name": html.unescape(t["name"]), "children": [
                     {"id": c["id"], "name": html.unescape(c["name"])} for c in t.get("children", [])]}
                    for top in md.toc_tokens for t in (top.get("children", []) if top["level"] == 1 else [top])]
        body = _rewrite_links(body, page, by_file, base, repo)
        # Tables scroll on their own on a narrow screen, rather than the page.
        page.html = body.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")


def _nav_html(pages: list[Page], current: Page, base: str) -> str:
    out, section = [], None
    for page in pages:
        if page.section != section:
            if section is not None:
                out.append("</ul></li>")
            section = page.section
            out.append(f'<li class="nav-section"><span class="nav-section-title">{html.escape(section)}</span><ul>')
        here = ' aria-current="page"' if page is current else ""
        out.append(f'<li><a href="{page.url(base)}"{here}>{html.escape(page.title)}</a></li>')
    out.append("</ul></li>")
    return f'<ul class="nav-list">{"".join(out)}</ul>'


def _toc_html(page: Page) -> str:
    if not page.toc:
        return ""
    items = []
    for t in page.toc:
        children = "".join(f'<li><a href="#{c["id"]}">{html.escape(c["name"])}</a></li>' for c in t["children"])
        items.append(f'<li><a href="#{t["id"]}">{html.escape(t["name"])}</a>{f"<ul>{children}</ul>" if children else ""}</li>')
    return f'<nav class="toc" aria-label="On this page"><p class="toc-title">On this page</p><ul>{"".join(items)}</ul></nav>'


def _top_links(links: list[dict], base: str) -> str:
    """The header's links (nav.toml's `top`): a page path under the site, or a full address."""
    out = []
    for link in links:
        url = link["url"] if re.match(r"^(https?:)?/", link["url"]) else f"{base}{link['url']}"
        out.append(f'<a href="{html.escape(url, quote=True)}">{html.escape(link["title"])}</a>')
    return "".join(out)


def _page_html(page: Page, pages: list[Page], base: str, repo: str = REPO, top: list[dict] | None = None,
               footer: list[dict] | None = None, footer_note: str = "") -> str:
    i = pages.index(page)
    prev_page, next_page = (pages[i - 1] if i else None), (pages[i + 1] if i + 1 < len(pages) else None)
    pager = "".join([
        f'<a class="pager-prev" href="{prev_page.url(base)}"><span>Previous</span>{html.escape(prev_page.title)}</a>' if prev_page else "<span></span>",
        f'<a class="pager-next" href="{next_page.url(base)}"><span>Next</span>{html.escape(next_page.title)}</a>' if next_page else "",
    ])
    title = "Glitched docs" if not page.slug else f"{page.heading} · Glitched docs"
    top = _top_links(top or [], base)
    footer = _top_links(footer or [], base)  # the same kind of links, on the right of the footer
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="{base}_assets/docs.css">
<link rel="preload" href="{base}_assets/InterVariable.woff2" as="font" type="font/woff2" crossorigin>
<script src="{base}_assets/docs.js" defer></script>
</head>
<body data-base="{base}">
<header class="topbar">
  <button type="button" class="nav-toggle" aria-controls="sidebar" aria-expanded="false">Menu</button>
  <a class="brand" href="{base}">glitched <span>docs</span></a>
  <nav class="top-links" aria-label="Glitched">{top}</nav>
  <button type="button" class="search-button" aria-label="Search the docs (press /)">
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="m11 11 3.5 3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
    <span>Search documentation</span><kbd>/</kbd>
  </button>
</header>
<div class="layout">
  <aside class="sidebar" id="sidebar" aria-label="Documentation">{_nav_html(pages, page, base)}</aside>
  <main class="content">
    <article class="doc">{page.html}</article>
    <nav class="pager" aria-label="Previous and next">{pager}</nav>
    <footer class="site-footer">
      <span class="footer-note">{html.escape(footer_note)}</span>
      <nav class="footer-links" aria-label="Links">{footer}<a href="{repo}/docs/{page.file}">Edit this page</a></nav>
    </footer>
  </main>
  <aside class="toc-column">{_toc_html(page)}</aside>
</div>
</body>
</html>
"""


def _search_index(pages: list[Page], base: str) -> list[dict]:
    """One entry per section of each page (split at headings), with its words, for the search box."""
    out = []
    for page in pages:
        parts = re.split(r'(<h[23] id="[^"]+">.*?</h[23]>)', page.html, flags=re.S)
        anchor, heading = "", page.title
        for part in parts:
            m = re.match(r'<h[23] id="([^"]+)">(.*?)</h[23]>', part, re.S)
            if m:
                anchor, heading = m[1], re.sub(r"<[^>]+>", "", m[2]).replace("#", "").strip()
                continue
            text = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", part))).strip()
            if text or anchor:
                out.append({"page": page.title, "heading": html.unescape(heading), "url": page.url(base) + (f"#{anchor}" if anchor else ""),
                            "text": text[:2000]})
    return out


def _highlight_css() -> str:
    from pygments.formatters import HtmlFormatter

    light = HtmlFormatter(style="default").get_style_defs(".highlight")
    dark = HtmlFormatter(style="github-dark").get_style_defs(":root[data-theme=dark] .highlight")
    dark_auto = HtmlFormatter(style="github-dark").get_style_defs(":root:not([data-theme=light]) .highlight")
    keep = lambda css: "\n".join(line for line in css.splitlines() if " .hll" not in line and "background:" not in line.split("{")[0])  # noqa: E731
    return (f"/* Code: Pygments (light), github-dark (dark) */\n{keep(light)}\n{keep(dark)}\n"
            f"@media (prefers-color-scheme: dark) {{\n{keep(dark_auto)}\n}}\n")


def build(out: Path, base: str = "/docs/", docs: Path = DOCS) -> list[Page]:
    if not base.startswith("/") or not base.endswith("/"):
        raise ValueError("--base must start and end with / (like /docs/)")
    pages = load_nav(docs)
    nav = tomllib.loads((docs / "nav.toml").read_text())
    render_pages(pages, base, docs)
    if out.exists():
        shutil.rmtree(out)
    (out / "_assets").mkdir(parents=True)
    for page in pages:
        target = out / page.slug / "index.html" if page.slug else out / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_page_html(page, pages, base, repo_url(docs), nav.get("top", []), nav.get("footer", []),
                                     nav.get("footer_note", "")))
    for name in ("docs.css", "docs.js"):
        shutil.copy(ASSETS / name, out / "_assets" / name)
    with (out / "_assets" / "docs.css").open("a") as css:
        css.write("\n" + _highlight_css())
    shutil.copy(FONT, out / "_assets" / "InterVariable.woff2")
    (out / "_assets" / "search.json").write_text(json.dumps(_search_index(pages, base), separators=(",", ":")))
    # A "not found" page in the same frame (static hosts such as GitHub Pages serve 404.html).
    home = (out / "index.html").read_text()
    start, end = home.index('<article class="doc">'), home.index("</article>") + len("</article>")
    missing = (home[:start] + f'<article class="doc"><h1>Page not found</h1><p>There\'s no page at this address. '
               f'Try the <a href="{base}">docs home</a>, or press <kbd>/</kbd> to search.</p></article>' + home[end:])
    missing = re.sub(r'<nav class="pager".*?</nav>', "", missing, flags=re.S)
    missing = re.sub(r'<nav class="toc".*?</nav>', "", missing, flags=re.S)
    missing = missing.replace(' aria-current="page"', "").replace("<title>Glitched docs</title>", "<title>Page not found · Glitched docs</title>")
    (out / "404.html").write_text(missing)
    return pages


def serve(port: int, base: str = "/docs/") -> None:
    """A preview: rebuilt on every page load, so editing a .md file and reloading shows it."""
    import http.server
    import tempfile

    out = Path(tempfile.mkdtemp(prefix="glitched-docs-"))

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(out), **kwargs)

        def translate_path(self, path: str) -> str:
            path = path.split("?", 1)[0]
            if not path.startswith(base):
                return str(out / "__missing__")
            return super().translate_path("/" + path[len(base):])

        def do_GET(self):  # noqa: N802 - http.server's naming
            if self.path in ("/", ""):
                self.send_response(302)
                self.send_header("Location", base)
                self.end_headers()
                return
            if not self.path.startswith(f"{base}_assets/") or self.path.endswith("search.json"):
                build(out, base)
            super().do_GET()

        def log_message(self, *args):
            pass

    build(out, base)
    print(f"Docs preview: http://127.0.0.1:{port}{base}  (rebuilt on each page load; Ctrl+C to stop)")
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m glitched.docsite", description=__doc__.split("\n\n")[0].strip())
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="write the site")
    b.add_argument("--out", type=Path, default=ROOT / "site", help="where (default: site/)")
    b.add_argument("--base", default="/docs/", help="the path it's served under (default /docs/)")
    b.add_argument("--docs", type=Path, default=DOCS, help="the Markdown folder (default: docs/ in this checkout)")
    s = sub.add_parser("serve", help="preview it locally, rebuilt on each page load")
    s.add_argument("--port", type=int, default=8001)
    args = parser.parse_args(argv)
    if args.command == "build":
        pages = build(args.out, args.base, args.docs)
        print(f"wrote {len(pages)} pages to {args.out}")
    else:
        try:
            serve(args.port)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
