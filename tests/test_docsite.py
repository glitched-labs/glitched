"""
The docs site (glitched.docsite): every page in docs/nav.toml builds, links between pages
work, nothing in it loads from anywhere else, and the console serves it at /docs.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

try:
    import markdown  # noqa: F401
    HAVE_MARKDOWN = True
except ImportError:
    HAVE_MARKDOWN = False

from glitched import docsite


@unittest.skipUnless(HAVE_MARKDOWN, "needs the markdown package (the docs or console extra)")
class DocsiteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = Path(tempfile.mkdtemp())
        cls.pages = docsite.build(cls.out, "/docs/")

    def test_every_page_in_the_nav_is_built_and_every_doc_is_in_the_nav(self):
        for page in self.pages:
            self.assertTrue((self.out / page.slug / "index.html").is_file() if page.slug else (self.out / "index.html").is_file())
        listed = {p.file for p in self.pages}
        on_disk = {str(p.relative_to(docsite.DOCS)) for p in docsite.DOCS.rglob("*.md")}
        self.assertEqual(on_disk - listed, set(), "a doc that isn't in docs/nav.toml won't be published")

    def test_links_between_pages_resolve(self):
        urls = {p.url("/docs/") for p in self.pages}
        for page in self.pages:
            text = (self.out / page.slug / "index.html" if page.slug else self.out / "index.html").read_text()
            for href in re.findall(r'href="(/docs/[^"#]*)', text):
                if not href.startswith("/docs/_assets/"):
                    self.assertIn(href, urls, f"{page.file} links to {href}, which isn't a page")
            stray = [h for h in re.findall(r'href="([^"]+\.md(?:#[^"]*)?)"', text) if not h.startswith("https://github.com/")]
            self.assertEqual(stray, [], f"{page.file} still links to a .md file")

    def test_self_contained(self):
        for path in self.out.rglob("*.html"):
            text = path.read_text()
            self.assertIsNone(re.search(r'<(script|link)[^>]+(src|href)="https?://', text), path)
            self.assertNotIn("<style", text)  # the console allows only its own stylesheets
            self.assertIsNone(re.search(r"<script>(?!</script>)", text))  # ... and scripts
        index = json.loads((self.out / "_assets" / "search.json").read_text())
        self.assertTrue(any(e["heading"] == "Exit codes" for e in index))

    def test_page_has_navigation_and_contents(self):
        text = (self.out / "cli" / "index.html").read_text()
        self.assertIn('aria-current="page">The command line</a>', text)
        self.assertIn('class="toc"', text)
        self.assertIn('href="/docs/cli-reference/"', text)


if __name__ == "__main__":
    unittest.main()
