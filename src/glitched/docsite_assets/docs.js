"use strict";
// The Glitched docs site: search (/ or ⌘K), light/dark, the "On this page" highlight,
// copy buttons on code, and the menu on a phone. No libraries.

const BASE = document.body.dataset.base || "/docs/";
const $ = (selector, root = document) => root.querySelector(selector);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) if (child !== null && child !== undefined) node.append(child);
  return node;
}

// -- light / dark: follows the system until you choose -------------------------------------
const THEME_KEY = "glitched-docs-theme";
function storedTheme() { try { return localStorage.getItem(THEME_KEY); } catch { return null; } }
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme; else delete document.documentElement.dataset.theme;
}
applyTheme(storedTheme());
const isDark = () => (document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark";
const sun = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><circle cx="8" cy="8" r="3.2" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M8 1v1.6M8 13.4V15M1 8h1.6M13.4 8H15M3 3l1.1 1.1M11.9 11.9 13 13M3 13l1.1-1.1M11.9 4.1 13 3" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
const moon = '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="M13.5 9.8A5.8 5.8 0 0 1 6.2 2.5a5.8 5.8 0 1 0 7.3 7.3Z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>';
const toggle = el("button", { type: "button", class: "theme-toggle" });
function drawToggle() {
  toggle.innerHTML = isDark() ? sun : moon;
  toggle.setAttribute("aria-label", isDark() ? "Use the light theme" : "Use the dark theme");
}
toggle.addEventListener("click", () => {
  const next = isDark() ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch { /* private window: this page only */ }
  drawToggle();
});
drawToggle();
$(".topbar").append(toggle);

// -- the menu on a phone ---------------------------------------------------------------------
const navToggle = $(".nav-toggle");
navToggle.addEventListener("click", () => {
  const open = document.body.classList.toggle("nav-open");
  navToggle.setAttribute("aria-expanded", String(open));
});
$("#sidebar [aria-current='page']")?.scrollIntoView({ block: "center" });

// -- copy buttons on code ---------------------------------------------------------------------
for (const pre of document.querySelectorAll(".doc pre")) {
  const button = el("button", { type: "button", class: "copy" }, "Copy");
  button.addEventListener("click", async () => {
    const text = pre.querySelector("code")?.innerText ?? pre.innerText;
    try { await navigator.clipboard.writeText(text.replace(/\n$/, "")); button.textContent = "Copied"; }
    catch { button.textContent = "Select and copy"; }
    setTimeout(() => { button.textContent = "Copy"; }, 1600);
  });
  pre.append(button);
}

// -- "On this page": the section you're reading --------------------------------------------------
const tocLinks = [...document.querySelectorAll(".toc a")];
if (tocLinks.length) {
  const headings = tocLinks.map((a) => document.getElementById(decodeURIComponent(a.hash.slice(1)))).filter(Boolean);
  const mark = () => {
    let current = headings[0];
    for (const h of headings) if (h.getBoundingClientRect().top < 120) current = h;
    for (const a of tocLinks) a.classList.toggle("active", current && a.hash === `#${current.id}`);
  };
  addEventListener("scroll", mark, { passive: true });
  mark();
}

// -- search ---------------------------------------------------------------------------------------
let index = null;
async function loadIndex() {
  if (!index) index = await fetch(`${BASE}_assets/search.json`).then((r) => r.json()).catch(() => []);
  return index;
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function highlight(text, terms) {
  const out = [];
  if (!terms.length) return [text];
  const re = new RegExp(`(${terms.map(escapeRe).join("|")})`, "ig");
  let last = 0;
  for (const m of text.matchAll(re)) {
    out.push(text.slice(last, m.index), el("mark", {}, m[0]));
    last = m.index + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

function search(entries, query) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return [];
  const scored = [];
  for (const e of entries) {
    const heading = e.heading.toLowerCase(), page = e.page.toLowerCase(), text = e.text.toLowerCase();
    let score = 0;
    for (const t of terms) {
      const s = (heading.includes(t) ? 10 : 0) + (page.includes(t) ? 4 : 0) + (text.includes(t) ? 1 : 0);
      if (!s) { score = 0; break; }
      score += s;
    }
    if (score) scored.push([score, e]);
  }
  return scored.sort((a, b) => b[0] - a[0]).slice(0, 12).map(([, e]) => e);
}

function snippet(text, terms) {
  const lower = text.toLowerCase();
  const at = Math.max(0, Math.min(...terms.map((t) => lower.indexOf(t)).filter((i) => i >= 0)) - 40);
  return (at ? "…" : "") + text.slice(at, at + 160);
}

async function openSearch() {
  if ($("dialog.search")) return;
  const input = el("input", { type: "search", placeholder: "Search the docs", "aria-label": "Search the docs", autocomplete: "off",
    role: "combobox", "aria-controls": "search-results", "aria-expanded": "true" });
  const list = el("ul", { class: "search-results", id: "search-results", role: "listbox" });
  const dialog = el("dialog", { class: "search", "aria-label": "Search" }, el("div", { class: "search-box" }, input, list,
    el("p", { class: "search-keys" }, el("kbd", {}, "↑"), el("kbd", {}, "↓"), " to move · ", el("kbd", {}, "Enter"), " to open · ",
      el("kbd", {}, "Esc"), " to close")));
  let results = [];
  let selected = 0;
  const draw = () => {
    const terms = input.value.toLowerCase().split(/\s+/).filter(Boolean);
    results = search(index || [], input.value);
    selected = Math.min(selected, Math.max(0, results.length - 1));
    list.replaceChildren(...(results.length ? results.map((r, i) => el("li", { role: "option", "aria-selected": String(i === selected),
      class: i === selected ? "on" : null, id: `sr-${i}` },
      el("a", { href: r.url, onclick: () => dialog.close() },
        el("span", { class: "r-title" }, ...highlight(r.heading, terms)),
        r.heading !== r.page ? el("span", { class: "r-page" }, r.page) : null,
        r.text ? el("span", { class: "r-text" }, ...highlight(snippet(r.text, terms), terms)) : null)))
      : [el("li", { class: "search-empty" }, input.value.trim() ? "Nothing matches - try fewer words." : "Type to search every page.")]));
    input.setAttribute("aria-activedescendant", results.length ? `sr-${selected}` : "");
    list.querySelector(".on")?.scrollIntoView({ block: "nearest" });
  };
  input.addEventListener("input", () => { selected = 0; draw(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); selected = Math.min(selected + 1, results.length - 1); draw(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); selected = Math.max(selected - 1, 0); draw(); }
    else if (e.key === "Enter" && results[selected]) { e.preventDefault(); dialog.close(); location.href = results[selected].url; }
  });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) dialog.close(); });
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  input.focus();
  draw();
  await loadIndex();
  if (dialog.open) draw();
}

$(".search-button").addEventListener("click", openSearch);
document.addEventListener("keydown", (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
  if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) { e.preventDefault(); openSearch(); }
  else if (e.key === "/" && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) { e.preventDefault(); openSearch(); }
});
