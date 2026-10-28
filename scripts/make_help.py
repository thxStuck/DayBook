#!/usr/bin/env python3
"""Builds the app's Apple Help book from the documentation in docs/ (the GitHub Pages site).

    scripts/make_help.py

Writes DayBookEvtxMacOS/Resources/DayBookEvtxMacOS.help: one page per docs page for Russian and
English, a stylesheet, the icon and a search index per language (hiutil). The Help menu opens it
in the system help window; the search field of the Help menu searches it. Re-run after editing
docs/ru or docs/en.

The converter covers the Markdown the docs use: headings, paragraphs, lists (nested, with code),
tables, fenced code, inline code, bold, links, Just the Docs callouts ({: .note }) and {:toc}.
"""
import html
import os
import plistlib
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
BOOK = os.path.join(ROOT, "DayBookEvtxMacOS", "Resources", "DayBookEvtxMacOS.help")
BOOK_ID = "app.daybook.evtx.help"
TITLES = {"ru": "Справка DayBookEvtxMacOS", "en": "DayBookEvtxMacOS Help"}
CONTENTS = {"ru": "Содержание", "en": "Contents"}
ONLINE = {"ru": "Документация на сайте", "en": "Documentation online"}
SITE = "https://thxstuck.github.io/DayBook/"
CALLOUT_TITLES = {"note": "Note", "warning": "Warning", "note-ru": "Примечание", "warning-ru": "Важно"}


def slug(text):
    """GitHub-style heading id (kramdown GFM): lower case, Unicode letters kept, spaces to '-'."""
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def inline(text):
    """Inline Markdown: code spans first (verbatim), then links, bold and italics."""
    # Code spans: ``x`` may contain single backticks; `x` may not.
    parts = re.split(r"(``.+?``|`[^`]+`)", text)
    out = []
    for p in parts:
        if p.startswith("``") and p.endswith("``") and len(p) > 4:
            out.append("<code>" + html.escape(p[2:-2].strip()) + "</code>")
            continue
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            out.append("<code>" + html.escape(p[1:-1]) + "</code>")
            continue
        s = html.escape(p, quote=False)
        s = re.sub(r"\\\|", "|", s)
        s = re.sub(r"\\\*", "&#42;", s)

        def link(m):
            label, url = m.group(1), m.group(2)
            if url.startswith("../"):            # the other language: not in this book
                return label
            ext = ' class="external"' if url.startswith("http") else ""
            return f'<a href="{html.escape(url)}"{ext}>{label}</a>'
        s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"(?<![\w*])\*([^*\s][^*]*)\*(?![\w*])", r"<em>\1</em>", s)
        out.append(s)
    return "".join(out)


def split_row(line):
    cells = re.split(r"(?<!\\)\|", line.strip())
    if cells and cells[0].strip() == "":
        cells = cells[1:]
    if cells and cells[-1].strip() == "":
        cells = cells[:-1]
    return [c.strip() for c in cells]


def convert(md, lang):
    """Markdown body → (title, html). Front matter is read by the caller."""
    lines = md.split("\n")
    out, toc, i = [], [], 0

    def para_close(buf):
        if buf:
            text = " ".join(x.strip() for x in buf)
            if pending_box[0]:
                cls = pending_box[0]
                out.append(f'<div class="callout {cls}"><p class="callout-title">{CALLOUT_TITLES.get(cls, "")}</p><p>{inline(text)}</p></div>')
                pending_box[0] = None
            else:
                out.append(f"<p>{inline(text)}</p>")
            buf.clear()

    pending_box = [None]
    buf = []
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        # Attribute lists: callouts mark the next paragraph, other attributes are layout only.
        m = re.fullmatch(r"\{:\s*\.([\w-]+)[^}]*\}", stripped)
        if m:
            para_close(buf)
            if m.group(1) in CALLOUT_TITLES:
                pending_box[0] = m.group(1)
            i += 1
            continue
        if stripped == "{:toc}":
            i += 1
            continue
        if stripped == "1. TOC":
            para_close(buf)
            out.append("<!--TOC-->")
            i += 1
            continue
        if not stripped:
            para_close(buf)
            i += 1
            continue
        if stripped.startswith(("[English version](", "[Русская версия](")):
            i += 1
            continue
        h = re.match(r"(#{1,4})\s+(.*)", stripped)
        if h:
            para_close(buf)
            level, text = len(h.group(1)), h.group(2).strip()
            hid = slug(text)
            if level in (2, 3):
                toc.append((level, hid, text))
            out.append(f'<h{level} id="{hid}"><a name="{hid}"></a>{inline(text)}</h{level}>')
            i += 1
            continue
        if stripped.startswith("```"):
            para_close(buf)
            indent = len(line) - len(line.lstrip())
            code = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i][indent:] if lines[i][:indent].strip() == "" else lines[i])
                i += 1
            i += 1
            out.append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
            continue
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{3,}", lines[i + 1]):
            para_close(buf)
            header = split_row(stripped)
            i += 2
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            t = ["<table>", "<thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in header) + "</tr></thead>", "<tbody>"]
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table>")
            out.append("\n".join(t))
            continue
        if re.match(r"^\s*([-*]|\d+\.)\s+", line):
            para_close(buf)
            i = parse_list(lines, i, out)
            continue
        buf.append(line)
        i += 1
    para_close(buf)
    body = "\n".join(out)
    first = next((re.sub(r"<[^>]+>", "", x) for x in out if x.startswith("<p>")), "")
    summary = html.unescape(first)[:220]
    keywords = ", ".join(html.unescape(re.sub(r"<[^>]+>", "", inline(t))) for _, _, t in toc)
    if "<!--TOC-->" in body:
        items = []
        for level, hid, text in toc:
            cls = ' class="sub"' if level == 3 else ""
            items.append(f'<li{cls}><a href="#{hid}">{inline(text)}</a></li>')
        body = body.replace("<!--TOC-->", '<nav class="toc"><ul>' + "".join(items) + "</ul></nav>")
    return body, summary, keywords


def parse_list(lines, i, out):
    """A list starting at line i, with nesting by indentation and code blocks inside items."""
    first = lines[i]
    base = len(first) - len(first.lstrip())
    ordered = bool(re.match(r"^\s*\d+\.", first))
    out.append("<ol>" if ordered else "<ul>")
    item = None

    def flush():
        if item is not None:
            out.append("<li>" + inline(" ".join(x.strip() for x in item["text"])) + "".join(item["children"]) + "</li>")

    while i < len(lines):
        line = lines[i]
        if not line.strip():
            # A blank line ends the list unless the next line continues it (indented or a new item).
            j = i + 1
            if j < len(lines) and lines[j].strip() and (len(lines[j]) - len(lines[j].lstrip()) > base
                                                        or re.match(r"^\s{%d}([-*]|\d+\.)\s+" % base, lines[j])):
                i += 1
                continue
            break
        indent = len(line) - len(line.lstrip())
        m = re.match(r"^\s*([-*]|\d+\.)\s+(.*)", line)
        if m and indent == base:
            flush()
            item = {"text": [m.group(2)], "children": []}
            i += 1
            continue
        if indent > base and item is not None:
            if re.match(r"^\s*([-*]|\d+\.)\s+", line):
                sub = []
                i = parse_list(lines, i, sub)
                item["children"].append("".join(sub))
                continue
            if line.strip().startswith("```"):
                code = []
                i += 1
                while i < len(lines) and not lines[i].strip().startswith("```"):
                    code.append(lines[i][indent:] if lines[i][:indent].strip() == "" else lines[i])
                    i += 1
                i += 1
                item["children"].append("<pre><code>" + html.escape("\n".join(code)) + "</code></pre>")
                continue
            item["text"].append(line)
            i += 1
            continue
        break
    flush()
    out.append("</ol>" if ordered else "</ul>")
    return i


def front_matter(text):
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    meta = {}
    if m:
        for row in m.group(1).split("\n"):
            if ":" in row:
                k, v = row.split(":", 1)
                meta[k.strip()] = v.strip()
        text = text[m.end():]
    return meta, text


STYLE = """
:root { color-scheme: light dark; --fg: #1d1d1f; --muted: #6e6e73; --bg: #ffffff; --code: #f2f2f5;
        --line: #d2d2d7; --accent: #0a64d6; --note: #e8f1fd; --warn: #fdecec; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #f5f5f7; --muted: #a1a1a6; --bg: #1e1e1e; --code: #2c2c2e; --line: #3a3a3c;
          --accent: #4ea1ff; --note: #1d2c40; --warn: #3d2324; }
}
body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; color: var(--fg);
       background: var(--bg); margin: 0; }
main { max-width: 860px; margin: 0 auto; padding: 18px 24px 40px; }
header.top { font-size: 13px; color: var(--muted); padding: 10px 24px; border-bottom: 1px solid var(--line); }
header.top a { margin-right: 14px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 26px; margin: 12px 0 14px; }
h2 { font-size: 20px; margin: 28px 0 8px; padding-top: 6px; border-top: 1px solid var(--line); }
h3 { font-size: 16px; margin: 20px 0 6px; }
h4 { font-size: 14px; margin: 16px 0 4px; }
code { font: 12.5px ui-monospace, Menlo, monospace; background: var(--code); padding: 1px 4px; border-radius: 4px; }
pre { background: var(--code); padding: 10px 12px; border-radius: 6px; overflow-x: auto; }
pre code { padding: 0; background: none; }
table { border-collapse: collapse; margin: 10px 0; width: 100%; font-size: 13px; }
th, td { border: 1px solid var(--line); padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: var(--code); }
.callout { border-left: 4px solid var(--accent); background: var(--note); padding: 4px 12px; margin: 12px 0; border-radius: 4px; }
.callout.warning, .callout.warning-ru { border-color: #d70015; background: var(--warn); }
.callout-title { font-weight: 600; margin: 6px 0 0; }
nav.toc { background: var(--code); border-radius: 6px; padding: 6px 14px; margin: 8px 0 16px; }
nav.toc ul { margin: 4px 0; padding-left: 18px; }
nav.toc li.sub { margin-left: 16px; font-size: 13px; }
"""


def page(lang, title, body, name, summary="", keywords=""):
    nav = f'<a href="index.html">{CONTENTS[lang]}</a>' if name != "index.html" else ""
    online = f'<a class="external" href="{SITE}{lang}/">{ONLINE[lang]}</a>'
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="robots" content="anchors">
<meta name="color-scheme" content="light dark">
<meta name="description" content="{html.escape(summary)}">
<meta name="keywords" content="{html.escape(keywords)}">
{'<meta name="AppleTitle" content="' + TITLES[lang] + '">' if name == "index.html" else ''}
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="../shared/style.css">
</head>
<body>
<header class="top">{nav}{online}</header>
<main>
{body}
</main>
</body>
</html>
"""


def main():
    if os.path.exists(BOOK):
        shutil.rmtree(BOOK)
    res = os.path.join(BOOK, "Contents", "Resources")
    os.makedirs(os.path.join(res, "shared"))
    with open(os.path.join(res, "shared", "style.css"), "w") as f:
        f.write(STYLE.strip() + "\n")
    shutil.copy(os.path.join(DOCS, "assets", "icon.png"), os.path.join(res, "shared", "icon.png"))
    for lang in ("ru", "en"):
        src = os.path.join(DOCS, lang)
        dst = os.path.join(res, f"{lang}.lproj")
        os.makedirs(dst)
        for fn in sorted(os.listdir(src)):
            if not fn.endswith(".md"):
                continue
            meta, md = front_matter(open(os.path.join(src, fn), encoding="utf-8").read())
            name = fn[:-3] + ".html"
            body, summary, keywords = convert(md, lang)
            title = TITLES[lang] if fn == "index.md" else f"{meta.get('title', fn)} — {TITLES[lang]}"
            with open(os.path.join(dst, name), "w", encoding="utf-8") as f:
                f.write(page(lang, title, body, name, summary, keywords))
        with open(os.path.join(dst, "InfoPlist.strings"), "wb") as f:
            plistlib.dump({"CFBundleName": TITLES[lang], "HPDBookTitle": TITLES[lang],
                           "HPDBookIconPath": "../shared/icon.png"}, f)
        index = os.path.join(dst, "search.cshelpindex")
        r = subprocess.run(["hiutil", "-I", "corespotlight", "-Caf", index, "-l", lang, dst],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"hiutil failed for {lang}: {r.stderr}")
    with open(os.path.join(BOOK, "Contents", "Info.plist"), "wb") as f:
        plistlib.dump({
            "CFBundleDevelopmentRegion": "en",
            "CFBundleIdentifier": BOOK_ID,
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": "DayBookEvtxMacOS",
            "CFBundlePackageType": "BNDL",
            "CFBundleShortVersionString": "1",
            "CFBundleSignature": "hbwr",
            "CFBundleVersion": "1",
            "HPDBookAccessPath": "index.html",
            "HPDBookCSIndexPath": "search.cshelpindex",
            "HPDBookIconPath": "../shared/icon.png",
            "HPDBookTitle": "DayBookEvtxMacOS Help",
            "HPDBookType": "3",
        }, f)
    pages = sum(1 for d, _, fs in os.walk(res) for x in fs if x.endswith(".html"))
    print(f"help book: {BOOK} ({pages} pages)")


if __name__ == "__main__":
    main()
