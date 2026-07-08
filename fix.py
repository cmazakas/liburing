#!/bin/python3

import re
import sys
from pathlib import Path
import subprocess
import os.path

_CODE = re.compile(
    r"(?P<esc>\\.)"                  # backslash escape: \[  \]  \`  \*  ...
    r"|(?P<fence>^```.*?^```\s*$)"   # fenced code block
    r"|(?P<inline>`[^`\n]*`)",       # inline code span
    re.DOTALL | re.MULTILINE,
)

def fixup_links_skipping_code(md: str, fixup) -> str:
    """Run `fixup` (your existing [text] -> [text](url) function) on prose only."""
    out = []
    last = 0
    for m in _CODE.finditer(md):
        # prose before this code region: safe to transform
        out.append(fixup(md[last:m.start()]))
        # code region: pass through untouched
        out.append(m.group(0))
        last = m.end()
    out.append(fixup(md[last:]))   # trailing prose
    return "".join(out)

def fix_man_link(match: re.Match) -> str:
    fn_name = match.group(1)

    man_link_map = {}
    path = man_link_map.get(fn_name, f"man2/{fn_name}.2.html")
    url = f"https://man7.org/linux/man-pages/{path}"
    return f"[{fn_name}]({url})"

def fix_man_links(text: str) -> str:
    pattern = re.compile(r'\[(?![^\]]*\]\()(?!io_uring)([^\]]+)\]')
    found = pattern.findall(text)
    # print(found)

    return pattern.sub(fix_man_link, text)

def process(text: str) -> str:
    # 1. Remove the "# NAME" line entirely
    text = re.sub(r'^# NAME\s*\n', '', text, flags=re.MULTILINE)

    # 2. Extract the short description line:
    #    e.g. "io_uring_for_each_cqe - iterate pending completion events"
    m = re.search(r'\A(.*?)\s*-\s*(.*)$', text, flags=re.MULTILINE)
    if m:
        short = m.group(2).strip()
        if not short.startswith('io_uring'):
                short = short[0].upper() + short[1:]
        text = text[:m.start()] + short + text[m.end():]

    # 3. Remove everything from "# SYNOPSIS" up to "# DESCRIPTION"
    text = re.sub(
        r'# SYNOPSIS[\s\S]*?# DESCRIPTION',
        '# DESCRIPTION',
        text,
        flags=re.MULTILINE
    )

    # 4. Transform SEE ALSO entries:
    #    **symbol**(3) → [symbol]
    def fix_see_also(match):
        symbol = match.group(1)
        if symbol == "io_uring_clone_buffers":
            return f"[{symbol}()]"
        return f'[{symbol}]'

    text = re.sub(
        r'\*\*([A-Za-z0-9_]+)\*\*\((\d+)\)',
        fix_see_also,
        text
    )

    text = fixup_links_skipping_code(text, fix_man_links)
#     text = fix_man_links(text)
    text = re.sub(r'\*\*  ', r'**\\', text)

    return text

if __name__ == "__main__":
    for path in sys.argv[1:]:
        p = Path(path)
        name = p.name.rsplit('.')[0]

        out_name = f"liburing-rs/docs/{name}.md"
        subprocess.run(['pandoc',  '-f', 'man', '-t', 'commonmark', '--lua-filter=tag-c.lua', '-o', out_name, path], stdout=True)

        p = Path(out_name)
        original = p.read_text()
        cleaned = process(original)
        # print(cleaned)
        p.write_text(cleaned)
        print(f"Processed {p}")
