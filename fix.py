#!/bin/python3

import re
import sys
from pathlib import Path
import subprocess

def fix_man_link(match: re.Match) -> str:
    fn_name = match.group(1)

    man_link_map = {}
    path = man_link_map.get(fn_name, f"man2/{fn_name}.2.html")
    url = f"https://man7.org/linux/man-pages/{path}"
    return f"[{fn_name}]({url})"

def fix_man_links(text: str) -> str:
    pattern = re.compile(r'\[(?![^\]]*\]\()(?!io_uring)([^\]]+)\]')
    found = pattern.findall(text)
    print(found)

    return pattern.sub(fix_man_link, text)

def process(text: str) -> str:
    # 1. Remove the "# NAME" line entirely
    text = re.sub(r'^# NAME\s*\n', '', text, flags=re.MULTILINE)

    # 2. Extract the short description line:
    #    e.g. "io_uring_for_each_cqe - iterate pending completion events"
    m = re.search(r'^(.*?)\s*-\s*(.*)$', text, flags=re.MULTILINE)
    if m:
        short = m.group(2).strip()
        # Capitalize first word
        short = short[0].upper() + short[1:]
        # Replace the whole line with just the cleaned short description
        text = re.sub(r'^.*? - .*$', short, text, flags=re.MULTILINE)

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
        return f'[{symbol}]'

    text = re.sub(
        r'\*\*([A-Za-z0-9_]+)\*\*\((\d+)\)',
        fix_see_also,
        text
    )

    text = fix_man_links(text)
    return text

if __name__ == "__main__":
    for path in sys.argv[1:]:
        p = Path(path)
        if not p.is_file():
            continue
        print(p.name)

        name = p.name.rsplit('.')[0]

        out_name = f"liburing-rs/docs/{name}.md"
        subprocess.run(['pandoc', '-f', 'man', '-t', 'commonmark', '-o', out_name, p])

        p = Path(out_name)
        original = p.read_text()
        cleaned = process(original)
        print(cleaned)
        p.write_text(cleaned)
        print(f"Processed {p}")
