import re
import sys
from pathlib import Path

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
        # Ensure trailing period
        if not short.endswith('.'):
            short += '.'
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
        r'\*\*([A-Za-z0-9_]+)\*\*\(\d+\)',
        fix_see_also,
        text
    )

    return text

if __name__ == "__main__":
    for path in sys.argv[1:]:
        p = Path(path)
        original = p.read_text()
        cleaned = process(original)
        print(cleaned)
        p.write_text(cleaned)
        print(f"Processed {p}")
