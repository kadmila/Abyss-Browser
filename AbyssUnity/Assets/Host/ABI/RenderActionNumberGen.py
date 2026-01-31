# Renumber trailing numbers in the first `oneof inner { ... }` block of RenderAction.proto.
#
# Updated rule:
# - If a paragraph does NOT begin with a `//N` comment, its base = previous paragraph's base + 100.
# - If it's the FIRST paragraph and has no comment, start at 100.
#
# Other rules (unchanged):
# - Paragraph = consecutive non-empty lines; blank/whitespace-only lines separate paragraphs.
# - If the first non-empty line of a paragraph is a comment like `//12 ...`, use N=12 → base = 1200.
# - Only change numbers on lines that END with "<number>;" (spaces around ';' allowed).
# - Preserve all other text/spacing verbatim.
#
# Always edits "RenderAction.proto" in place. No CLI and no __main__ guard.

from pathlib import Path
import re

START_MARKER = "oneof inner {"
COMMENT_N_RE = re.compile(r'^\s*//\s*(\d+)')  # captures N in leading comment: // <N> ...
NUM_LINE_RE = re.compile(r'^(?P<prefix>.*?)(?P<num>\d+)\s*;(?P<suffix>\s*)$')  # matches lines ending with "<num>;"

def process_block_lines(block_lines):
    """
    Process lines between 'oneof inner {' and the closing '}'.
    Paragraph = maximal run of non-empty lines (blank lines separate paragraphs).
    """
    out = []
    j = 0
    last_base = None  # base used for the previous paragraph

    while j < len(block_lines):
        line = block_lines[j]
        if line.strip() == '':
            # Blank line outside any paragraph: copy and continue
            out.append(line)
            j += 1
            continue

        # Start of a paragraph: gather until next blank line or end
        start = j
        k = j
        while k < len(block_lines) and block_lines[k].strip() != '':
            k += 1
        paragraph = block_lines[start:k]  # non-empty lines

        # Determine base for this paragraph
        first_line = paragraph[0]
        m_comment = COMMENT_N_RE.match(first_line)
        if m_comment:
            base = int(m_comment.group(1)) * 100
        else:
            base = (last_base + 100) if last_base is not None else 100

        offset = 0  # numbering within this paragraph

        # Emit the paragraph
        for idx, pline in enumerate(paragraph):
            if idx == 0 and m_comment:
                # Keep the leading comment line unchanged
                out.append(pline)
                continue

            raw = pline.rstrip('\n')
            newline = pline[len(raw):]  # preserve exact newline(s)
            m_num = NUM_LINE_RE.match(raw)
            if m_num:
                new_num = base + offset
                offset += 1
                new_raw = f"{m_num.group('prefix')}{new_num};{m_num.group('suffix')}"
                out.append(new_raw + newline)
            else:
                out.append(pline)

        # Remember base for the next paragraph
        last_base = base
        j = k  # advance past this paragraph

    return out

def renumber_content(text: str) -> str:
    lines = text.splitlines(keepends=True)

    # Find first line containing the start marker
    start_idx = None
    for i, ln in enumerate(lines):
        if START_MARKER in ln:
            start_idx = i
            break

    if start_idx is None:
        # No block; return unchanged
        return text

    out = []
    # Copy everything up to and including the start marker line
    out.extend(lines[:start_idx + 1])

    # Collect inner block lines until a line that starts with '}' (allow leading spaces)
    i = start_idx + 1
    block_inner = []
    while i < len(lines):
        if lines[i].lstrip().startswith('}'):
            break
        block_inner.append(lines[i])
        i += 1

    # Process block inner lines by paragraphs
    out.extend(process_block_lines(block_inner))

    # Append the closing '}' line (if present) and the rest
    if i < len(lines):
        out.append(lines[i])  # the '}' line
        i += 1
    out.extend(lines[i:])

    return ''.join(out)

# Edit the file in place
path = Path("RenderAction.proto")
original = path.read_text(encoding="utf-8")
updated = renumber_content(original)
path.write_text(updated, encoding="utf-8")
