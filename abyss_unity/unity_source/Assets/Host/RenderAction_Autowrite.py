#!/usr/bin/env python3
"""
update_executor_switch.py

Regenerates *both* switch-case blocks in Executor.cs from the public-void
methods declared in ABI/RenderActionWriter.cs.

Key points
• Still uses str.startswith for method discovery (no regex).
• Keeps fixed indentation (8 spaces for `case`, 12 for contents).
• Overwrites Executor.cs in-place (no .bak file).
• **First switch** keeps the original “call-through” behaviour.
• **Second switch** logs the action as JSON through `logwriter`
  instead of calling a method.
"""

from pathlib import Path
import sys

ROOT_DIR      = Path(".").resolve()
WRITER_FILE   = ROOT_DIR / "ABI" / "RenderActionWriter.cs"
INTERPRETER_FILE = ROOT_DIR / "HostInterpretRequest.cs"
LOGGER_FILE = ROOT_DIR / "HostLogRequest.cs"
METHOD_PREFIX = "public void "
SWITCH_MARKER = "switch (render_action.InnerCase)"   # appears twice

# ----------------------------------------------------------------------
# Step 1-3: collect method names
# ----------------------------------------------------------------------
def collect_writer_methods(path: Path) -> list[str]:
    if not path.is_file():
        sys.exit(f"[error] {path} not found")

    methods: list[str] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.startswith(METHOD_PREFIX):
                method_name = line[len(METHOD_PREFIX):].strip()
                if method_name:                       # ignore blank lines
                    methods.append(method_name)

    if not methods:
        sys.exit("[error] No 'public void' methods found in RenderActionWriter.cs")
    return methods


# ----------------------------------------------------------------------
# helpers to build each switch block
# ----------------------------------------------------------------------
def build_cases_call(methods: list[str]) -> list[str]:
    """`case X: X(render_action.X); return;` + default"""
    lines = [
        f"            case RenderAction.InnerOneofCase.{m}: RenderingActionQueue.Enqueue({m}(render_action.{m})); return;"
        for m in methods
    ]
    lines.append(
        '            default: StderrQueue.Enqueue("Executor: invalid RenderAction: " + '
        "render_action.InnerCase); return;"
    )
    return [ln + "\n" for ln in lines]


def build_cases_log(methods: list[str]) -> list[str]:
    """`case X: X(render_action.X); return;` + default"""
    lines = [
        f"            case RenderAction.InnerOneofCase.{m}: GlobalDependency.Logger.Writer.WriteLine(FormatFlatLogLine(render_action.{m})); return;"
        for m in methods
    ]
    lines.append(
        '            default: StderrQueue.Enqueue("Executor: invalid RenderAction: " + '
        "render_action.InnerCase); return;"
    )
    return [ln + "\n" for ln in lines]


# ----------------------------------------------------------------------
# Step 4-7: overwrite Executor.cs (patch both switches)
# ----------------------------------------------------------------------
def patch_executor(path: Path, methods: list[str]) -> None:
    # Build replacement bodies in order
    replacements = [build_cases_call(methods), build_cases_log(methods)]

    # find target file
    if not path.is_file():
        sys.exit(f"[error] {path} not found")

    src = path.read_text(encoding="utf-8").splitlines(keepends=True)

    # find **all** switch statements
    switch_indices = [
        i for i, ln in enumerate(src) if SWITCH_MARKER in ln
    ]

    if len(switch_indices) != 2:
        sys.exit("[error] Expected at least two switch blocks but found "
                 f"{len(switch_indices)}")

    prev_idx = 0
    result = []
    open_idx = None
    close_idx = None
    for block_no in range(2):  # only the first two
        open_idx = prev_idx

        # locate switch statement
        while SWITCH_MARKER not in src[open_idx]:
            open_idx += 1
            if open_idx >= len(src):
                sys.exit("[error] switch statement not found")

        # locate opening brace
        while "{" not in src[open_idx]:
            open_idx += 1
            if open_idx >= len(src):
                sys.exit("[error] opening brace for switch not found")
        # now, open_idx is the index of opening brace line.

        # find closing brace, accounting for nested scopes
        depth = 0
        for i in range(open_idx, len(src)):
            depth += src[i].count("{") - src[i].count("}")
            if depth == 0:
                close_idx = i
                break
        if close_idx is None:
            sys.exit("[error] closing brace for switch not found")

        # append result
        result += src[prev_idx:open_idx + 1] + replacements[block_no]
        prev_idx = close_idx

    result += src[close_idx:]

    path.write_text("".join(result), encoding="utf-8")
    print(f"[done] Re-generated two switch-case blocks in {path}")

# ----------------------------------------------------------------------
# single patcher
# ----------------------------------------------------------------------
def replace_cases(path: Path, replacement: list[str]) -> None:
    # find target file
    if not path.is_file():
        sys.exit(f"[error] {path} not found")

    src = path.read_text(encoding="utf-8").splitlines(keepends=True)

    result = []
    open_idx = 0
    close_idx = None

    # locate switch statement
    while SWITCH_MARKER not in src[open_idx]:
        open_idx += 1
        if open_idx >= len(src):
            sys.exit("[error] switch statement not found")

    # locate opening brace
    while "{" not in src[open_idx]:
        open_idx += 1
        if open_idx >= len(src):
            sys.exit("[error] opening brace for switch not found")
    # now, open_idx is the index of opening brace line.

    # find closing brace, accounting for nested scopes
    depth = 0
    for i in range(open_idx, len(src)):
        depth += src[i].count("{") - src[i].count("}")
        if depth == 0:
            close_idx = i
            break
    if close_idx is None:
        sys.exit("[error] closing brace for switch not found")

    # append result
    result += src[0:open_idx + 1]
    result += replacement
    result += src[close_idx:]

    path.write_text("".join(result), encoding="utf-8")
    print(f"Re-generated switch-case block in {path}")


if __name__ == "__main__":
    methods = collect_writer_methods(WRITER_FILE)
    replace_cases(INTERPRETER_FILE, build_cases_call(methods))
    replace_cases(LOGGER_FILE, build_cases_log(methods))
