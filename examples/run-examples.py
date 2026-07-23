#!/usr/bin/env python3

"""Run bllsh example files and check their expected-output markers.

An example file is a sequence of repl commands, the same format the
repl's import command reads. A marker comment of the form

    ; expect: <line>

placed on the line after a command asserts that the command's first
line of output is exactly <line>. Evaluation results, nil and ERR(...)
values all print as a single line, so the one marker form covers
passing checks, clean refusals and errors alike. Output beyond the
first line (the allocation report of eval and blleval, the leak dump)
is ignored.

Every eval and blleval command must carry a marker, an unasserted
evaluation is a failure. Other commands (program, compile) may carry
one. A Python traceback from the repl is a failure regardless of
markers.

Usage, from the repository root:

    python3 examples/run-examples.py [FILE ...]

Without arguments the marked corpus examples listed in CORPUS are run.
Exits nonzero if any file fails.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys

CORPUS = [
    "examples/test-vault",
    "examples/test-flexmarks",
    "examples/test-flexmarks-htlc",
    "examples/test-p2-delegated",
    "examples/test-singleton",
    "examples/test-cat",
    "examples/test-commitment",
]

MARKER = "; expect:"

# commands whose result must be asserted by a marker
CHECKED = ("eval", "blleval", "spend")


def load_repl_class(root):
    """Load the BTCLispRepl class from the extensionless bllsh script.

    The script's __main__ guard keeps the interactive loop from
    starting, so no readline history is read or written.
    """
    path = os.path.join(root, "bllsh")
    loader = importlib.machinery.SourceFileLoader("bllsh_repl", path)
    spec = importlib.util.spec_from_loader("bllsh_repl", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module.BTCLispRepl


class Pending:
    """One executed command whose output may still be asserted."""

    def __init__(self, lineno, line, first_line, required):
        self.lineno = lineno
        self.line = line
        self.first_line = first_line
        self.required = required


def run_file(path, repl_cls):
    """Run one example file. Returns (checks, failures)."""
    repl = repl_cls(prompt="")
    checks = 0
    failures = []
    pending = None

    def settle():
        nonlocal pending
        if pending is not None and pending.required:
            failures.append(
                f"{path}:{pending.lineno}: unasserted result of"
                f" '{pending.line}', add a '{MARKER}' marker"
            )
        pending = None

    with open(path, "r") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if line == "":
                continue
            if line.startswith(MARKER):
                expected = line[len(MARKER):].strip()
                if pending is None:
                    failures.append(f"{path}:{lineno}: marker without a command")
                    continue
                checks += 1
                if pending.first_line != expected:
                    failures.append(
                        f"{path}:{pending.lineno}: {pending.line}\n"
                        f"    expected: {expected}\n"
                        f"    got:      {pending.first_line}"
                    )
                pending = None
                continue
            if line.startswith(";"):
                continue
            settle()
            out = io.StringIO()
            err = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                repl.onecmd(line)
            if err.getvalue():
                failures.append(
                    f"{path}:{lineno}: {line}\n"
                    + "".join("    " + e + "\n" for e in err.getvalue().splitlines())
                )
                continue
            stdout_lines = out.getvalue().splitlines()
            first_line = stdout_lines[0] if stdout_lines else ""
            word = line.split(None, 1)[0]
            pending = Pending(lineno, line, first_line, word in CHECKED)
    settle()
    return checks, failures


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # resolve file arguments against the caller's directory before the
    # chdir below moves the process to the repository root
    files = [os.path.abspath(f) for f in argv[1:]] if len(argv) > 1 else CORPUS
    sys.path.insert(0, root)
    os.chdir(root)
    repl_cls = load_repl_class(root)
    exit_code = 0
    for path in files:
        checks, failures = run_file(path, repl_cls)
        if failures:
            exit_code = 1
            print(f"FAIL {path} ({checks} checks, {len(failures)} failures)")
            for failure in failures:
                print("  " + failure)
        else:
            print(f"PASS {path} ({checks} checks)")
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
