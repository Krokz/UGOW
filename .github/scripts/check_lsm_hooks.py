#!/usr/bin/env python3
"""Check the BPF LSM programs against a kernel's LSM hook prototypes.

BPF_PROG() maps its declared arguments onto the hook's raw argument slots by
position, so a program written for the wrong prototype still compiles and
still passes the verifier -- it just reads the wrong arguments at runtime.
Nothing else catches that, so compare each SEC("lsm/<hook>") program against
the LSM_HOOK() entry in the kernel's include/linux/lsm_hook_defs.h.

A program that takes the raw ctx instead of using BPF_PROG() fetches its
arguments at runtime with bpf_get_func_arg(), which bounds-checks them, so for
those only the hook's existence is checked.

Usage: check_lsm_hooks.py <lsm_hook_defs.h> <ugow.bpf.c> [label]
"""

import re
import sys

_QUALIFIERS = {"const", "volatile", "__user", "__rcu", "__kernel"}


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _call_args(text, start):
    """Return the text between the parenthesis at @start and its match."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
    raise ValueError("unbalanced parentheses")


def _split_top_level(args):
    parts, depth, cur = [], 0, []
    for ch in args:
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts]


def _param_type(param):
    """'const struct dentry *dentry' -> 'struct dentry *'."""
    tokens = re.findall(r"\w+|\*", param)
    if len(tokens) > 1 and tokens[-1] != "*":
        tokens = tokens[:-1]  # drop the parameter name
    tokens = [t for t in tokens if t not in _QUALIFIERS]
    return " ".join(tokens).replace(" *", "*").replace("*", " *").strip()


def _is_pointer(ctype):
    return ctype.endswith("*")


def kernel_hooks(defs_text):
    text = _strip_comments(defs_text)
    hooks = {}
    for m in re.finditer(r"\bLSM_HOOK\s*\(", text):
        parts = _split_top_level(_call_args(text, m.end() - 1))
        name, params = parts[2], parts[3:]
        if params == ["void"]:
            params = []
        hooks[name] = [_param_type(p) for p in params]
    return hooks


_LSM_SEC = r'SEC\(\s*"lsm(?:\.s)?/(\w+)"\s*\)'


def bpf_programs(src_text):
    """Return (hook, program, params) per LSM program; params is None for a
    program that reads its arguments through the raw ctx."""
    text = _strip_comments(src_text)
    progs = []
    for m in re.finditer(_LSM_SEC + r"\s*int\s+BPF_PROG\s*\(", text):
        parts = _split_top_level(_call_args(text, m.end() - 1))
        progs.append((m.start(), m.group(1), parts[0],
                      [_param_type(p) for p in parts[1:]]))
    for m in re.finditer(_LSM_SEC + r"\s*int\s+(\w+)\s*\(\s*"
                         r"(?:unsigned\s+long\s+long|__u64|void)\s*\*\s*\w+\s*\)",
                         text):
        progs.append((m.start(), m.group(1), m.group(2), None))
    # Every LSM section must have been recognised: one that neither pattern
    # matches would otherwise drop out of the check without a trace.
    expected = len(re.findall(_LSM_SEC, text))
    if len(progs) != expected:
        raise ValueError(f"recognised {len(progs)} of {expected} LSM programs")
    return [prog[1:] for prog in sorted(progs)]


def compare(kernel, ours):
    """Return a reason string if @ours cannot be read from @kernel's slots."""
    if len(ours) > len(kernel):
        return f"declares {len(ours)} arguments, the hook has {len(kernel)}"
    for i, (k, o) in enumerate(zip(kernel, ours)):
        # Scalars only need to fit the u64 slot; pointers must agree on the
        # pointee, since that decides every field offset read through them.
        if (_is_pointer(k) or _is_pointer(o)) and k != o:
            return f"argument {i + 1} is '{k}' in the kernel, '{o}' here"
    return None


def main(argv):
    if len(argv) not in (3, 4):
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    with open(argv[1]) as f:
        hooks = kernel_hooks(f.read())
    with open(argv[2]) as f:
        try:
            progs = bpf_programs(f.read())
        except ValueError as e:
            print(f"error: {argv[2]}: {e}", file=sys.stderr)
            return 2
    label = argv[3] if len(argv) == 4 else argv[1]

    if not hooks or not progs:
        print(f"error: parsed {len(hooks)} hooks and {len(progs)} programs",
              file=sys.stderr)
        return 2

    failures = 0
    for hook, prog, params in progs:
        if hook not in hooks:
            reason = "no such LSM hook"
        elif params is None:
            reason = None
        else:
            reason = compare(hooks[hook], params)
        if reason:
            failures += 1
            print(f"MISMATCH {hook}: {prog}() {reason}")
            if hook in hooks:
                print(f"  kernel: ({', '.join(hooks[hook])})")
                print(f"  bpf:    ({', '.join(params)})")
        elif params is None:
            print(f"ok       {hook} (reads arguments via ctx)")
        else:
            print(f"ok       {hook}")

    print(f"{label}: {len(progs) - failures}/{len(progs)} hooks match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
