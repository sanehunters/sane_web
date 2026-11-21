#!/usr/bin/env python3
"""Generate .claude/skills/*/SKILL.md and .claude/agents/*.md from src/skills/*.md and src/agents/*.md.

A source file is the skill or agent as written by hand, plus include directives:

    <!-- include playbooks/PB-06-hunt.md -->

Each directive is replaced by the named file, with its first-level heading turned into a section heading and every
other heading pushed one level down, so the skill or agent carries the whole procedure and never has to guess.
The playbooks and docs stay the single source of truth: edit them, or the file under src/, then run this.

    scripts/build_claude.py           write the generated files
    scripts/build_claude.py --check   exit 1 if any generated file is out of date
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INC = re.compile(r"^<!--\s*include\s+(\S+)\s*-->\s*$", re.M)


def demote(text, path):
    lines = text.rstrip("\n").split("\n")
    out, in_code, first = [], False, True
    for ln in lines:
        if ln.strip().startswith("```"):
            in_code = not in_code
        if not in_code and ln.startswith("#"):
            m = re.match(r"^(#+)\s+(.*)$", ln)
            if m:
                if first and len(m.group(1)) == 1:
                    ln = f"## Reference: {m.group(2)}\n\n_Included from `{path}`. That file is the source of truth._"
                    first = False
                else:
                    ln = "#" + ln
        out.append(ln)
    return "\n".join(out)


def render(src_path):
    text = open(src_path, encoding="utf-8").read()
    rel = os.path.relpath(src_path, ROOT)

    def sub(m):
        p = m.group(1)
        full = os.path.join(ROOT, p)
        if not os.path.exists(full):
            raise SystemExit(f"{rel}: include not found: {p}")
        return "\n---\n\n" + demote(open(full, encoding="utf-8").read(), p)

    body = INC.sub(sub, text)
    # the generated-file note goes after the frontmatter so the frontmatter stays first
    m = re.match(r"^(---\n.*?\n---\n)", body, re.S)
    note = f"\n<!-- GENERATED from {rel} by scripts/build_claude.py. Edit that file or the included playbook, then rebuild. -->\n"
    return (m.group(1) + note + body[m.end():]) if m else note + body


def targets():
    out = []
    sd = os.path.join(ROOT, "src", "skills")
    for fn in sorted(os.listdir(sd)):
        if fn.endswith(".md"):
            out.append((os.path.join(sd, fn), os.path.join(ROOT, ".claude", "skills", fn[:-3], "SKILL.md")))
    ad = os.path.join(ROOT, "src", "agents")
    for fn in sorted(os.listdir(ad)):
        if fn.endswith(".md"):
            out.append((os.path.join(ad, fn), os.path.join(ROOT, ".claude", "agents", fn)))
    return out


def main():
    check = "--check" in sys.argv
    stale = 0
    for src, dst in targets():
        new = render(src)
        old = open(dst, encoding="utf-8").read() if os.path.exists(dst) else None
        if new != old:
            stale += 1
            if check:
                print(f"out of date: {os.path.relpath(dst, ROOT)}")
            else:
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "w", encoding="utf-8") as f:
                    f.write(new)
                print(f"wrote {os.path.relpath(dst, ROOT)} ({len(new):,} bytes)")
    n = len(targets())
    if check:
        print(f"{n} generated files, {stale} out of date")
        sys.exit(1 if stale else 0)
    print(f"{n} generated files, {stale} written")


if __name__ == "__main__":
    main()
