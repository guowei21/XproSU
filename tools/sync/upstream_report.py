"""Upstream delta report: what changed, and which sync layer it belongs to.

Reads the reference clone in vendor/ghostlock-app and classifies everything that
landed since the fork point into the four layers described in
docs/upstream-sync-plan.md:

  A  偏移数据      kernel_profiles/*.conf  -> 可用 conf_to_offsets.py 自动搬运
  B  引擎补丁      src/core/*.c|*.h        -> 逐条人工判定 + 真机 A/B
  C  App 逻辑      app/**.kt               -> 读 diff 手改（包名 app -> pro）
  D  架构          src/**.cpp 等           -> 只读参考，不移植

Nothing is modified. Exit code is 0 whether or not there are changes, so this
can run from a scheduled job.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_REPO = Path(__file__).resolve().parents[2] / "vendor" / "ghostlock-app"
DEFAULT_BASE = "50d2b72"

# Paths that decide which layer a commit belongs to, in priority order.
LAYER_RULES: list[tuple[str, str, str]] = [
    ("A", "偏移数据", "app/src/main/assets/kernel_profiles/"),
    ("A", "偏移数据", "src/kernels/"),
    ("B", "引擎补丁", "src/core/"),
    ("C", "App 逻辑", "app/src/main/kotlin/"),
    ("C", "App 资源", "app/src/main/res/"),
    ("C", "App 清单", "app/src/main/AndroidManifest.xml"),
    ("C", "构建", "build.gradle.kts"),
    ("C", "构建", "Makefile"),
    ("C", "构建", "settings.gradle.kts"),
    ("C", "构建", "gradle.properties"),
]

CFG_DIR = "app/src/main/assets/kernel_profiles/"


def git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


@dataclass
class Report:
    base: str
    head: str
    total_commits: int = 0
    commits: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    portable_c: list[tuple[str, str]] = field(default_factory=list)
    profiles: dict[str, int] = field(default_factory=dict)
    top_level: list[str] = field(default_factory=list)

    def add(self, layer: str, subject: str, sha: str) -> None:
        self.commits.setdefault(layer, []).append((sha, subject))


def layer_of(path: str) -> tuple[str, str] | None:
    for layer, name, prefix in LAYER_RULES:
        if path.startswith(prefix):
            return layer, name
    return None


def collect(repo: Path, base: str, head: str) -> Report:
    rep = Report(base=base, head=head)
    rep.total_commits = int(git(repo, "rev-list", "--count", f"{base}..{head}").strip() or 0)

    # one pass over the commits, each with the paths it touched
    raw = git(
        repo, "log", "--no-merges", "--format=@@%H%x09%s", "--name-only", f"{base}..{head}"
    )
    cur: tuple[str, str] | None = None
    seen: set[tuple[str, str]] = set()
    for line in raw.splitlines():
        if line.startswith("@@"):
            sha, _, subject = line[2:].partition("\t")
            cur = (sha, subject)
            continue
        # `git log --name-only` separates the header from the file list with a
        # blank line; resetting on it would drop every path of that commit
        if not line.strip() or cur is None:
            continue
        hit = layer_of(line.strip())
        if hit is None:
            continue
        key = (hit[0], cur[0])
        if key in seen:
            continue
        seen.add(key)
        rep.add(hit[0], cur[1], cur[0])
        if hit[0] == "B" and cur[1].startswith(("fix(", "feat(")):
            rep.portable_c.append((cur[0], cur[1]))

    # profile files: how many exist upstream now, and how many we could map
    cfg = git(repo, "ls-tree", "-r", "--name-only", head, "--", CFG_DIR).splitlines()
    rep.profiles["total"] = len(cfg)
    rep.profiles["templates"] = sum(1 for p in cfg if "template" in Path(p).name)

    # directories that only exist upstream -> architecture candidates
    top = git(repo, "ls-tree", "--name-only", head).splitlines()
    rep.top_level = sorted(top)
    return rep


def render(rep: Report) -> str:
    out: list[str] = []
    out.append(f"upstream range : {rep.base}..{rep.head}")
    out.append(f"commits        : {rep.total_commits}")
    out.append("")

    titles = {"A": "A 偏移数据", "B": "引擎补丁", "C": "App 逻辑"}
    for layer in ("A", "B", "C"):
        items = rep.commits.get(layer, [])
        out.append(f"[{titles.get(layer, layer)}] {len(items)} 个提交")
        for sha, subject in items[:12]:
            out.append(f"  {sha[:7]}  {subject}")
        if len(items) > 12:
            out.append(f"  … 另有 {len(items) - 12} 个")
        out.append("")

    out.append(f"[B 候选] fix()/feat() 且触碰 src/core：{len(rep.portable_c)} 条")
    for sha, subject in rep.portable_c[:15]:
        out.append(f"  {sha[:7]}  {subject}")
    if len(rep.portable_c) > 15:
        out.append(f"  … 另有 {len(rep.portable_c) - 15} 条")
    out.append("")

    p = rep.profiles
    out.append(f"[A 数据] 上游 kernel_profiles：{p.get('total', 0)} 个文件"
               f"（模板 {p.get('templates', 0)}，工作区可见 {p.get('top_level', 0)}）")
    out.append("         下一步：tools/sync/conf_to_offsets.py --diff <release>.conf")
    out.append("")

    out.append("[D 架构] 上游顶层目录（与本地对比后判定，不移植）")
    out.append("  " + "  ".join(rep.top_level))
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=DEFAULT_REPO, help="reference clone of ghostlock-app")
    ap.add_argument("--base", default=DEFAULT_BASE, help="fork point (default: 50d2b72)")
    ap.add_argument("--head", default="HEAD", help="upstream revision to inspect")
    args = ap.parse_args()

    if not (args.repo / ".git").exists():
        raise SystemExit(f"not a git clone: {args.repo}")

    rep = collect(args.repo, args.base, args.head)
    print(render(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
