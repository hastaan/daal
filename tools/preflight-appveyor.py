#!/usr/bin/env python3
"""
tools/preflight-appveyor.py — sanity-check appveyor.yml before push.

Validates every error class we've hit so far in the v0.1.0 build:

  1. YAML parses cleanly.
  2. No multi-line `cmd:` blocks (each YAML line runs as separate
     cmd.exe → multi-line `if exist (...)` etc. exits 255).
  3. No `where ...|| echo ...` patterns (cmd.exe propagates the
     intermediate errorlevel even after `||` rescue).
  4. Every `go build`/`go install` invocation is in a block that sets
     GOPATH and GOMODCACHE (Go 1.25 refuses to run without them).
  5. Every `go build`/`go install` invocation is in a block that sets
     GOTOOLCHAIN=local (so Go doesn't auto-download a different
     patch version and create a runtime-vs-tool version mismatch).
  6. Every `sh:` block uses `set -euo pipefail`.
  7. Deploy artifact regex matches every declared artifact path.
  8. Each `for:` block has a unique matrix selector.
  9. Every Go shared-lib build also exports CGO_ENABLED=1.
 10. Local end-to-end test of `gen-assets.sh` and `core/cmd/libdaalcore`
     in a clean-cache, GOTOOLCHAIN=local environment, mimicking what
     AppVeyor will do.

Exits 0 only when ALL checks pass. Run before every `git push`:

    python3 tools/preflight-appveyor.py
"""
from __future__ import annotations
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    print("FATAL: PyYAML not installed (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)


ROOT = Path(__file__).resolve().parent.parent
YAML_PATH = ROOT / "appveyor.yml"

CHECKS_PASSED: list[str] = []
ISSUES: list[str] = []


def ok(msg: str) -> None:
    CHECKS_PASSED.append(msg)
    print(f"  [ok]   {msg}")


def fail(msg: str) -> None:
    ISSUES.append(msg)
    print(f"  [FAIL] {msg}")


def warn(msg: str) -> None:
    print(f"  [warn] {msg}")


def iter_steps(d: dict):
    """Yield (location, lang, code) tuples for every install/build/after step."""
    for i, blk in enumerate(d.get("for", [])):
        for phase in ("install", "build_script", "after_build", "test_script"):
            for s in blk.get(phase) or []:
                if isinstance(s, dict):
                    for k, v in s.items():
                        if k in ("ps", "sh", "cmd") and isinstance(v, str):
                            yield (f"for[{i}].{phase}", k, v)
    for phase in ("init", "install", "build_script", "after_build"):
        for s in d.get(phase) or []:
            if isinstance(s, dict):
                for k, v in s.items():
                    if k in ("ps", "sh", "cmd") and isinstance(v, str):
                        yield (f"top.{phase}", k, v)


def check_yaml_parse() -> dict | None:
    print("\n[1] YAML parses cleanly")
    try:
        d = yaml.safe_load(YAML_PATH.read_text())
        ok(f"parsed {YAML_PATH}")
        return d
    except Exception as e:
        fail(f"YAML parse error: {e}")
        return None


def check_multiline_cmd(d: dict) -> None:
    print("\n[2] No multi-line cmd: blocks")
    found = False
    for loc, lang, v in iter_steps(d):
        if lang == "cmd" and "\n" in v.strip():
            fail(f"{loc}: multi-line cmd: block — AppVeyor runs each line as separate cmd.exe")
            found = True
    if not found:
        ok("no multi-line cmd: blocks")


def check_where_or_echo(d: dict) -> None:
    print("\n[3] No `where ... || echo ...` rescue patterns")
    found = False
    for loc, lang, v in iter_steps(d):
        if lang == "cmd" and re.search(r"\bwhere\b.*\|\|.*echo", v):
            fail(f"{loc}: `where ... || echo ...` — exit code propagates anyway")
            found = True
    if not found:
        ok("no fragile `where || echo` patterns")


def check_gopath(d: dict) -> None:
    print("\n[4] Go invocations set GOPATH + GOMODCACHE")
    found_any_go = False
    for loc, lang, v in iter_steps(d):
        if re.search(r"\bgo\s+(build|install|test|run|mod)\b", v):
            found_any_go = True
            has_gopath = "GOPATH" in v
            has_modcache = "GOMODCACHE" in v
            if has_gopath and has_modcache:
                ok(f"{loc} ({lang}): GOPATH+GOMODCACHE set")
            else:
                missing = []
                if not has_gopath:
                    missing.append("GOPATH")
                if not has_modcache:
                    missing.append("GOMODCACHE")
                fail(f"{loc} ({lang}): missing {missing}")
    if not found_any_go:
        warn("no go build/install invocations found anywhere — unexpected")


def check_gotoolchain(d: dict) -> None:
    print("\n[5] Go invocations set GOTOOLCHAIN=local (prevents version drift)")
    for loc, lang, v in iter_steps(d):
        if re.search(r"\bgo\s+(build|install|test|run)\b", v):
            if "GOTOOLCHAIN" in v:
                ok(f"{loc} ({lang}): GOTOOLCHAIN set")
            else:
                fail(
                    f"{loc} ({lang}): no GOTOOLCHAIN — Go auto-downloads newer patch "
                    f"and triggers 'go1.X.0 does not match go tool go1.X.Y' compile errors"
                )


def check_cgo_enabled(d: dict) -> None:
    print("\n[6] c-shared builds set CGO_ENABLED=1")
    for loc, lang, v in iter_steps(d):
        if "buildmode=c-shared" in v:
            if "CGO_ENABLED" in v:
                ok(f"{loc} ({lang}): CGO_ENABLED set")
            else:
                fail(f"{loc} ({lang}): c-shared build without CGO_ENABLED=1")


def check_set_e(d: dict) -> None:
    print("\n[7] All multi-line sh: blocks use `set -e` or `set -euo pipefail`")
    for loc, lang, v in iter_steps(d):
        # Single-command sh: lines (e.g. `init:` echoes) are fine without
        # `set -e` — only enforce on multi-statement blocks.
        if lang == "sh" and ("\n" in v.strip() or ";" in v):
            if "set -e" in v or "set -euo" in v:
                ok(f"{loc} sh: has `set -e`")
            else:
                fail(f"{loc} sh: missing `set -e`")


def check_deploy_regex(d: dict) -> None:
    print("\n[8] Deploy artifact regex matches every declared artifact")
    deploys = d.get("deploy") or []
    if not deploys:
        warn("no deploy section")
        return
    deploy_re = deploys[0].get("artifact", "").strip("/")
    if not deploy_re:
        warn("deploy.artifact is empty (matches everything)")
        return
    for i, blk in enumerate(d.get("for", [])):
        for art in blk.get("artifacts", []) or []:
            path = art.get("path", "")
            ext = path.rsplit(".", 1)[-1]
            test_name = f"foo.{ext}"
            if re.search(deploy_re, test_name, re.I):
                ok(f"for[{i}] artifact {path!r} matches deploy filter")
            else:
                fail(f"for[{i}] artifact {path!r} doesn't match deploy filter {deploy_re}")


def check_tauri_ci_lowercase(d: dict) -> None:
    """Tauri 2's clap parser rejects `CI=True` (capitalized) with
    "invalid value 'True' for '--ci'". AppVeyor exports CI=True by
    default, so every `npx tauri build` / `npm run tauri -- build`
    invocation must force `CI=true` first.
    """
    print("\n[7b] tauri build invocations override CI=true (lowercase)")
    for loc, lang, v in iter_steps(d):
        if "tauri" in v and "build" in v and (
            "npm run tauri" in v or "npx tauri" in v or "tauri build" in v
        ):
            # Check for CI=true (lowercase) in the same block.
            has_ci_lower = bool(
                re.search(r"\bCI\s*=\s*['\"]?true['\"]?\b", v)
                or re.search(r"\$env:CI\s*=\s*['\"]true['\"]", v)
            )
            if has_ci_lower:
                ok(f"{loc} ({lang}): tauri build forces CI=true")
            else:
                fail(
                    f"{loc} ({lang}): tauri build without CI=true override — "
                    f"AppVeyor's CI=True (capitalized) will trip clap's "
                    f"`invalid value 'True' for '--ci'`"
                )


def check_unique_matrix(d: dict) -> None:
    print("\n[9] Each `for:` block has a unique matrix selector")
    seen: set[tuple] = set()
    for i, blk in enumerate(d.get("for", [])):
        for sel in blk.get("matrix", {}).get("only", []):
            key = tuple(sorted(sel.items()))
            if key in seen:
                fail(f"for[{i}] selector duplicate: {sel}")
            seen.add(key)
    ok(f"{len(seen)} unique matrix selectors")


def check_local_go_build() -> None:
    print("\n[10a] Local Go build with GOTOOLCHAIN=local + fresh cache")
    go = shutil.which("go125") or "/usr/local/go125/bin/go"
    if not Path(go).exists():
        go = shutil.which("go")
    if not go:
        warn("no `go` binary found, skipping local build test")
        return
    tmp = Path(tempfile.mkdtemp(prefix="daal-preflight-"))
    try:
        env = os.environ.copy()
        env.update(
            {
                "GOPATH": str(tmp / "gopath"),
                "GOMODCACHE": str(tmp / "gopath" / "pkg" / "mod"),
                "GOTOOLCHAIN": "local",
                "CGO_ENABLED": "1",
                "HOME": str(tmp / "home"),
            }
        )
        Path(env["GOMODCACHE"]).mkdir(parents=True)
        Path(env["HOME"]).mkdir()
        result = subprocess.run(
            [
                go,
                "build",
                "-buildmode=c-shared",
                "-tags",
                "cshared",
                "-o",
                str(tmp / "libdaalcore.so"),
                "./cmd/libdaalcore",
            ],
            cwd=ROOT / "core",
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0 and (tmp / "libdaalcore.so").exists():
            size_mb = (tmp / "libdaalcore.so").stat().st_size / 1024 / 1024
            ok(f"local `go build -buildmode=c-shared` succeeds ({size_mb:.1f} MB)")
        else:
            fail(
                f"local go build failed (rc={result.returncode})\n"
                f"  stdout tail: {result.stdout[-300:]!r}\n"
                f"  stderr tail: {result.stderr[-300:]!r}"
            )
    except subprocess.TimeoutExpired:
        fail("local go build timed out after 5 min")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_local_gen_assets() -> None:
    print("\n[10b] Local gen-assets.sh runs to completion with magick-only PATH")
    script = ROOT / "tools" / "gen-assets.sh"
    if not script.exists():
        fail(f"missing {script}")
        return
    # Simulate Windows IM7 (only `magick` resolves, no `convert`).
    shim = Path(tempfile.mkdtemp(prefix="daal-shim-"))
    try:
        real = shutil.which("magick") or shutil.which("convert")
        if not real:
            warn("no IM binary found locally — skipping IM7 shim test")
            return
        (shim / "magick").write_text(f"#!/bin/bash\nexec {real} \"$@\"\n")
        (shim / "magick").chmod(0o755)
        clean_path = ":".join(p for p in os.environ["PATH"].split(":") if "/usr/bin" not in p)
        env = os.environ.copy()
        env["PATH"] = f"{shim}:{clean_path}"
        result = subprocess.run(
            ["bash", str(script)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode == 0:
            ok("gen-assets.sh succeeds with only `magick` (IM7 Windows scenario)")
        else:
            fail(
                f"gen-assets.sh failed (rc={result.returncode})\n"
                f"  stderr tail: {result.stderr[-300:]!r}"
            )
    finally:
        shutil.rmtree(shim, ignore_errors=True)


def main() -> int:
    d = check_yaml_parse()
    if d is None:
        return 1
    check_multiline_cmd(d)
    check_where_or_echo(d)
    check_gopath(d)
    check_gotoolchain(d)
    check_cgo_enabled(d)
    check_set_e(d)
    check_tauri_ci_lowercase(d)
    check_deploy_regex(d)
    check_unique_matrix(d)
    check_local_go_build()
    check_local_gen_assets()
    print()
    if ISSUES:
        print("=" * 70)
        print(f"FAILED: {len(ISSUES)} issue(s) — DO NOT push:")
        for i in ISSUES:
            print(f"  - {i}")
        return 1
    print("=" * 70)
    print(f"PREFLIGHT CLEAN — {len(CHECKS_PASSED)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
