#!/usr/bin/env python3
"""Build PHProtect for Chrome/Edge/Brave and Firefox.

Outputs dist/phprotect-chrome.zip and dist/phprotect-firefox.zip.
Fixed zip timestamps so a rebuild of identical sources is byte-identical.
"""
import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from tools.render_privacy import render as render_privacy

ROOT = Path(__file__).resolve().parent
SRC, DIST = ROOT / "src", ROOT / "dist"
FIREFOX_ID = "phprotect@phprotect-extension"

# Only reviewable runtime assets ship; source manifests and tooling stay out.
ASSET_SUFFIXES = {".js", ".css", ".html", ".json", ".png"}


def manifest(target: str) -> dict:
    m = json.loads((SRC / "manifest.base.json").read_text(encoding="utf-8"))
    if target == "chrome":
        m["background"] = {"service_worker": "background.js"}
        m["minimum_chrome_version"] = "116"
    else:
        m["background"] = {"scripts": ["assess.js", "background.js"]}
        m["browser_specific_settings"] = {
            "gecko": {
                "id": FIREFOX_ID,
                "strict_min_version": "128.0",
                "data_collection_permissions": {"required": ["none"]},
            }
        }
    return m


def build(target: str) -> Path:
    out = DIST / f"phprotect-{target}"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    for source in sorted(SRC.rglob("*")):
        if not source.is_file() or source.name == "manifest.base.json" or source.suffix not in ASSET_SUFFIXES:
            continue
        dest = out / source.relative_to(SRC)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
    for name in ("LICENSE", "NOTICE"):
        shutil.copyfile(ROOT / name, out / name)
    shutil.copytree(ROOT / "third_party", out / "third_party")
    (out / "manifest.json").write_text(
        json.dumps(manifest(target), indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    zpath = DIST / f"phprotect-{target}.zip"
    zpath.unlink(missing_ok=True)
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(out.rglob("*")):
            if not f.is_file():
                continue
            info = zipfile.ZipInfo(f.relative_to(out).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            z.writestr(info, f.read_bytes())
    digest = hashlib.sha256(zpath.read_bytes()).hexdigest()
    print(f"built {zpath.relative_to(ROOT)} sha256:{digest}")
    return zpath


def build_source() -> Path:
    """An inspectable source release, excluding local state and dependencies."""
    files = []
    for folder in ("src", "tools", "tests", "third_party", "store", "docs", ".github"):
        files.extend(p for p in (ROOT / folder).rglob("*") if p.is_file()
                     and "__pycache__" not in p.parts and p.suffix != ".pyc")
    for name in ("README.md", "LICENSE", "NOTICE", "PRIVACY.md", "THREAT-MODEL.md",
                 "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "HANDOFF.md", "build.py",
                 "package.json", "package-lock.json", ".gitignore", ".gitattributes", ".prettierrc.json", ".prettierignore"):
        files.append(ROOT / name)
    zpath = DIST / "phprotect-source.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(files):
            info = zipfile.ZipInfo(source.relative_to(ROOT).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes())
    print(f"built {zpath.relative_to(ROOT)} sha256:{hashlib.sha256(zpath.read_bytes()).hexdigest()}")
    return zpath


if __name__ == "__main__":
    render_privacy()
    DIST.mkdir(exist_ok=True)
    for t in ("chrome", "firefox"):
        build(t)
    build_source()
    paths = sorted(DIST.glob("phprotect-*.zip"))
    (DIST / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in paths
    ), encoding="utf-8", newline="\n")
