"""Release packages must be deterministic, inspectable and legally complete."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("phprotect_build", ROOT / "build.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class ReleasePackages(unittest.TestCase):
    def test_reproducible_packages_match_runtime_source(self):
        out = ROOT / ".test-output"
        out.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=out) as temp:
            original_dist = builder.DIST
            builder.DIST = Path(temp).resolve()
            self.assertTrue(builder.DIST.is_relative_to(out.resolve()))
            try:
                for target in ("chrome", "firefox"):
                    first = builder.build(target)
                    before = hashlib.sha256(first.read_bytes()).hexdigest()
                    second = builder.build(target)
                    self.assertEqual(before, hashlib.sha256(second.read_bytes()).hexdigest())
                    with zipfile.ZipFile(second) as package:
                        names = package.namelist()
                        self.assertNotIn("manifest.base.json", names)
                        for required in ("manifest.json", "help.html", "privacy.html", "LICENSE", "NOTICE", "third_party/Apache-2.0.txt", "third_party/BIP39-MIT.txt", "third_party/upstream-MIT.txt"):
                            self.assertIn(required, names)
                        manifest = json.loads(package.read("manifest.json"))
                        self.assertEqual(manifest["version"], "1.1.0")
                        self.assertEqual(sorted(manifest["permissions"]), ["storage", "webRequest"])
                        for name in names:
                            self.assertNotIn("\\", name)
                            self.assertNotIn("..", Path(name).parts)
                            self.assertNotIn("node_modules", name)
                            self.assertNotIn(".map", name)
                            local = ROOT / "src" / name
                            if local.is_file():
                                self.assertEqual(package.read(name), local.read_bytes(), name)
                        if target == "chrome":
                            self.assertEqual(manifest["background"], {"service_worker": "background.js"})
                        else:
                            self.assertEqual(manifest["browser_specific_settings"]["gecko"]["data_collection_permissions"], {"required": ["none"]})
            finally:
                builder.DIST = original_dist

    def test_privacy_page_contains_current_policy(self):
        import html
        policy = (ROOT / "PRIVACY.md").read_text(encoding="utf-8")
        page = (ROOT / "src" / "privacy.html").read_text(encoding="utf-8")
        for paragraph in policy.split("\n\n"):
            if not paragraph.strip():
                continue
            for line in paragraph.splitlines():
                text = line.lstrip("#- ").strip()
                self.assertIn(html.escape(text), page)

if __name__ == "__main__":
    unittest.main()
