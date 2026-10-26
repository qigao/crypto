"""GmSSL source provenance and exact vcpkg-cache handoff archive tests."""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import tarfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "tools/verify_gmssl_import.py"
spec = importlib.util.spec_from_file_location("crypto_gmssl_import", SCRIPT)
assert spec and spec.loader
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class GmSSLImportTest(unittest.TestCase):
    def test_port_metadata_stays_with_vcpkg(self):
        for path in ("portfile.cmake", "vcpkg.json", "GmSSLConfig.cmake"):
            group, target = verifier.classify(path)
            self.assertEqual(group, "vcpkg-packaging")
            self.assertTrue(target.startswith("vcpkg-cache/"))

    def test_gmssl_sources_preserve_sibling_backport_layout(self):
        pairs = {
            "aes_key_wrap.c": "providers/gmssl/patches/aes_key_wrap.c",
            "backports/secp384r1_verify.c":
                "providers/gmssl/patches/backports/secp384r1_verify.c",
            "external-io.cmake": "providers/gmssl/patches/external-io.cmake",
            "tests/fixtures/p384-ca-sha384.pem":
                "providers/gmssl/tests/fixtures/p384-ca-sha384.pem",
        }
        for source, target in pairs.items():
            with self.subTest(source=source):
                self.assertEqual(verifier.classify(source)[1], target)

    def test_traversal_noncanonical_and_unclassified_files_rejected(self):
        for path in (
            "../bad", "tests/../../bad", "/absolute", "tests//twice.c",
            "notes.md", "", "patches\\windows.c",
        ):
            with self.subTest(path=path):
                if "\\" in path:
                    # Guard Windows path separators as well as POSIX ones.
                    self.assertRaises(ValueError, verifier.safe_path, path)
                else:
                    with self.assertRaises(ValueError):
                        verifier.classify(path)

    def test_content_hash_changes_on_byte_mutation(self):
        a = verifier.git_blob_sha(b"sha256\n")
        self.assertNotEqual(a, verifier.git_blob_sha(b"sha256\r\n"))
        self.assertEqual(len(a), 40)

    def test_deterministic_tar_preserves_exact_bytes(self):
        entries = {
            "providers/gmssl/patches/x509-compat.cmake": b"abc\r\n",
            "providers/gmssl/tests/example.c": b"int x;\n",
        }
        first = verifier.deterministic_tar(entries)
        self.assertEqual(first, verifier.deterministic_tar(entries))
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            self.assertEqual(archive.getnames(), sorted(entries))
            for path in sorted(entries):
                self.assertEqual(archive.extractfile(path).read(), entries[path])
                self.assertEqual(archive.getmember(path).mtime, 0)

    def test_actual_original_source_git_blobs_are_identical(self):
        manifest, files = verifier.verify()
        self.assertEqual(manifest["source"]["version"], "3.2.0")
        self.assertEqual(manifest["source"]["port_version"], 13)
        self.assertEqual(len(files), 95)

    def test_rebuilt_archive_matches_vcpkg_cache_artifact(self):
        _, files = verifier.verify()
        import hashlib
        digest = hashlib.sha256(verifier.deterministic_tar(files)).hexdigest()
        self.assertEqual(digest, verifier.EXPECTED_ARCHIVE_SHA256)


if __name__ == "__main__":
    unittest.main()
