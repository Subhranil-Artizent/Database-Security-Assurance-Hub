from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.validate_control_packs import validate_repository  # noqa: E402


SOURCE_ROOT = REPOSITORY_ROOT / "control-packs"
QUERY_CATALOG = (
    REPOSITORY_ROOT / "services" / "api" / "assurance_hub" / "query_catalog.py"
)
class ControlPackValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="aegisdb-control-pack-"
        )
        self.addCleanup(self.temporary_directory.cleanup)
        self.control_pack_root = Path(self.temporary_directory.name) / "control-packs"
        shutil.copytree(SOURCE_ROOT, self.control_pack_root)

    def _pack_path(self, platform: str) -> Path:
        return self.control_pack_root / "packs" / platform / "database-security" / "1.0.0.json"

    def _load(self, path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, path: Path, value: dict[str, Any]) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def _refresh_manifest_digest(self, pack_path: Path) -> None:
        manifest_path = self.control_pack_root / "manifest.json"
        manifest = self._load(manifest_path)
        relative_path = pack_path.relative_to(self.control_pack_root).as_posix()
        for entry in manifest["packs"]:
            if entry["path"] == relative_path:
                entry["sha256"] = hashlib.sha256(pack_path.read_bytes()).hexdigest()
                break
        else:
            self.fail(f"test pack {relative_path} is absent from manifest")
        self._write(manifest_path, manifest)

    def _messages(self) -> list[str]:
        return [
            str(issue)
            for issue in validate_repository(self.control_pack_root, QUERY_CATALOG)
        ]

    def test_repository_is_valid(self) -> None:
        self.assertEqual(self._messages(), [])

    def test_rejects_unapproved_probe_id(self) -> None:
        path = self._pack_path("oracle")
        pack = self._load(path)
        pack["controls"][0]["assessment"]["probe_ids"] = ["oracle.execute_anything"]
        self._write(path, pack)
        self._refresh_manifest_digest(path)

        messages = self._messages()

        self.assertTrue(any("is not approved for platform 'oracle'" in item for item in messages))

    def test_rejects_probe_from_wrong_domain(self) -> None:
        path = self._pack_path("postgresql")
        pack = self._load(path)
        pack["controls"][0]["assessment"]["probe_ids"] = ["postgresql.role_posture"]
        self._write(path, pack)
        self._refresh_manifest_digest(path)

        messages = self._messages()

        self.assertTrue(any("belongs to domain 'access_security'" in item for item in messages))

    def test_rejects_embedded_sql_even_when_digest_is_refreshed(self) -> None:
        path = self._pack_path("oracle")
        pack = self._load(path)
        pack["controls"][0]["assessment"]["sql"] = "SELECT * FROM customer_data"
        self._write(path, pack)
        self._refresh_manifest_digest(path)

        messages = self._messages()

        self.assertTrue(any("forbidden field name" in item for item in messages))
        self.assertTrue(any("additional property is not allowed" in item for item in messages))

    def test_detects_immutable_content_digest_change(self) -> None:
        path = self._pack_path("sybase")
        pack = self._load(path)
        pack["description"] += " Review pending."
        self._write(path, pack)

        messages = self._messages()

        self.assertTrue(any("sha256 mismatch" in item for item in messages))

    def test_requires_all_four_control_domains(self) -> None:
        path = self._pack_path("oracle")
        pack = self._load(path)
        pack["controls"] = [
            control for control in pack["controls"] if control["domain"] != "data_masking"
        ]
        self._write(path, pack)
        self._refresh_manifest_digest(path)

        messages = self._messages()

        self.assertTrue(any("missing required control domains" in item for item in messages))

    def test_manual_evidence_cannot_claim_automatic_decision(self) -> None:
        path = self._pack_path("postgresql")
        pack = self._load(path)
        masking = next(
            control for control in pack["controls"] if control["domain"] == "data_masking"
        )
        masking["assessment"]["decision_mode"] = "automatic_pass_fail"
        self._write(path, pack)
        self._refresh_manifest_digest(path)

        messages = self._messages()

        self.assertTrue(any("decision_mode" in item and "analyst_review_required" in item for item in messages))

    def test_rejects_unregistered_version_file(self) -> None:
        source = self._pack_path("oracle")
        unregistered = source.with_name("1.0.1.json")
        shutil.copyfile(source, unregistered)

        messages = self._messages()

        self.assertTrue(any("not registered in the immutable manifest" in item for item in messages))


if __name__ == "__main__":
    unittest.main()
