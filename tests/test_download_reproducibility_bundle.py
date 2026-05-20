import json

from scripts import download_reproducibility_bundle


def test_download_bundle_selects_named_bundle_from_metadata(tmp_path, monkeypatch, capsys):
    metadata_path = tmp_path / "release_artifacts.json"
    metadata_path.write_text(
        json.dumps(
            {
                "status": "published",
                "bundles": [
                    {
                        "name": "first",
                        "filename": "first.zip",
                        "url": "file://first.zip",
                        "sha256": "a",
                        "bytes": 1,
                    },
                    {
                        "name": "second",
                        "filename": "second.zip",
                        "url": "file://second.zip",
                        "sha256": "b",
                        "bytes": 2,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    seen = {}

    def fake_download(source, *, output_path, expected_sha256, expected_bytes):
        seen.update(
            {
                "source": source,
                "output_path": str(output_path),
                "expected_sha256": expected_sha256,
                "expected_bytes": expected_bytes,
            }
        )
        return {"status": "ok"}

    monkeypatch.setattr(download_reproducibility_bundle, "download_bundle_file", fake_download)
    monkeypatch.setattr(
        "sys.argv",
        [
            "download_reproducibility_bundle.py",
            "--metadata",
            str(metadata_path),
            "--bundle-name",
            "second",
            "--output",
            str(tmp_path / "out.zip"),
        ],
    )

    assert download_reproducibility_bundle.main() == 0
    assert seen["source"] == "file://second.zip"
    assert seen["expected_sha256"] == "b"
    assert seen["expected_bytes"] == 2
    assert json.loads(capsys.readouterr().out)["release_metadata"]["name"] == "second"
