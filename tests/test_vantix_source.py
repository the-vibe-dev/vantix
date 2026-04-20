from secops.services.vantix import _normalize_source_input


def test_normalize_source_input_defaults_to_none() -> None:
    assert _normalize_source_input(None) == {"type": "none"}
    assert _normalize_source_input({"type": "weird"}) == {"type": "none"}


def test_normalize_source_input_variants() -> None:
    github = _normalize_source_input({"type": "github", "github": {"url": "https://github.com/example/repo", "ref": "main"}})
    assert github["type"] == "github"
    assert github["github"]["url"] == "https://github.com/example/repo"

    local = _normalize_source_input({"type": "local", "local": {"path": "/tmp/src"}})
    assert local == {"type": "local", "local": {"path": "/tmp/src"}}

    upload = _normalize_source_input({"type": "upload", "upload": {"staged_upload_id": "src-abc"}})
    assert upload == {"type": "upload", "upload": {"staged_upload_id": "src-abc"}}

