from secops.mode_profiles import MODE_PROFILES, get_mode_profile


def test_mode_profiles_include_required_modes() -> None:
    assert {"ctf", "koth", "pentest", "bugbounty"}.issubset(MODE_PROFILES.keys())


def test_koth_profile_keeps_koth_playbook() -> None:
    profile = get_mode_profile("koth")
    assert any("koth_playbook.md" in path for path in profile.startup_paths)
    assert "koth" in profile.learn_tags
