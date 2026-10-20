"""Guards the printer share's hardening settings against accidental edits."""

import configparser
from pathlib import Path

import pytest

CONF = Path(__file__).parent.parent / "deploy" / "samba" / "smb.conf"


@pytest.fixture(scope="module")
def conf():
    parser = configparser.ConfigParser(
        inline_comment_prefixes=(";",), comment_prefixes=("#", ";"), interpolation=None
    )
    parser.read(CONF)
    return parser


@pytest.mark.parametrize(
    ("section", "key", "expected"),
    [
        ("global", "server min protocol", "SMB2_02"),
        ("global", "map to guest", "never"),
        ("global", "restrict anonymous", "2"),
        ("global", "ntlm auth", "ntlmv2-only"),
        ("global", "follow symlinks", "no"),
        ("global", "wide links", "no"),
        ("global", "unix extensions", "no"),
        ("global", "disable netbios", "yes"),
        ("global", "load printers", "no"),
        ("scans", "path", "/inbox"),
        ("scans", "valid users", "scanner"),
        ("scans", "browseable", "no"),
        ("scans", "create mask", "0660"),
        ("scans", "directory mask", "0770"),
    ],
)
def test_hardening_setting(conf, section, key, expected):
    assert conf[section][key] == expected


def test_only_one_share(conf):
    assert conf.sections() == ["global", "scans"]


def test_no_guest_access(conf):
    for section in conf.sections():
        assert conf[section].get("guest ok", "no") == "no"
        assert conf[section].get("public", "no") == "no"


def test_entrypoint_reads_password_from_a_secret_file():
    script = (CONF.parent / "entrypoint.sh").read_text()
    assert "SCANNER_PASSWORD_FILE" in script
    assert "smbpasswd -s" in script
    assert "set -x" not in script
