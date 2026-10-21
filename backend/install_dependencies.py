from __future__ import annotations

import hashlib
from importlib import metadata
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

# SSLyze 6.3.1 predates cryptography 50 and declares <47. Upstream PR #728
# changes only this compatibility ceiling to <51. Beacon applies that exact
# metadata-only change to the checksum-verified official 6.3.1 source archive
# until an upstream release containing the fix is available.
SSLYZE_VERSION = "6.3.1"
SSLYZE_URL = (
    "https://files.pythonhosted.org/packages/source/s/sslyze/"
    f"sslyze-{SSLYZE_VERSION}.tar.gz"
)
SSLYZE_SHA256 = "2cd4062f82a3fa605dbd34e3b71f99961e4e7cf438879da1c52f619855ffbc1d"
OLD_REQUIREMENT = "cryptography>=43,<47"
PATCHED_REQUIREMENT = "cryptography>=43,<51"
ROOT = Path(__file__).resolve().parent


def pip(*args: str) -> None:
    subprocess.run(
        [sys.executable, "-m", "pip", *args],
        check=True,
    )


def install_sslyze() -> None:
    with tempfile.TemporaryDirectory(prefix="beacon-sslyze-") as temporary:
        temp = Path(temporary)
        archive = temp / f"sslyze-{SSLYZE_VERSION}.tar.gz"
        with urllib.request.urlopen(SSLYZE_URL, timeout=30) as response:
            archive.write_bytes(response.read())

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != SSLYZE_SHA256:
            raise RuntimeError("SSLyze source archive checksum mismatch")

        with tarfile.open(archive, "r:gz") as source_archive:
            source_archive.extractall(temp, filter="data")

        source = temp / f"sslyze-{SSLYZE_VERSION}"
        setup_py = source / "setup.py"
        setup_source = setup_py.read_text(encoding="utf-8")
        if setup_source.count(OLD_REQUIREMENT) != 1:
            raise RuntimeError("Unexpected SSLyze dependency metadata")
        setup_py.write_text(
            setup_source.replace(OLD_REQUIREMENT, PATCHED_REQUIREMENT),
            encoding="utf-8",
        )
        pip("install", "--no-deps", "--no-build-isolation", str(source))


def verify_sslyze_metadata() -> None:
    requirements = metadata.metadata("sslyze").get_all("Requires-Dist") or []
    crypto_requirements = [item for item in requirements if "cryptography" in item]
    if not any("<51" in item for item in crypto_requirements):
        raise RuntimeError("Patched SSLyze cryptography constraint is missing")


def main() -> None:
    pip(
        "install",
        "--require-hashes",
        "--requirement",
        str(ROOT / "requirements.lock"),
    )
    install_sslyze()
    verify_sslyze_metadata()
    pip("check")


if __name__ == "__main__":
    main()
