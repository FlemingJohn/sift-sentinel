import hashlib
from pathlib import PurePosixPath

CHUNK_SIZE = 8 * 1024 * 1024


def wsl_to_windows_path(path):
    parts = PurePosixPath(path).parts
    if len(parts) >= 3 and parts[0] == "/" and parts[1] == "mnt" and len(parts[2]) == 1:
        drive = parts[2].upper() + ":\\"
        return drive + "\\".join(parts[3:])
    return path


def compute_evidence_hashes(host_path):
    windows_path = wsl_to_windows_path(host_path)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(windows_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
