"""
discover.py — SIFT MCP Tool Discovery
======================================
Run this ONCE on your SIFT machine (WSL) after cloning the repo.

Usage:
    python discover.py sift/packages

What it does:
    1. Reads package names from sift/packages/init.sls
    2. Asks the OS (dpkg -L) what binaries each package actually installs
    3. Checks shutil.which() — is the binary on PATH right now?
    4. Groups into servers using PACKAGE_CATEGORY (verified from WSL tests)
    5. Writes registry.json — everything else reads from this

All skip decisions in PACKAGE_CATEGORY are based on hard evidence
from actual WSL verification testing, not assumptions.
"""

import subprocess
import json
import re
import shutil
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone


# ══════════════════════════════════════════════════════════════════════════════
# PACKAGE_CATEGORY
# Every entry verified against actual SIFT WSL output.
# Skip reasons documented inline with evidence.
# ══════════════════════════════════════════════════════════════════════════════

PACKAGE_CATEGORY = {

    # ── sift-disk ─────────────────────────────────────────────────────────────
    # Filesystem imaging, carving, recovery, mounting tools

    "afflib-tools":      "disk",   # affinfo, affcat, affconvert etc — all CLI
    "avfs":              "disk",   # mountavfs, umountavfs — CLI confirmed
    "dc3dd":             "disk",   # forensic dd — CLI confirmed
    "dcfldd":            "disk",   # forensic dd variant — CLI confirmed
    "disktype":          "disk",   # detects disk/fs type — CLI confirmed
    "e2fsprogs":         "disk",   # debugfs, dumpe2fs, e2fsck — CLI confirmed
    "ewf-tools":         "disk",   # ewfinfo, ewfacquire, ewfmount — CLI confirmed
    "exfat-extras":      "disk",   # mkfs.exfat, dumpexfat — CLI confirmed
    "exfat-fuse":        "disk",   # mount.exfat-fuse — CLI confirmed
    "exif":              "disk",   # reads EXIF metadata — CLI confirmed
    "extundelete":       "disk",   # ext3/4 file recovery — CLI confirmed
    "fdupes":            "disk",   # find duplicate files — CLI confirmed
    "feh":               "disk",   # VERIFIED WSL: --list mode works without display
    "file":              "disk",   # file type detection — CLI confirmed
    "foremost":          "disk",   # file carving — CLI confirmed
    "gddrescue":         "disk",   # ddrescue — CLI confirmed
    "gzrt":              "disk",   # gzrecover — CLI confirmed
    "jq":                "disk",   # VERIFIED WSL: echo '{"pid":1}' | jq '.pid' → 123
    "kpartx":            "disk",   # partition mapping — CLI confirmed
    "libewf-tools":      "disk",   # ewf tools (libyal upstream) — dedupe with ewf-tools at runtime
    "libfsapfs-tools":   "disk",   # fsapfsinfo, fsapfsmount — CLI confirmed
    "libguestfs-tools":  "disk",   # guestfish, virt-cat, virt-ls etc — CLI confirmed
    "libplist-utils":    "disk",   # plistutil — CLI confirmed
    "lvm2":              "disk",   # lvcreate, lvdisplay, pvdisplay — CLI confirmed
    "mdadm":             "disk",   # RAID management/inspection — CLI confirmed
    "mtd-utils":         "disk",   # flash/NAND tools — CLI confirmed
    "nbd-client":        "disk",   # network block device client — CLI confirmed
    "ntfs-3g":           "disk",   # ntfscat, ntfsls, ntfsundelete — CLI confirmed
    "p7zip-full":        "disk",   # 7z, 7za, 7zr — CLI confirmed
    "qemu-utils":        "disk",   # VERIFIED WSL: qemu-img --help → exit 0
    "rar":               "disk",   # rar archive tool — CLI confirmed
    "safecopy":          "disk",   # bad-block aware copy — CLI confirmed
    "scalpel":           "disk",   # file carving — CLI confirmed
    "sleuthkit":         "disk",   # fls, mmls, istat, blkcat, tsk_* — CLI confirmed
    "squashfs-tools":    "disk",   # mksquashfs, unsquashfs — CLI confirmed
    "testdisk":          "disk",   # testdisk, photorec — CLI confirmed
    "unrar":             "disk",   # unrar archives — CLI confirmed
    "vmfs-tools":        "disk",   # vmfs-fuse, debugvmfs3 — CLI confirmed
    "vbindiff":          "disk",   # VERIFIED WSL: --help exit 0, FILE args work
    "xfsprogs":          "disk",   # xfs_repair, xfs_db, xfs_info — CLI confirmed
    "xmount":            "disk",   # image format converter/mounter — CLI confirmed
    "git":               "disk",   # VERIFIED WSL: git --version → 2.34.1 — forensic repo analysis
    "autopsy":           "disk",   # VERIFIED WSL: runs web server :9999, NOT a GUI binary

    # ── sift-windows ──────────────────────────────────────────────────────────
    # Windows artifact parsing — registry, event logs, email, timeline

    "cabextract":        "windows", # extract Windows CAB files — CLI confirmed
    "libesedb-tools":    "windows", # esedbinfo, esedbexport — CLI confirmed
    "libevt-tools":      "windows", # evtinfo, evtexport — CLI confirmed
    "libevtx-tools":     "windows", # evtxinfo, evtxexport — CLI confirmed
    "libregf-tools":     "windows", # regfinfo, regfexport, regfmount — CLI confirmed
    "libvshadow-tools":  "windows", # vshadowinfo, vshadowmount — CLI confirmed
    "pff-tools":         "windows", # pffinfo, pffexport (PST/OST) — CLI confirmed
    "plaso-tools":       "windows", # log2timeline.py, psort.py, pinfo.py — CLI confirmed
    "powershell":        "windows", # pwsh — CLI confirmed
    "pst-utils":         "windows", # readpst, pst2ldif — CLI confirmed
    "samdump2":          "windows", # dump SAM hashes — CLI confirmed

    # ── sift-network ──────────────────────────────────────────────────────────
    # Network forensics — pcap analysis, flow data, passive fingerprinting

    "aircrack-ng":       "network", # aircrack-ng suite — CLI confirmed
    "arp-scan":          "network", # ARP host discovery — CLI confirmed
    "cifs-utils":        "network", # mount.cifs, smbinfo — CLI confirmed
    "cryptcat":          "network", # netcat with encryption — CLI confirmed
    "dsniff":            "network", # dsniff, urlsnarf, filesnarf etc — CLI confirmed
    "driftnet":          "network", # VERIFIED WSL: -a -d /tmp/out -i lo adjunct mode works
    "ettercap-graphical":"network", # ettercap -T text mode — CLI confirmed
    "etherape":          "network", # VERIFIED WSL: -r replay + --final-export headless works
    "grepcidr":          "network", # CIDR grep — CLI confirmed
    "lft":               "network", # layer4 traceroute — CLI confirmed
    "nbtscan":           "network", # NetBIOS scanner — CLI confirmed
    "netcat":            "network", # nc — CLI confirmed
    "netsed":            "network", # network stream editor — CLI confirmed
    "netwox":            "network", # network toolbox — CLI confirmed
    "nfdump":            "network", # nfdump, nfcapd, nfreplay — CLI confirmed
    "ngrep":             "network", # network grep — CLI confirmed
    "nikto":             "network", # web scanner — CLI confirmed
    "p0f":               "network", # passive OS fingerprinting — CLI confirmed
    "python-flowgrep":   "network", # flowgrep — CLI confirmed
    "socat":             "network", # socket relay — CLI confirmed
    "ssldump":           "network", # SSL/TLS decoder — CLI confirmed
    "sslsniff":          "network", # SSL MITM — CLI confirmed
    "tcpflow":           "network", # TCP stream reassembler — CLI confirmed
    "tcpick":            "network", # TCP stream sniffer — CLI confirmed
    "tcpreplay":         "network", # tcpreplay, tcprewrite, tcpprep — CLI confirmed
    "tcpslice":          "network", # pcap time slicer — CLI confirmed
    "tcpstat":           "network", # pcap statistics — CLI confirmed
    "tcptrace":          "network", # TCP analysis — CLI confirmed
    "tcptrack":          "network", # VERIFIED WSL: --help exit 0, -r flag works
    "tcpxtract":         "network", # extract files from pcap — CLI confirmed
    "wireshark":         "network", # tshark, capinfos, editcap, mergecap — CLI confirmed

    # ── sift-memory ───────────────────────────────────────────────────────────
    # Memory image analysis, string/key extraction

    "aeskeyfind":        "memory",  # AES key finder in memory — CLI confirmed
    "bulk-extractor":    "memory",  # bulk_extractor — CLI confirmed
    "ent":               "memory",  # entropy analysis — CLI confirmed
    "rsakeyfind":        "memory",  # RSA key finder in memory — CLI confirmed

    # ── sift-hashing ──────────────────────────────────────────────────────────
    # Hash computation and verification

    "hashdeep":          "hashing", # hashdeep, md5deep, sha1deep, sha256deep — CLI confirmed
    "ssdeep":            "hashing", # fuzzy hashing — CLI confirmed

    # ── sift-malware ──────────────────────────────────────────────────────────
    # Malware analysis, PE inspection, reverse engineering

    "clamav":            "malware", # clamscan, clamdscan, sigtool — CLI confirmed
    "gdb":               "malware", # debugger batch mode (-batch -ex) — CLI confirmed
    "pev":               "malware", # readpe, pesec, pepack, pehash etc — CLI confirmed
    "radare2":           "malware", # r2, rabin2, rahash2, radiff2 etc — CLI confirmed
    "upx-ucl":           "malware", # upx packer/unpacker — CLI confirmed
    "wine":              "malware", # VERIFIED WSL: wine --version → wine-6.0.3 — Windows binary analysis

    # ── sift-crypto ───────────────────────────────────────────────────────────
    # Encryption, decryption, password cracking, BitLocker/FileVault

    "ccrypt":            "crypto",  # ccrypt, ccencrypt, ccdecrypt — CLI confirmed
    "cmospwd":           "crypto",  # CMOS password dump — CLI confirmed
    "cryptsetup":        "crypto",  # LUKS container tool — CLI confirmed
    "dislocker":         "crypto",  # BitLocker — dislocker, dislocker-find etc — CLI confirmed
    "hydra":             "crypto",  # hydra, pw-inspector — CLI confirmed
    "libbde-tools":      "crypto",  # bdeinfo, bdemount (BitLocker) — CLI confirmed
    "libfvde-tools":     "crypto",  # fvdeinfo, fvdemount (FileVault) — CLI confirmed
    "ophcrack-cli":      "crypto",  # ophcrack-cli batch mode — CLI confirmed
    "ophcrack":          "crypto",  # VERIFIED WSL: -b -t -f batch flags confirmed working
    "outguess":          "crypto",  # steganography — CLI confirmed

    # ── sift-container ────────────────────────────────────────────────────────
    # Container forensics — NEW SERVER from WSL verification

    "docker":            "container", # VERIFIED WSL: docker inspect confirmed → container forensics

    # ── sift-cloud ────────────────────────────────────────────────────────────
    # Cloud forensics — NEW SERVER from WSL verification

    "aws-cli":           "cloud",   # VERIFIED WSL: aws-cli/2.15.24 confirmed → S3 evidence pull

    # ── sift-mobile ───────────────────────────────────────────────────────────
    # Mobile device forensics — NEW SERVER

    "android-sdk-platform-tools": "mobile",  # adb, fastboot — CLI confirmed

    # ══════════════════════════════════════════════════════════════════════════
    # PERMANENT SKIPS — hard evidence from WSL verification
    # ══════════════════════════════════════════════════════════════════════════

    # TIMEOUT x2 in WSL — hangs permanently, cannot produce output
    "bless":             "SKIP:TIMEOUT",    # bless --help TIMEOUT, bless --version TIMEOUT
    "kdiff3":            "SKIP:TIMEOUT",    # kdiff3 --help TIMEOUT, kdiff3 --auto TIMEOUT
    "magnus":            "SKIP:TIMEOUT",    # magnus --help TIMEOUT — GTK Gdk errors

    # NEEDS-DISPLAY — --help output contains --help-gtk / GTK errors
    "ghex":              "SKIP:DISPLAY",    # help says GTK binary editor, crashes without display
    "gthumb":            "SKIP:DISPLAY",    # help says --help-gtk --help-clutter
    "zenity":            "SKIP:DISPLAY",    # dialog renderer, needs display for any operation
    "transmission":      "SKIP:DISPLAY",    # transmission-gtk --help-gtk confirmed
    "unity-control-center": "SKIP:DISPLAY", # system settings panel, needs display
    "chromium-browser":  "SKIP:DISPLAY",    # snap sandbox errors in WSL, cannot run headless

    # NOT INSTALLED on this SIFT build
    "transmission-cli":  "SKIP:NOT_INSTALLED",

    # LIBRARY — .so files only, no CLI binary
    "libafflib":         "SKIP:LIBRARY",
    "libafflib-dev":     "SKIP:LIBRARY",
    "libasound2-dev":    "SKIP:LIBRARY",
    "libbcprov-java":    "SKIP:LIBRARY",
    "libbde":            "SKIP:LIBRARY",
    "libbz2-dev":        "SKIP:LIBRARY",
    "libcairo2-dev":     "SKIP:LIBRARY",
    "libcommons-lang3-java": "SKIP:LIBRARY",
    "libdatetime-perl":  "SKIP:LIBRARY",
    "libencode-perl":    "SKIP:LIBRARY",
    "libesedb":          "SKIP:LIBRARY",
    "libevt":            "SKIP:LIBRARY",
    "libevtx":           "SKIP:LIBRARY",
    "libewf":            "SKIP:LIBRARY",
    "libewf2":           "SKIP:LIBRARY",
    "libewf-dev":        "SKIP:LIBRARY",
    "libext2fs2":        "SKIP:LIBRARY",
    "libffi-dev":        "SKIP:LIBRARY",
    "libfuse-dev":       "SKIP:LIBRARY",
    "libfvde":           "SKIP:LIBRARY",
    "libgirepository":   "SKIP:LIBRARY",
    "libglib2-bin":      "SKIP:LIBRARY",
    "libgtk-3-dev":      "SKIP:LIBRARY",
    "libicu":            "SKIP:LIBRARY",
    "liblightgrep":      "SKIP:LIBRARY",
    "libmsiecf":         "SKIP:LIBRARY",   # no -tools sibling, no CLI
    "libncurses":        "SKIP:LIBRARY",
    "libnet1":           "SKIP:LIBRARY",
    "libolecf":          "SKIP:LIBRARY",   # no -tools sibling, no CLI
    "libpcap-dev":       "SKIP:LIBRARY",
    "libpff":            "SKIP:LIBRARY",
    "libpff-dev":        "SKIP:LIBRARY",
    "libregf":           "SKIP:LIBRARY",
    "libregf-dev":       "SKIP:LIBRARY",
    "libssl-dev":        "SKIP:LIBRARY",
    "libtext-csv-perl":  "SKIP:LIBRARY",
    "libvhdi":           "SKIP:LIBRARY",   # no -tools sibling
    "libvmdk":           "SKIP:LIBRARY",   # no -tools sibling
    "libvshadow":        "SKIP:LIBRARY",
    "libvshadow-dev":    "SKIP:LIBRARY",
    "libxml2-dev":       "SKIP:LIBRARY",
    "libxslt-dev":       "SKIP:LIBRARY",
    "libyara3":          "SKIP:LIBRARY",   # C lib only, no yara CLI
    "phonon":            "SKIP:LIBRARY",
    "blt":               "SKIP:LIBRARY",
    "zlib1g-dev":        "SKIP:LIBRARY",

    # IMPORTABLE Python packages — import directly, no subprocess needed
    # These become native Python MCP tools in sift_native.py instead
    "libewf-python3":    "SKIP:IMPORTABLE",  # import pyewf
    "libregf-python3":   "SKIP:IMPORTABLE",  # import pyregf
    "libvshadow-python3":"SKIP:IMPORTABLE",  # import pyvshadow
    "python3-debian":    "SKIP:IMPORTABLE",
    "python3-dfvfs":     "SKIP:IMPORTABLE",  # import dfvfs
    "python3-fuse":      "SKIP:IMPORTABLE",
    "python3-keyrings-alt": "SKIP:IMPORTABLE",
    "python3-m2crypto":  "SKIP:IMPORTABLE",
    "python3-magic":     "SKIP:IMPORTABLE",  # import magic
    "python3-pefile":    "SKIP:IMPORTABLE",  # import pefile
    "python3-plaso":     "SKIP:IMPORTABLE",  # import plaso
    "python3-pypff":     "SKIP:IMPORTABLE",  # import pypff
    "python3-pytsk3":    "SKIP:IMPORTABLE",  # import pytsk3
    "python3-redis":     "SKIP:IMPORTABLE",
    "python3-tsk":       "SKIP:IMPORTABLE",
    "python3-xlsxwriter":"SKIP:IMPORTABLE",
    "python3-yara":      "SKIP:IMPORTABLE",  # import yara

    # INFRA — build tools, runtimes, system services, no forensic value
    "apache2":           "SKIP:INFRA",
    "apt-transport-https":"SKIP:INFRA",
    "at":                "SKIP:INFRA",
    "build-essential":   "SKIP:INFRA",
    "claude-code":       "SKIP:INFRA",
    "curl":              "SKIP:INFRA",       # infra utility, not forensic analysis
    "dbus-x11":          "SKIP:INFRA",
    "dconf-cli":         "SKIP:INFRA",
    "default-jre":       "SKIP:INFRA",
    "dotnet":            "SKIP:INFRA",
    "dos2unix":          "SKIP:INFRA",
    "epic5":             "SKIP:INFRA",       # IRC client
    "flex":              "SKIP:INFRA",
    "g++":               "SKIP:INFRA",
    "gawk":              "SKIP:INFRA",
    "gcc":               "SKIP:INFRA",
    "graphviz":          "SKIP:INFRA",
    "htop":              "SKIP:INFRA",       # process monitor, no forensic output
    "ipython3":          "SKIP:INFRA",       # interactive shell, not batch
    "libparse-win32registry-perl": "SKIP:INFRA",
    "net-tools":         "SKIP:INFRA",
    "netpbm":            "SKIP:INFRA",
    "open-iscsi":        "SKIP:INFRA",
    "openjdk":           "SKIP:INFRA",
    "patch":             "SKIP:INFRA",
    "pdftk-java":        "SKIP:INFRA",
    "perl":              "SKIP:INFRA",
    "pkg-config":        "SKIP:INFRA",
    "pv":                "SKIP:INFRA",
    "python3":           "SKIP:INFRA",
    "python3-dev":       "SKIP:INFRA",
    "python3-pip":       "SKIP:INFRA",
    "python3-pyqt5":     "SKIP:INFRA",
    "python3-setuptools":"SKIP:INFRA",
    "python3-setuptools-rust": "SKIP:INFRA",
    "python3-tk":        "SKIP:INFRA",
    "python3-virtualenv":"SKIP:INFRA",
    "python3-wheel":     "SKIP:INFRA",
    "python3-wxgtk4":    "SKIP:INFRA",
    "qemu":              "SKIP:INFRA",       # full VM, not forensic tool
    "samba":             "SKIP:INFRA",
    "silversearcher-ag": "SKIP:INFRA",
    "software-properties-common": "SKIP:INFRA",
    "stunnel4":          "SKIP:INFRA",
    "swig":              "SKIP:INFRA",
    "tcl":               "SKIP:INFRA",
    "tofrodos":          "SKIP:INFRA",
    "ugrep":             "SKIP:INFRA",
    "vim":               "SKIP:INFRA",
    "virtuoso-minimal":  "SKIP:INFRA",
    "winbind":           "SKIP:INFRA",
    # NOTE: "wine" is set to "malware" earlier (Windows binary analysis); do not duplicate here.
    # NOTE: "feh" is set to "disk" earlier (verified wrappable in --list mode); do not duplicate here.
    "xdot":              "SKIP:INFRA",       # graphviz viewer, needs display
    "okular":            "SKIP:INFRA",       # PDF viewer, needs display
    "orca":              "SKIP:INFRA",       # screen reader, no forensic value
    "onboard":           "SKIP:INFRA",       # on-screen keyboard, no forensic value
}


# ══════════════════════════════════════════════════════════════════════════════
# BINARY_BLACKLIST
# Binaries that dpkg-L reports but are unsuitable as MCP tools.
# Audited via audit_tools.py — these reliably hang without a display, so they
# would always burn the 300s subprocess timeout and return nothing useful.
# ══════════════════════════════════════════════════════════════════════════════

BINARY_BLACKLIST = {
    "wineconsole-stable",   # Wine GUI console, hangs without X11
    "winefile-stable",      # Wine GUI file manager, hangs without X11
    "msiexec-stable",       # Wine MSI installer, hangs without X11 on cold start
}


# ══════════════════════════════════════════════════════════════════════════════
# DISCOVERY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def get_packages_from_repo(packages_dir: str) -> list:
    """Read every package name from sift/packages/init.sls."""
    init = Path(packages_dir) / "init.sls"
    if not init.exists():
        print(f"ERROR: {init} not found")
        sys.exit(1)
    packages = re.findall(r"-\s+sift\.packages\.([a-z0-9\-_]+)", init.read_text())
    print(f"[discover] found {len(packages)} packages in init.sls")
    return packages


def get_binaries_for_package(pkg: str) -> list:
    """
    Ask the OS what files this package installed.
    Filters to executable paths only: /usr/bin, /usr/local/bin, /bin, /sbin, /usr/sbin.
    Returns [] if package not installed on this machine.
    """
    try:
        result = subprocess.run(
            ["dpkg", "-L", pkg],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return []

        BIN_PREFIXES = (
            "/usr/bin/", "/usr/local/bin/",
            "/bin/", "/usr/sbin/", "/sbin/",
            "/usr/games/"
        )

        binaries = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if any(line.startswith(p) for p in BIN_PREFIXES):
                binary = line.split("/")[-1]
                if binary:
                    binaries.append({
                        "binary":    binary,
                        "full_path": line
                    })
        return binaries

    except subprocess.TimeoutExpired:
        print(f"  [warn] dpkg -L {pkg} timed out")
        return []
    except Exception as e:
        print(f"  [warn] dpkg -L {pkg} failed: {e}")
        return []


def binary_exists(full_path: str) -> bool:
    """
    Check that the binary exists on disk.
    We test the dpkg-reported full path rather than shutil.which(), because
    /sbin and /usr/sbin are not on PATH for non-root users — that would
    silently drop mdadm, lvm, cryptsetup, dislocker-find, etc.
    """
    return Path(full_path).is_file()


def discover(packages_dir: str, output_path: str = "registry.json") -> dict:
    """
    Main discovery function.
    Returns registry dict and writes registry.json.
    """
    packages = get_packages_from_repo(packages_dir)

    servers   = defaultdict(list)  # { server_name: [{binary, full_path, pkg, fn_name}] }
    skipped   = defaultdict(list)  # { skip_reason: [pkg_name] }
    no_fit    = []                 # packages with no PACKAGE_CATEGORY entry
    seen_bins = set()              # global dedup across all servers

    print(f"\n[discover] classifying {len(packages)} packages ...\n")

    for pkg in packages:
        category = PACKAGE_CATEGORY.get(pkg)

        # no entry at all — flag for manual review
        if category is None:
            no_fit.append(pkg)
            print(f"  [no-fit]  {pkg}")
            continue

        # skip categories
        if category.startswith("SKIP:"):
            reason = category.split(":")[1]
            skipped[reason].append(pkg)
            continue

        # get binaries from OS
        binaries = get_binaries_for_package(pkg)

        if not binaries:
            print(f"  [no-bins] {pkg} — not installed or no binaries")
            skipped["NOT_INSTALLED"].append(pkg)
            continue

        added = 0
        for b in binaries:
            binary = b["binary"]

            # skip if binary not present on disk (covers uninstalled / partial pkgs)
            if not binary_exists(b["full_path"]):
                continue

            # skip audited-hang binaries
            if binary in BINARY_BLACKLIST:
                continue

            # global dedup — ewf-tools and libewf-tools both install ewfinfo
            if binary in seen_bins:
                continue
            seen_bins.add(binary)

            fn_name = "tool_" + re.sub(r"[^a-zA-Z0-9]", "_", binary)

            servers[category].append({
                "package":   pkg,
                "binary":    binary,
                "full_path": b["full_path"],
                "fn_name":   fn_name,
                "server":    f"sift-{category}",
            })
            added += 1

        print(f"  [ok]      sift-{category:<12}  {pkg:<30}  +{added} tools")

    # ── Build summary ─────────────────────────────────────────────────────────

    total_tools = sum(len(v) for v in servers.values())

    registry = {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "packages_dir":  str(packages_dir),
        "total_packages": len(packages),
        "total_tools":   total_tools,
        "servers":       dict(servers),
        "server_counts": {f"sift-{k}": len(v) for k, v in servers.items()},
        "skipped":       dict(skipped),
        "no_fit":        no_fit,
    }

    with open(output_path, "w") as f:
        json.dump(registry, f, indent=2)

    # ── Print report ──────────────────────────────────────────────────────────

    print("\n" + "═" * 56)
    print("  SIFT DISCOVERY COMPLETE")
    print("═" * 56)
    print(f"  Total packages in init.sls   : {len(packages)}")
    print(f"  Total MCP tools registered   : {total_tools}")
    print(f"  Servers created              : {len(servers)}")
    print()

    for server, tools in sorted(servers.items(), key=lambda x: -len(x[1])):
        bar = "█" * (len(tools) // 5)
        print(f"  sift-{server:<14} {len(tools):>3} tools  {bar}")

    print()
    print("  SKIPPED (with reason):")
    for reason, pkgs in sorted(skipped.items()):
        print(f"    {reason:<18} : {len(pkgs)} packages")

    if no_fit:
        print(f"\n  NO-FIT (need manual category): {len(no_fit)}")
        for p in no_fit:
            print(f"    - {p}")

    print(f"\n  registry.json written → {output_path}")
    print("═" * 56)

    return registry


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    packages_dir = sys.argv[1] if len(sys.argv) > 1 else "sift/packages"
    discover(packages_dir)
