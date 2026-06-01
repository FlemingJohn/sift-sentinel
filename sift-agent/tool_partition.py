from __future__ import annotations

_ACQUIRER_DISK = [
    "tool_dd", "tool_dc3dd", "tool_dcfldd", "tool_ddrescue", "tool_ddrescuelog",
    "tool_ewfacquire", "tool_ewfacquirestream", "tool_ewfverify", "tool_ewfexport",
    "tool_ewfinfo", "tool_ewfmount", "tool_ewfdebug", "tool_ewfrecover",
    "tool_affcat", "tool_affcompare", "tool_affconvert", "tool_affcopy",
    "tool_affcrypto", "tool_affdiskprint", "tool_affinfo", "tool_affix",
    "tool_affrecover", "tool_affsegment", "tool_affsign", "tool_affstats",
    "tool_affuse", "tool_affverify", "tool_affxml",
    "tool_xmount", "tool_qemu_img", "tool_qemu_nbd", "tool_qemu_io",
    "tool_safecopy", "tool_disktype",
    "tool_fsapfsmount", "tool_mount_ntfs", "tool_mount_ntfs_3g",
    "tool_mount_exfat_fuse", "tool_mountavfs", "tool_vshadowmount",
    "tool_regfmount", "tool_lowntfs_3g", "tool_ntfs_3g",
]

_FILESYSTEM = [
    "tool_fls", "tool_fcat", "tool_icat", "tool_ifind", "tool_ils", "tool_istat",
    "tool_jcat", "tool_jls", "tool_mmls", "tool_mmstat", "tool_mmcat",
    "tool_fsstat", "tool_img_cat", "tool_img_stat",
    "tool_blkcat", "tool_blkls", "tool_blkstat", "tool_blkcalc",
    "tool_pstat", "tool_ffind", "tool_mactime", "tool_sorter", "tool_sigfind",
    "tool_tsk_comparedir", "tool_tsk_gettimes", "tool_tsk_imageinfo",
    "tool_tsk_loaddb", "tool_tsk_recover", "tool_usnjls", "tool_fiwalk",
    "tool_ntfsinfo", "tool_ntfsls", "tool_ntfscat", "tool_ntfsundelete",
    "tool_ntfsfix", "tool_ntfscluster", "tool_ntfssecaudit", "tool_ntfsusermap",
    "tool_ntfscmp", "tool_ntfsdecrypt",
    "tool_debugfs", "tool_dumpe2fs", "tool_lsattr", "tool_filefrag",
]

_CARVER = [
    "tool_foremost", "tool_scalpel", "tool_photorec", "tool_srch_strings",
    "tool_testdisk", "tool_extundelete", "tool_ntfsrecover", "tool_gzrecover",
    "tool_jpeg_extract", "tool_7z", "tool_7za", "tool_rar",
    "tool_exif", "tool_fidentify", "tool_fdupes", "tool_plistutil",
]

_WINDOWS = [
    "tool_cabextract", "tool_esedbexport", "tool_esedbinfo",
    "tool_evtexport", "tool_evtinfo", "tool_evtxexport", "tool_evtxinfo",
    "tool_image_export_py", "tool_log2timeline_py", "tool_pinfo_py",
    "tool_psort_py", "tool_psteal_py",
    "tool_lspst", "tool_nick2ldif", "tool_pffexport", "tool_pffinfo",
    "tool_pst2dii", "tool_pst2ldif", "tool_readpst", "tool_pwsh",
    "tool_regfexport", "tool_regfinfo", "tool_regfmount", "tool_samdump2",
    "tool_vshadowdebug", "tool_vshadowinfo", "tool_vshadowmount",
]

_MEMORY = [
    "tool_aeskeyfind", "tool_bulk_extractor", "tool_ent",
    "tool_plugin_test", "tool_rsakeyfind",
]

_HASHING = [
    "tool_hashdeep", "tool_md5deep", "tool_sha1deep", "tool_sha256deep",
    "tool_ssdeep", "tool_tigerdeep", "tool_whirlpooldeep",
]

_NETWORK_PCAP = [
    "tool_tcpflow", "tool_tcpick", "tool_tcptrace", "tool_tcptrack",
    "tool_tcpstat", "tool_tcpprof", "tool_tcpcapinfo", "tool_tcpslice",
    "tool_tcpxtract", "tool_tcpreplay", "tool_tcpreplay_edit",
    "tool_tcprewrite", "tool_tcpbridge", "tool_tcpprep",
    "tool_ngrep", "tool_p0f", "tool_ssldump", "tool_etherape",
    "tool_nfcapd", "tool_nfdump", "tool_nfanon", "tool_nfexpire",
    "tool_nfprofile", "tool_nfreplay", "tool_nftrack", "tool_nfpcapd",
    "tool_kstats", "tool_get_oui", "tool_get_iab",
]

_MALWARE_STATIC = [
    "tool_readpe", "tool_pescan", "tool_pesec", "tool_pestr", "tool_peres",
    "tool_pehash", "tool_pedis", "tool_peldd", "tool_pepack",
    "tool_ofs2rva", "tool_rva2ofs",
    "tool_clamscan", "tool_clambc", "tool_clamsubmit", "tool_sigtool",
    "tool_upx_ucl",
]

_REVERSING = [
    "tool_r2", "tool_r2agent", "tool_r2p", "tool_r2pm", "tool_r2r",
    "tool_rabin2", "tool_radare2", "tool_radiff2", "tool_rafind2",
    "tool_ragg2", "tool_rahash2", "tool_rarun2", "tool_rasign2",
    "tool_rasm2", "tool_ravc2", "tool_rax2",
    "tool_gdb", "tool_gdbtui", "tool_gdb_add_index", "tool_gcore",
]

_CRYPTO = [
    "tool_dislocker", "tool_dislocker_bek", "tool_dislocker_file",
    "tool_dislocker_find", "tool_dislocker_fuse", "tool_dislocker_metadata",
    "tool_fvdeinfo", "tool_fvdemount", "tool_fvdewipekey",
    "tool_ccat", "tool_ccdecrypt", "tool_ccguess",
    "tool_cryptdisks_start", "tool_cryptdisks_stop",
    "tool_cmospwd", "tool_histogram",
]

_ATTACK = [
    "assess_attack_chain", "get_countermeasures", "get_groups_using_technique",
    "get_sift_tools_for_technique", "get_software_used_by_group",
    "get_technique_details", "list_techniques_by_tactic", "map_finding_to_technique",
]

_DEFEND = [
    "find_defenses_for_artifact", "get_attack_to_defend_coverage",
    "get_defense", "list_defenses_by_tactic", "list_defenses_for_attack",
]


WORKER_TOOLS: dict[str, list[str]] = {
    "acquirer": _ACQUIRER_DISK,
    "hasher": _HASHING,
    "filesystem": _FILESYSTEM,
    "carver": _CARVER,
    "windows": _WINDOWS,
    "memory": _MEMORY,
    "network": _NETWORK_PCAP,
    "malware_static": _MALWARE_STATIC,
    "reversing": _REVERSING,
    "crypto": _CRYPTO,
    "attack_map": _ATTACK,
    "defense_map": _DEFEND,
}
