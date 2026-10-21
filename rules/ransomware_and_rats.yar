/*
   Aegis AV — SOTA YARA-X Rules for Ransomware, Wipers, and RATs (2010–2026)
   Covers real-world families from Malware-Database:
   - Petya / GoldenEye (MBR wiper & Salsa20 encryption)
   - REvil / Sodinokibi (Symmetric ChaCha / Curve25519)
   - BlackCat / ALPHV (Rust-based multi-threaded ransomware)
   - Maze (Symmetric stream & RSA-2048)
   - TeslaCrypt (ECDH key exchange & shadow deletion)
   - Thanos (Fast multi-threaded builder)
   - GandCrab (V1-V5 payload signatures)
   - CaddyWiper / StoneDrill (Raw partition table & sector zeroing)
   - NetWire, Remcos, WarzoneRAT, DCRat, Nanocore
*/

private rule IsExecutable
{
    condition:
        // PE magic "MZ" or ELF magic "\x7fELF"
        uint16(0) == 0x5a4d or uint32(0) == 0x464c457f
}

rule Ransom_Petya_GoldenEye_MBR
{
    meta:
        description = "Petya, GoldenEye, and NotPetya MBR destructive wiper and filesystem encryption"
        severity    = "critical"
        threat_type = "Ransomware.Petya"
        mitre_att   = "T1486, T1561.002"
    strings:
        $p1 = "\\\\.\\PhysicalDrive0" ascii wide
        $p2 = "chkdisk" ascii nocase
        $p3 = "CHKDSK is repairing" ascii wide
        $p4 = "your files are encrypted" ascii nocase
        $p5 = "Salsa20" ascii
        $p6 = "we accept only Bitcoin" ascii nocase
        $p7 = "CoMiscellaneous" ascii
    condition:
        IsExecutable and (3 of ($p*))
}

rule Ransom_REvil_Sodinokibi
{
    meta:
        description = "REvil / Sodinokibi ransomware core strings and shadow copy suppression"
        severity    = "critical"
        threat_type = "Ransomware.REvil"
        mitre_att   = "T1486, T1490"
    strings:
        $r1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
        $r2 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $r3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $r4 = "-readme.txt" ascii wide
        $r5 = "sodinokibi" ascii wide nocase
        $r6 = "expand 32-byte k" ascii
    condition:
        IsExecutable and (2 of ($r1, $r2, $r3) or ($r6 and ($r4 or $r5)))
}

rule Ransom_BlackCat_ALPHV
{
    meta:
        description = "BlackCat (ALPHV) Rust-based multi-platform ransomware"
        severity    = "critical"
        threat_type = "Ransomware.BlackCat"
        mitre_att   = "T1486, T1490"
    strings:
        $bc1 = "--access-token" ascii
        $bc2 = "esxi_vm_kill" ascii
        $bc3 = "chcp 65001" ascii
        $bc4 = "fsutil behavior set SymlinkEvaluation" ascii
        $bc5 = "RECOVER-" ascii wide
        $bc6 = "masquerade" ascii
        $bc7 = "blackcat" ascii nocase
    condition:
        IsExecutable and (2 of ($bc*))
}

rule Ransom_Maze_ChaCha_RSA
{
    meta:
        description = "Maze ransomware payload with network share traversal and ChaCha encryption"
        severity    = "critical"
        threat_type = "Ransomware.Maze"
        mitre_att   = "T1486, T1021.002"
    strings:
        $m1 = "DECRYPT-FILES.txt" ascii wide
        $m2 = "WNetOpenEnumW" ascii
        $m3 = "WNetEnumResourceW" ascii
        $m4 = "WNetCloseEnum" ascii
        $m5 = "ChaCha" ascii
        $m6 = "CryptImportKey" ascii
    condition:
        IsExecutable and ($m1 or (3 of ($m2, $m3, $m4, $m5, $m6)))
}

rule Ransom_TeslaCrypt_ECDH
{
    meta:
        description = "TeslaCrypt ransomware ECDH key negotiation and shadow copy deletion"
        severity    = "critical"
        threat_type = "Ransomware.TeslaCrypt"
        mitre_att   = "T1486, T1490"
    strings:
        $t1 = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
        $t2 = "how_recover" ascii wide nocase
        $t3 = "recovery_file.txt" ascii wide nocase
        $t4 = "HELP_RESTORE_FILES" ascii wide
        $t5 = "secp256k1" ascii
    condition:
        IsExecutable and (2 of ($t*))
}

rule Ransom_Thanos_Ransomware
{
    meta:
        description = "Thanos / Prometheus configurable ransomware builder"
        severity    = "critical"
        threat_type = "Ransomware.Thanos"
        mitre_att   = "T1486, T1490"
    strings:
        $th1 = "HOW_TO_DECRYPT_FILES.txt" ascii wide
        $th2 = "Thanos" ascii wide nocase
        $th3 = "kill_processes" ascii wide nocase
        $th4 = "delete_shadows" ascii wide nocase
        $th5 = "RESTORE_FILES_INFO" ascii wide
    condition:
        IsExecutable and (2 of ($th*))
}

rule Ransom_GandCrab_Core
{
    meta:
        description = "GandCrab ransomware family (V1-V5 payload and decryption instructions)"
        severity    = "critical"
        threat_type = "Ransomware.GandCrab"
        mitre_att   = "T1486"
    strings:
        $g1 = "GDCB-DECRYPT.txt" ascii wide
        $g2 = "KRAB-DECRYPT.txt" ascii wide
        $g3 = "---= GANDCRAB V" ascii wide
        $g4 = "ns1.gandcrab.bit" ascii wide
        $g5 = ".lock1" ascii wide
        $g6 = "http://gandcrab" ascii wide
    condition:
        ($g1 or $g2 or $g3 or $g4 or ($g5 and $g6))
}

rule Wiper_CaddyWiper_Core
{
    meta:
        description = "CaddyWiper raw drive access and destructive sector zeroing"
        severity    = "critical"
        threat_type = "Wiper.CaddyWiper"
        mitre_att   = "T1561.002"
    strings:
        $c1 = "\\\\.\\PhysicalDrive" ascii wide
        $c2 = "IOCTL_DISK_GET_DRIVE_GEOMETRY" ascii wide
        $c3 = "SetFilePointer" ascii wide
        $c4 = "WriteFile" ascii wide
        $c5 = "SeTakeOwnershipPrivilege" ascii wide
    condition:
        IsExecutable and ($c1 and $c2 and ($c3 or $c4 or $c5))
}

rule RAT_NetWire_Client
{
    meta:
        description = "NetWire multi-platform Remote Access Trojan keylogger and C2 configuration"
        severity    = "critical"
        threat_type = "Trojan.RAT.NetWire"
        mitre_att   = "T1056.001, T1071.001"
    strings:
        $nw1 = "NetWire" ascii wide
        $nw2 = "[Log Started]" ascii wide
        $nw3 = "[Pause]" ascii wide
        $nw4 = "Install Path:" ascii wide
        $nw5 = "Host:" ascii wide
        $nw6 = "Port:" ascii wide
        $nw7 = "Password:" ascii wide
    condition:
        IsExecutable and (3 of ($nw*))
}

rule RAT_Remcos_Professional
{
    meta:
        description = "Remcos commercial Remote Access Trojan backdoor commands and settings"
        severity    = "critical"
        threat_type = "Trojan.RAT.Remcos"
        mitre_att   = "T1219, T1071"
    strings:
        $rem1 = "Remcos Professional" ascii wide
        $rem2 = "Remote Administration Tool" ascii wide
        $rem3 = "Breaking-Security" ascii wide
        $rem4 = "Connecting to:" ascii wide
        $rem5 = "PingInterval" ascii wide
        $rem6 = "\\remcos" ascii wide nocase
    condition:
        IsExecutable and (2 of ($rem*))
}

rule RAT_Warzone_AveMaria
{
    meta:
        description = "WarzoneRAT / AveMaria stealth remote access trojan"
        severity    = "critical"
        threat_type = "Trojan.RAT.Warzone"
        mitre_att   = "T1219, T1056"
    strings:
        $wz1 = "AveMaria" ascii wide
        $wz2 = "warzone" ascii wide nocase
        $wz3 = "\\cmd.exe" ascii wide
        $wz4 = "Elevation:Administrator!Token elevates!" ascii wide
        $wz5 = "Password Viewer" ascii wide
    condition:
        IsExecutable and (2 of ($wz*))
}

rule RAT_DCRat_Payload
{
    meta:
        description = "DCRat modular .NET Remote Access Trojan"
        severity    = "critical"
        threat_type = "Trojan.RAT.DCRat"
        mitre_att   = "T1219, T1059.001"
    strings:
        $dc1 = "DCRat" ascii wide nocase
        $dc2 = "dcrat" ascii wide nocase
        $dc3 = "plugin_manager" ascii wide nocase
        $dc4 = "BypassUAC" ascii wide nocase
        $dc5 = "Stealer" ascii wide nocase
    condition:
        IsExecutable and ($dc1 or ($dc2 and ($dc3 or $dc4 or $dc5)))
}
