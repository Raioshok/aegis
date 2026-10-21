/*
   Aegis Antivirus & EDR — High-Fidelity SOTA YARA-X Threat Rules (2010–2026)
   Coverage: Petya, REvil, BlackCat, Maze, TeslaCrypt, Thanos, GandCrab, CaddyWiper, StoneDrill,
             NetWire, Remcos, WarzoneRAT, CrimsonRAT, DCRat, Nanocore, AlienSpy, Cobalt Strike
*/

private rule IsOfficeOrOLE {
    condition:
        (uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1) or
        (uint32(0) == 0x04034b50) or
        (uint32(0) == 0x74725c7b)
}

// -----------------------------------------------------------------------------
// 1. Petya / NotPetya / GoldenEye (MBR/VBR Overwrite & Low-Level Ransomware)
// -----------------------------------------------------------------------------
rule Ransom_Petya_NotPetya_Advanced
{
    meta:
        description = "Detects Petya, NotPetya, and GoldenEye bootloader/MBR destructive lockers"
        threat_family = "Petya"
        severity = "critical"
        confidence = "high"
    strings:
        // Raw drive and MBR access
        $raw1 = "\\\\.\\PhysicalDrive0" ascii wide
        $raw2 = "\\\\.\\PhysicalDrive" ascii wide
        // Journal and event wiping command lines
        $cmd1 = "fsutil usn deletejournal /D" ascii wide nocase
        $cmd2 = "wevtutil cl Setup" ascii wide nocase
        $cmd3 = "wevtutil cl System" ascii wide nocase
        $cmd4 = "wevtutil cl Security" ascii wide nocase
        // Artifacts / named pipes / exports
        $art1 = "perfc.dat" ascii wide
        $art2 = "1HourAfterShutdown" ascii wide
        $art3 = "chkntfs /c %c:" ascii wide
        // Microkernel / bootloader stub strings
        $boot1 = "Repairing file system on" ascii
        $boot2 = "DO NOT TURN OFF YOUR PC" ascii
    condition:
        IsPE and (
            ($raw1 and 2 of ($cmd1, $cmd2, $cmd3, $cmd4)) or
            ($raw2 and any of ($art1, $art2, $art3)) or
            any of ($boot1, $boot2)
        )
}

// -----------------------------------------------------------------------------
// 2. REvil / Sodinokibi (Ransomware-as-a-Service)
// -----------------------------------------------------------------------------
rule Ransom_REvil_Sodinokibi
{
    meta:
        description = "Detects REvil / Sodinokibi RaaS payloads, JSON config parser, and shadow copy destruction"
        threat_family = "REvil"
        severity = "critical"
        confidence = "high"
    strings:
        // Embedded config block flags & JSON parameters
        $cfg1 = "\"pk\":" ascii
        $cfg2 = "\"pid\":" ascii
        $cfg3 = "\"sub\":" ascii
        $cfg4 = "\"dbg\":" ascii
        $cfg5 = "\"et\":" ascii
        $cfg6 = "\"wipe\":" ascii
        // WMI & Shadow copy destruction
        $cmd_vss = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
        $cmd_bde = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd_rec = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $cmd_wb  = "wbadmin DELETE SYSTEMSTATE -keepVersions:0" ascii wide nocase
        // Ransom note pattern format
        $note = "-readme.txt" ascii wide
    condition:
        IsPE and (
            (3 of ($cfg1, $cfg2, $cfg3, $cfg4, $cfg5, $cfg6) and ($note or any of ($cmd_vss, $cmd_bde))) or
            (2 of ($cmd_vss, $cmd_bde, $cmd_rec, $cmd_wb) and $note)
        )
}

// -----------------------------------------------------------------------------
// 3. BlackCat / ALPHV (Rust-based Ransomware for Windows & Linux ESXi)
// -----------------------------------------------------------------------------
rule Ransom_BlackCat_ALPHV
{
    meta:
        description = "Detects BlackCat (ALPHV) Rust-based cross-platform ransomware (Windows & Linux/ESXi)"
        threat_family = "BlackCat"
        severity = "critical"
        confidence = "high"
    strings:
        // Config JSON & CLI arguments
        $bc1 = "note_file_name\":\"RECOVER-${EXTENSION}-FILES.txt\"" ascii
        $bc2 = "default_file_cipher\":\"Best\"" ascii
        $bc3 = "enable_esxi_vm_kill" ascii
        $bc4 = "enable_esxi_vm_snapshot_kill" ascii
        // Internal Rust crate paths & commands
        $crate1 = "src/bin/encrypt_app/app.rs" ascii
        $crate2 = "locker::core::pipeline::file_worker_pool_core" ascii
        $crate3 = "locker::core::os::linux::esxi" ascii
        $crate4 = "locker::core::os::windows::file_unlocker" ascii
        // ESXi specific commands
        $esxi1 = "esxcli vm process kill --type=force" ascii
        $esxi2 = "vim-cmd vmsvc/snapshot.removeall" ascii
        // Windows privilege escalation and network concurrency tuning
        $win1 = "Services\\LanmanServer\\Parameters /v MaxMpxCt /d 65535" ascii wide
    condition:
        (IsPE or IsELF) and (
            any of ($bc1, $bc2) or
            2 of ($bc3, $bc4, $crate1, $crate2, $crate3, $crate4) or
            any of ($esxi1, $esxi2, $win1)
        )
}

// -----------------------------------------------------------------------------
// 4. Maze / ChaCha20 Ransomware
// -----------------------------------------------------------------------------
rule Ransom_Maze_ChaCha20
{
    meta:
        description = "Detects Maze ransomware PE/DLL binaries and ChaCha20/RSA extortion logic"
        threat_family = "Maze"
        severity = "critical"
        confidence = "high"
    strings:
        // Ransom note & campaign markers
        $note1 = "DECRYPT-FILES.txt" ascii wide
        $note2 = "Attention! What happened?" ascii
        $note3 = "All your files, documents, photos, databases and other important files are encrypted" ascii
        // Specific API calls for privilege manipulation and network share enumeration
        $s1 = "WNetOpenEnumW" ascii
        $s2 = "WNetEnumResourceW" ascii
        $s3 = "CryptDllExportPublicKeyInfoEx" ascii
    condition:
        IsPE and (
            any of ($note1, $note2, $note3) or
            ($s3 and all of ($s1, $s2))
        )
}

// -----------------------------------------------------------------------------
// 5. TeslaCrypt (ECDH / OpenSSL-based Ransomware)
// -----------------------------------------------------------------------------
rule Ransom_TeslaCrypt
{
    meta:
        description = "Detects TeslaCrypt ransomware (v1-v4) and ECC key-exchange markers"
        threat_family = "TeslaCrypt"
        severity = "critical"
        confidence = "high"
    strings:
        $t1 = "CBigNum::operator= : BN_copy failed" ascii
        $t2 = "Subject=Crypted&key=" ascii
        $t3 = "Subject=Ping&key=" ascii
        $t4 = "7tno4hib47vlep5o.tor2web" ascii
        $t5 = "with strongest encryption and unique key, generated for this computer." ascii
        $t6 = "Private decryption key is stored on a secret Internet server" ascii
        $ext1 = ".ecc" ascii wide
        $ext2 = ".ezz" ascii wide
        $ext3 = ".exx" ascii wide
        $ext4 = ".micro" ascii wide
    condition:
        IsPE and (
            any of ($t1, $t2, $t3, $t4) or
            ($t5 and $t6) or
            (2 of ($ext1, $ext2, $ext3, $ext4) and any of ($t5, $t6))
        )
}

// -----------------------------------------------------------------------------
// 6. Thanos / Hakbit (RIPlace Evasion & .NET Builder Ransomware)
// -----------------------------------------------------------------------------
rule Ransom_Thanos_Hakbit
{
    meta:
        description = "Detects Thanos / Hakbit .NET ransomware featuring RIPlace rename evasion"
        threat_family = "Thanos"
        severity = "critical"
        confidence = "high"
    strings:
        // .NET metadata markers and method names
        $m1 = "WalkDirectoryTree" ascii
        $m2 = "GetProcessSecurityDescriptor" ascii
        $m3 = "SetProcessSecurityDescriptor" ascii
        $m4 = "GetKeyFromEncryptionString" ascii
        $m5 = "AES256KeySize" ascii
        $m6 = "PrepareToRipIt" ascii
        $m7 = "CmOCZJRfKEYgY" ascii
        $m8 = "rawSecurityDescriptor_0" ascii
        $clr = "_CorExeMain" ascii
    condition:
        IsPE and $clr and (
            3 of ($m1, $m2, $m3, $m4, $m5, $m6, $m7, $m8)
        )
}

// -----------------------------------------------------------------------------
// 7. GandCrab (v1 to v5.x RaaS & Dropper Swarm)
// -----------------------------------------------------------------------------
rule Ransom_GandCrab
{
    meta:
        description = "Detects GandCrab ransomware binaries, decryption instruction templates, and droppers"
        threat_family = "GandCrab"
        severity = "critical"
        confidence = "high"
    strings:
        // Ransom note naming patterns
        $n1 = "GDCB-DECRYPT.txt" ascii wide
        $n2 = "KRAB-DECRYPT.txt" ascii wide
        $n3 = "-DECRYPT.txt" ascii wide
        $n4 = "GandCrab" ascii wide nocase
        // Embedded onion gate and decryptor URL patterns
        $gate1 = "gdcb.bit" ascii wide
        $gate2 = "gandcrab" ascii wide
        // Specific custom section layout observed in packed GandCrab binaries
        $sec1 = ".mysec" ascii
        $sec2 = ".mysec2" ascii
        $sec3 = ".mysec3" ascii
        $sec4 = ".rcrs" ascii
    condition:
        IsPE and (
            any of ($n1, $n2) or
            (2 of ($sec1, $sec2, $sec3, $sec4)) or
            ($n3 and any of ($gate1, $gate2) and $n4)
        )
}

// -----------------------------------------------------------------------------
// 8. CaddyWiper (Lightweight Raw Disk & Partition Destruction Wiper)
// -----------------------------------------------------------------------------
rule Wiper_CaddyWiper
{
    meta:
        description = "Detects CaddyWiper disk wiper targeting physical drives and AD Domain Controllers"
        threat_family = "CaddyWiper"
        severity = "critical"
        confidence = "high"
    strings:
        // Physical drive enumeration & IOCTL layout
        $drv = "\\\\.\\PhysicalDrive%d" ascii wide
        $priv1 = "SeTakeOwnershipPrivilege" ascii wide
        $priv2 = "DsRoleGetPrimaryDomainInformation" ascii
        $priv3 = "DsRoleFreeMemory" ascii
        // Destruction loop pattern (zeroing buffers via DeviceIoControl / WriteFile)
        $hex_zero = { 83 ?? 09 77 ?? 6a 00 68 00 00 00 00 }
    condition:
        IsPE and (
            ($drv and any of ($priv1, $priv2, $priv3)) or
            (all of ($priv1, $priv2, $priv3)) or
            $hex_zero
        )
}

// -----------------------------------------------------------------------------
// 9. StoneDrill (Shamoon-Aligned Wiper & Memory Injector)
// -----------------------------------------------------------------------------
rule Wiper_StoneDrill
{
    meta:
        description = "Detects StoneDrill destructive wiper executable and anti-analysis memory injector"
        threat_family = "StoneDrill"
        severity = "critical"
        confidence = "high"
    strings:
        // Target service stopping / wiping
        $w1 = "\\\\.\\PhysicalDrive" ascii wide
        $w2 = "net stop" ascii wide nocase
        $w3 = "sc stop" ascii wide nocase
        // Evasion & memory unhooking artifacts
        $ev1 = "CreateProcessInternalW" ascii
        $ev2 = "NtUnmapViewOfSection" ascii
        $ev3 = "ZwUnmapViewOfSection" ascii
        // Specific StoneDrill resource & section markers
        $r1 = "C:\\Windows\\System32\\calc.exe" ascii wide
        $r2 = "cmd.exe /c start" ascii wide
    condition:
        IsPE and (
            $w1 and any of ($ev1, $ev2, $ev3) and any of ($w2, $w3) or
            (all of ($w1, $r1, $r2) and any of ($ev2, $ev3))
        )
}

/* ============================================================================
   Aegis AV / EDR — High-Fidelity YARA-X Signatures
   Threat Families: NetWire, Remcos, WarzoneRAT, CrimsonRAT, DCRat, 
                    Nanocore, AlienSpy, Cobalt Strike Malicious Documents
   ============================================================================ */

/* ----------------------------------------------------------------------------
   1. NetWire RAT
   Identifies NetWire's custom keylogging format, network protocol framing,
   and encrypted configuration routines.
   ---------------------------------------------------------------------------- */
rule RAT_Win32_NetWire
{
    meta:
        description = "Detects NetWire Remote Access Trojan payloads and keylogger telemetry"
        severity    = "critical"
        threat_type = "RAT.NetWire"
        mitre_att   = "T1056.001, T1071.001, T1027"

    strings:
        // Keylogger tag markers unique to NetWire builds
        $kl_tag1 = "[Log Started]" ascii
        $kl_tag2 = "[Prompt]" ascii
        $kl_tag3 = "[IE/Edge]" ascii
        $kl_tag4 = "[Firefox]" ascii
        $kl_tag5 = "[Backspace]" ascii wide
        $kl_tag6 = "[Enter]" ascii wide

        // Internal handler strings & commands
        $cmd1 = "GETSTOPPED" ascii
        $cmd2 = "GETAV" ascii
        $cmd3 = "LOG_DIRECTORY" ascii
        $cmd4 = "encrypted_key" ascii

        // Byte signature: NetWire pseudo-RC4 key schedule / state machine loop
        // 8A 04 18 (mov al, [eax+ebx]) ; 88 04 0A (mov [edx+ecx], al) ; 01 D8 (add eax, ebx)
        $netwire_crypto_loop = { 8A 04 ?? 88 ?? ?? 01 ?? 81 ?? ?? ?? 00 00 8A ?? ?? 88 ?? ?? }

    condition:
        IsPE and (
            3 of ($kl_tag*) or
            (2 of ($cmd*) and 1 of ($kl_tag*)) or
            $netwire_crypto_loop
        )
}

/* ----------------------------------------------------------------------------
   2. Remcos RAT (BreakingSecurity)
   Matches the embedded encrypted RC4 configuration resource (SETTINGS / "ex")
   and command dispatch tables.
   ---------------------------------------------------------------------------- */
rule RAT_Win32_Remcos
{
    meta:
        description = "Detects Remcos Remote Access Trojan configuration and C2 handlers"
        severity    = "critical"
        threat_type = "RAT.Remcos"
        mitre_att   = "T1059.003, T1547.001, T1070"

    strings:
        // Remcos standard resource section marker
        $res_cfg = "SETTINGS" ascii wide
        $res_ex  = "ex\x00" ascii wide

        // Remcos event & agent identifiers
        $rem_str1 = "Remcos Professional" ascii wide
        $rem_str2 = "Remcos by BreakingSecurity" ascii wide
        $rem_str3 = "[minlog]" ascii
        $rem_str4 = "Remote Security Administration" ascii wide
        $rem_str5 = "licpath" ascii

        // Byte signature: Remcos RC4 configuration decrypter stub
        // 33 C9 89 4C 24 ?? 8A 84 0C ?? ?? 00 00 88 84 0C
        $remcos_rc4_init = { 33 C9 89 ?? ?? 8A 84 ?? ?? ?? 00 00 88 84 ?? ?? ?? 00 00 41 81 F9 00 01 00 00 7C }

        // Remcos IPC / pipe string
        $pipe = "\\\\.\\pipe\\remcos" nocase ascii wide

    condition:
        IsPE and (
            $remcos_rc4_init or
            $pipe or
            2 of ($rem_str*) or
            (($res_cfg or $res_ex) and 1 of ($rem_str*))
        )
}

/* ----------------------------------------------------------------------------
   3. WarzoneRAT / AveMaria
   Detects Warzone/AveMaria privilege escalation, password extraction from
   browsers/mail clients, and C2 heartbeat markers.
   ---------------------------------------------------------------------------- */
rule RAT_Win32_WarzoneRAT
{
    meta:
        description = "Detects WarzoneRAT (AveMaria) credential thief, UAC bypass, and C2 routines"
        severity    = "critical"
        threat_type = "RAT.WarzoneRAT"
        mitre_att   = "T1548.002, T1555.003, T1041"

    strings:
        // Well-known Warzone core markers & mutexes
        $str1 = "Ave_Maria" ascii wide
        $str2 = "AveMaria" ascii wide
        $str3 = "warzone160" ascii wide
        $str4 = "warzone" nocase ascii wide

        // Warzone custom credential recovery strings
        $cred1 = "\\Microsoft\\Windows Live Mail" ascii wide
        $cred2 = "\\Thunderbird\\Profiles" ascii wide
        $cred3 = "Outlook\\Profiles" ascii wide

        // Byte signature: Warzone assembly loader shellcode / payload unpacking loop
        // 55 8B EC 81 EC ?? ?? 00 00 53 56 57 E8 00 00 00 00 58
        $unpack_sub = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 E8 00 00 00 00 58 83 C0 ?? }

        // Warzone reverse proxy & tile commands
        $cmd1 = "/c ping 127.0.0.1 -n 2" ascii wide
        $cmd2 = "Execute ERROR" ascii wide

    condition:
        IsPE and (
            any of ($str*) or
            ($unpack_sub and 1 of ($cred*)) or
            (2 of ($cred*) and 1 of ($cmd*))
        )
}

/* ----------------------------------------------------------------------------
   4. CrimsonRAT (MuddyWater / Seedworm)
   Identifies CrimsonRAT custom .NET and C++ variants using custom packet delimiters,
   port splitters, and surveillance routines.
   ---------------------------------------------------------------------------- */
rule RAT_Win_CrimsonRAT
{
    meta:
        description = "Detects MuddyWater CrimsonRAT backdoor modules and packet structures"
        severity    = "critical"
        threat_type = "RAT.CrimsonRAT"
        mitre_att   = "T1071.001, T1059.001, T1056"

    strings:
        // CrimsonRAT protocol delimiters and sub-commands
        $delim1 = "prt::" ascii wide
        $delim2 = "spr::" ascii wide
        $delim3 = "rst::" ascii wide
        $delim4 = "run::" ascii wide
        $delim5 = "rep::" ascii wide

        // Module names & specific commands
        $mod1 = "exc_vir" ascii wide
        $mod2 = "chk_pst" ascii wide
        $mod3 = "ch_str" ascii wide
        $mod4 = "my_port" ascii wide
        $mod5 = "vir_st" ascii wide

        // Byte signature: Base64 custom payload decoding loop
        $b64_custom = { 8A 14 01 80 FA 3D 74 ?? 8D 42 ?? 88 04 31 }

    condition:
        IsPE and (
            3 of ($delim*) or
            2 of ($mod*) or
            ($b64_custom and 1 of ($delim*))
        )
}

/* ----------------------------------------------------------------------------
   5. DCRat (DarkCrystal RAT)
   Detects DCRat .NET client assemblies, encrypted plugin manifests, and C2 URLs.
   ---------------------------------------------------------------------------- */
rule RAT_DotNet_DCRat
{
    meta:
        description = "Detects DCRat (DarkCrystal RAT) .NET payloads and obfuscated plugin managers"
        severity    = "critical"
        threat_type = "RAT.DCRat"
        mitre_att   = "T1059.005, T1027, T1113"

    strings:
        // Distinct namespaces & type names
        $dc1 = "DcRat" ascii wide
        $dc2 = "DCRatPlugin" ascii wide
        $dc3 = "DarkCrystal" nocase ascii wide

        // Mutex & configuration tags
        $tag1 = "DCR_MUTEX" ascii wide
        $tag2 = "dcrat_token" ascii wide
        $tag3 = "DcRat.Properties" ascii wide

        // Byte signature: .NET MSIL sequence for DCRat String Decryption / BouncyCastle AES wrap
        // 72 ?? ?? ?? 70 (ldstr ...) ; 28 ?? ?? ?? 06 (call Decrypt) ; 6F ?? ?? ?? 0A
        $msil_dec = { 72 [4] 70 28 [4] 06 6F [4] 0A 74 [4] 01 }

    condition:
        IsPE and (
            any of ($dc*) or
            2 of ($tag*) or
            ($msil_dec and 1 of ($tag*))
        )
}

/* ----------------------------------------------------------------------------
   6. NanoCore RAT
   Matches NanoCore encrypted primary plugin records, deserializer stubs,
   and Pipe handlers.
   ---------------------------------------------------------------------------- */
rule RAT_DotNet_NanoCore
{
    meta:
        description = "Detects NanoCore Remote Access Trojan .NET binaries and client structures"
        severity    = "critical"
        threat_type = "RAT.NanoCore"
        mitre_att   = "T1055, T1056.001, T1105"

    strings:
        // GUID and namespace references
        $guid1 = "NanoCore Client" ascii wide
        $guid2 = "NanoCore.ClientPlugin" ascii wide
        $guid3 = "IClientNetwork" ascii wide
        $guid4 = "IClientLogging" ascii wide

        // Embedded NanoCore resource names
        $res1 = "PrimaryClient.dll" ascii wide
        $res2 = "NanoCore.Properties.Resources" ascii wide

        // Byte pattern: NanoCore payload preamble / DES/AES salt parsing logic
        // 08 17 58 07 11 04 6F ?? ?? ?? 0A 25 14
        $deserializer_sig = { 08 17 58 07 11 04 6F [4] 0A 25 14 }

    condition:
        IsPE and (
            any of ($guid*) or
            ($res1 and $res2) or
            ($deserializer_sig and 1 of ($guid*))
        )
}

/* ----------------------------------------------------------------------------
   7. AlienSpy / Adwind / jRAT
   Detects Java-based AlienSpy / Frutas / Adwind / SockRAT archives, class loaders,
   and dynamic multi-OS persistence classes.
   ---------------------------------------------------------------------------- */
rule RAT_Java_AlienSpy_Adwind
{
    meta:
        description = "Detects AlienSpy / Adwind / jRAT cross-platform Java RAT bundles"
        severity    = "critical"
        threat_type = "RAT.AlienSpy"
        mitre_att   = "T1059.007, T1027.002, T1082"

    strings:
        // Java JAR ZIP signature: 50 4B 03 04
        // AlienSpy class markers and internal paths
        $cls1 = "AlienSpy" ascii
        $cls2 = "adwind" nocase ascii
        $cls3 = "spymodule" nocase ascii
        $cls4 = "jrat" nocase ascii
        $cls5 = "Frutas" ascii

        // Obfuscated config loader entries
        $cfg1 = "config.ini" ascii
        $cfg2 = "password.txt" ascii
        $cfg3 = "META-INF/MANIFEST.MF" ascii

        // Byte pattern: Java bytecode header inside embedded class or zip entry
        // CA FE BA BE (magic) followed by major/minor versions
        $java_magic = { 50 4B 03 04 [26-200] CA FE BA BE }

    condition:
        (uint32(0) == 0x04034b50 or uint32(0) == 0xbebafeca) and (
            2 of ($cls*) or
            ($java_magic and 1 of ($cls*)) or
            ($cls1 and 1 of ($cfg*))
        )
}

/* ----------------------------------------------------------------------------
   8. Cobalt Strike Malicious Documents (Beacon Stagers)
   Matches OLE/RTF/VBA/XLM droppers delivering Cobalt Strike shellcode beacons
   via Process Hollowing, HeapAlloc, or VirtualAlloc cradles.
   ---------------------------------------------------------------------------- */
rule Dropper_Doc_CobaltStrike_Stager
{
    meta:
        description = "Detects Cobalt Strike macro, RTF weaponization, and staged Beacon shellcode droppers"
        severity    = "critical"
        threat_type = "Stager.CobaltStrike.Office"
        mitre_att   = "T1204.002, T1059.005, T1055.002"

    strings:
        // VBA execution entry points
        $vba_entry1 = "AutoOpen" nocase ascii wide
        $vba_entry2 = "Document_Open" nocase ascii wide
        $vba_entry3 = "Workbook_Open" nocase ascii wide

        // Windows API allocation / execution imports called in VBA stagers
        $api1 = "VirtualAlloc" nocase ascii wide
        $api2 = "RtlMoveMemory" nocase ascii wide
        $api3 = "CreateThread" nocase ascii wide
        $api4 = "VirtualProtect" nocase ascii wide
        $api5 = "QueueUserAPC" nocase ascii wide
        $api6 = "HeapCreate" nocase ascii wide

        // Cobalt Strike default stager shellcode byte sequence
        // FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 (cld ; call ... ; pushad ; mov ebp, esp ; xor edx, edx ; mov edx, [fs:edx+0x30])
        $cs_stager_x86 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }

        // Cobalt Strike x64 stager shellcode preamble
        // FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 (cld ; and rsp, -0x10 ; call ...)
        $cs_stager_x64 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 }

        // Common hex/base64 encoded stager strings in CS docs
        $cs_str1 = "cobaltstrike" nocase ascii wide
        $cs_str2 = "/api/v2/" ascii
        $cs_str3 = "%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand" nocase ascii wide

    condition:
        (IsOfficeOrOLE or IsPE) and (
            $cs_stager_x86 or
            $cs_stager_x86 or
            $cs_stager_x64 or
            (any of ($vba_entry*) and 2 of ($api*)) or
            any of ($cs_str*)
        )
}