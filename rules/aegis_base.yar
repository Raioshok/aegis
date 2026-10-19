/*
   Aegis AV — bundled baseline YARA rules (compiled into the binary).
   Add your own under ~/.config/aegis/yara-rules/*.yar.
   Recognised metadata: severity = low|medium|high|critical, description.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file (harmless industry-standard test)"
        severity    = "high"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

// ELF magic (0x7f 'E' 'L' 'F') and PE magic ('M' 'Z').
// Exclude compiled binaries and bytecode from script-intent matching to avoid incidental string hits.
private rule IsELF { condition: uint32(0) == 0x464c457f }
private rule IsPE  { condition: uint16(0) == 0x5a4d }
private rule IsPyc { condition: uint16(2) == 0x0a0d or uint16(2) == 0x0d0d }

rule Linux_Reverse_Shell_Bash
{
    meta:
        description = "Bash reverse shell using /dev/tcp"
        severity    = "high"
    strings:
        $a = "/dev/tcp/"
        $b = "0>&1"
        $c = "bash -i"
    condition:
        not IsELF and not IsPE and not IsPyc and $a and ($b or $c)
}

rule Linux_Reverse_Shell_Python
{
    meta:
        description = "Python reverse shell (socket + dup2 + /bin/sh)"
        severity    = "high"
    strings:
        $sock = "socket.socket("
        $conn = ".connect(("
        $dup  = "dup2("
        $sh   = "/bin/sh"
    condition:
        not IsELF and not IsPE and not IsPyc and 3 of them
}

rule Dropper_Curl_Pipe_Shell
{
    meta:
        description = "Remote script piped straight into a shell (dropper)"
        severity    = "medium"
    strings:
        $a = /(curl|wget)\s+[^\n|]{0,200}\|\s*(bash|sh|zsh)/
    condition:
        not IsELF and not IsPE and not IsPyc and $a
}

rule Obfuscation_Base64_Exec
{
    meta:
        description = "Base64-decoded content piped to an interpreter"
        severity    = "medium"
    strings:
        $a = /base64\s+(-d|--decode)[^\n|]{0,60}\|\s*(bash|sh|python)/
        $b = /eval\s*\(\s*(atob|Buffer\.from|base64_decode)/
    condition:
        not IsELF and not IsPE and not IsPyc and any of them
}

rule Linux_CryptoMiner
{
    meta:
        description = "Common cryptominer / XMRig configuration strings"
        severity    = "high"
    strings:
        $a = "stratum+tcp://"
        $b = "xmrig" nocase
        $c = "cryptonight" nocase
        $d = "--donate-level"
    condition:
        2 of them
}

rule Linux_Persistence_Cron_SSH
{
    meta:
        description = "Writes to cron or authorized_keys for persistence"
        severity    = "low"
    strings:
        // Require write/append intent, not a bare path mention.
        $a = /(>>?)\s*\S{0,40}(\/etc\/cron|\.ssh\/authorized_keys)/
        $b = /\|\s*crontab\s+-/
    condition:
        not IsELF and not IsPE and not IsPyc and any of them
}

/* ==========================================================================
   2024-2026 TOP MALWARE & THREAT CAMPAIGN RULES
   ========================================================================== */

rule Win_Lumma_Stealer_2024_2026
{
    meta:
        description = "Lumma Stealer C2 communication and credential harvesting markers (2024-2026 dominant infostealer)"
        severity    = "critical"
    strings:
        $c2_1 = "api/v2/" ascii
        $c2_2 = "/api/v2/" ascii
        $tgt1 = "Telegram Desktop\\tdata" ascii wide
        $tgt2 = "Chrome\\User Data\\Default\\Login Data" ascii wide
        $tgt3 = "Edge\\User Data\\Default\\Login Data" ascii wide
        $tgt4 = "wallet.dat" ascii wide
        $tgt5 = "MetaMask" ascii wide
        $anti1 = "CPUSPEED" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
    condition:
        IsPE and (
            ($c2_1 or $c2_2) and 2 of ($tgt1, $tgt2, $tgt3, $tgt4, $tgt5)
            or (3 of ($tgt1, $tgt2, $tgt3, $tgt4, $tgt5) and any of ($anti1, $anti2))
        )
}

rule Win_Stealc_Infostealer
{
    meta:
        description = "Stealc infostealer configuration decryptor and extension targeting (2024-2026)"
        severity    = "critical"
    strings:
        $api1 = "/api/" ascii
        $hwid = "hwid=" ascii
        $ext1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii // MetaMask extension ID
        $ext2 = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii // TronLink extension ID
        $ext3 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii // Phantom extension ID
        $browser = "\\Local State" ascii wide
    condition:
        IsPE and (
            $api1 and $hwid and $browser and 1 of ($ext1, $ext2, $ext3)
        )
}

rule Win_CobaltStrike_Beacon_C2
{
    meta:
        description = "Cobalt Strike malleable C2 beacon configuration markers and sleep obfuscation"
        severity    = "critical"
    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\status_" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide
        $magic = "%s as %s\\%s: %d" ascii
        $postex = "ReflectiveLoader" ascii
        $b1 = "beacon.dll" ascii wide
        $b2 = "beacon.x64.dll" ascii wide
    condition:
        IsPE and (
            any of ($pipe1, $pipe2, $pipe3)
            or ($magic and $postex)
            or ($b1 or $b2)
        )
}

rule Win_Havoc_Demon_C2
{
    meta:
        description = "Havoc C2 Demon payload and KaynLdr reflective loader (2024-2026 open-source adversary framework)"
        severity    = "critical"
    strings:
        $h1 = "Demon.x64.bin" ascii wide
        $h2 = "Demon.x86.bin" ascii wide
        $h3 = "KaynLdr" ascii
        $h4 = "Havoc" ascii wide
        $cmd1 = "demon.sleep" ascii
        $cmd2 = "demon.checkin" ascii
    condition:
        IsPE and (
            any of ($h1, $h2, $h3)
            or ($h4 and ($cmd1 or $cmd2))
        )
}

rule Win_DarkGate_Loader
{
    meta:
        description = "DarkGate loader AutoIt/Delphi payload and Defender exclusion markers (2024-2026)"
        severity    = "high"
    strings:
        $s1 = "Add-MpPreference -ExclusionPath" ascii wide
        $s2 = "Add-MpPreference -ExclusionProcess" ascii wide
        $auto1 = "AutoIt3" ascii
        $auto2 = "This is a compiled AutoIt script" ascii wide
        $dark1 = "DarkGate" ascii wide
        $cmd = "cmd.exe /c start" ascii wide
    condition:
        IsPE and (
            ($s1 or $s2) and any of ($auto1, $auto2, $dark1, $cmd)
        )
}

rule Ransomware_LockBit_Akira_RansomHub
{
    meta:
        description = "LockBit 3.0 (Black), Akira, and RansomHub command flags and note signatures (2024-2026)"
        severity    = "critical"
    strings:
        $lb1 = ".lockbit" ascii wide
        $lb2 = "Restore-My-Files.txt" ascii wide
        $lb3 = "-pass" ascii wide
        $ak1 = ".akira" ascii wide
        $ak2 = "akira_readme.txt" ascii wide
        $ak3 = "fn.pow" ascii
        $rh1 = "RansomHub" ascii wide
        $rh2 = "-path" ascii wide
        $esxi = "vim-cmd vmsvc/power.off" ascii
    condition:
        ($lb1 and ($lb2 or $lb3)) or ($ak1 and ($ak2 or $ak3)) or ($rh1 and $rh2) or ($esxi and any of ($ak1, $lb1, $rh1))
}

rule Linux_Backdoor_XZ_CVE_2024_3094
{
    meta:
        description = "XZ Utils supply chain backdoor (CVE-2024-3094, liblzma sshd RCE)"
        severity    = "critical"
    strings:
        // Build-time extraction and injection script signatures
        $s1 = "eval $gl_path_map" ascii
        $s2 = "eval $gl_test_extract" ascii
        $s3 = "sed -r \"$gl_am_configmake\"" ascii
        // Function redirection signature targeting RSA_public_decrypt
        $r1 = "RSA_public_decrypt" ascii
        $r2 = "liblzma.so.5" ascii
    condition:
        ($s1 and $s2) or ($s3 and $s1) or (IsELF and $r1 and $r2 and filesize < 3000KB)
}

rule Linux_Rootkit_BPFdoor
{
    meta:
        description = "BPFdoor eBPF/raw-socket stealth backdoor (2024-2026 active cyber espionage tool)"
        severity    = "critical"
    strings:
        $ptmx = "/dev/ptmx" ascii
        $magic = { 52 72 73 76 } // Rrsv magic packet
        $sh = "/bin/sh" ascii
        $sock = "AF_PACKET" ascii
        $ipt = "iptables -t nat -D" ascii
    condition:
        IsELF and (
            ($ptmx and $magic)
            or ($ipt and $magic)
            or ($ptmx and $sock and $sh)
        )
}

rule Linux_Kinsing_Botnet
{
    meta:
        description = "Kinsing container / cloud botnet loader and cryptominer agent (2024-2026)"
        severity    = "high"
    strings:
        $k1 = "kdevtmpfsi" ascii
        $k2 = "kinsing" ascii
        $k3 = "alsp.sh" ascii
        $c1 = "/var/run/docker.sock" ascii
        $c2 = "k8s" ascii
        $cron = "/etc/cron.d/" ascii
    condition:
        IsELF and (
            ($k1 or $k2) and any of ($k3, $c1, $c2, $cron)
        )
}

/* ==========================================================================
   MALWARE DATABASE RULES (Cybersight, Da2dalus & Cryptware Repositories)
   ========================================================================== */

rule Ransom_WannaCry_EternalBlue
{
    meta:
        description = "WannaCry / WannaCrypt ransomware artifacts and task scheduler payload"
        severity    = "critical"
    strings:
        $w1 = "@WanaDecryptor@.exe" ascii wide
        $w2 = "WNcry@2ol7" ascii
        $w3 = "tasksche.exe" ascii wide
        $w4 = ".wnry" ascii wide
        $w5 = "c.wnry" ascii wide
        $w6 = "t.wnry" ascii wide
    condition:
        2 of ($w1, $w2, $w3, $w4, $w5, $w6)
}

rule Ransom_Petya_NotPetya_GoldenEye
{
    meta:
        description = "Petya, NotPetya, and GoldenEye MBR encryption and event log wiping commands"
        severity    = "critical"
    strings:
        $p1 = "wevtutil cl Setup" ascii wide
        $p2 = "wevtutil cl System" ascii wide
        $p3 = "wevtutil cl Security" ascii wide
        $p4 = "fsutil usn deletejournal" ascii wide
        $p5 = "perfc.dat" ascii wide
        $p6 = "1HourAfterShutdown" ascii wide
    condition:
        2 of ($p1, $p2, $p3, $p4, $p5, $p6)
}

rule Ransom_BadRabbit
{
    meta:
        description = "BadRabbit ransomware and DiskCryptor bootloader tasks"
        severity    = "critical"
    strings:
        $b1 = "cscc.dat" ascii wide
        $b2 = "infpub.dat" ascii wide
        $b3 = "schtasks /Create /RU 'SYSTEM' /TN 'rhaegal'" ascii wide
        $b4 = "schtasks /Create /RU 'SYSTEM' /TN 'drogon'" ascii wide
    condition:
        2 of ($b1, $b2, $b3, $b4)
}

rule Ransom_GandCrab_Cerber
{
    meta:
        description = "GandCrab and Cerber ransomware extension and decryption instruction markers"
        severity    = "critical"
    strings:
        $g1 = "GDCB-DECRYPT.txt" ascii wide
        $g2 = "KRAB-DECRYPT.txt" ascii wide
        $c1 = "_HELP_HELP_HELP_" ascii wide
        $c2 = "Cerber Ransomware" ascii wide
    condition:
        any of ($g1, $g2, $c1, $c2)
}

rule Wiper_Hermetic_Caddy_DriveZero
{
    meta:
        description = "HermeticWiper and CaddyWiper raw drive access and partition table destruction"
        severity    = "critical"
    strings:
        $raw1 = "\\\\.\\PhysicalDrive" ascii wide
        $raw2 = "\\\\.\\CdRom" ascii wide
        $priv1 = "SeLoadDriverPrivilege" ascii wide
        $priv2 = "SeBackupPrivilege" ascii wide
        $zero = "IOCTL_DISK_GET_DRIVE_LAYOUT_EX" ascii
    condition:
        IsPE and (
            ($raw1 and any of ($priv1, $priv2, $zero))
            or ($raw1 and $raw2 and any of ($priv1, $priv2))
        )
}

rule Stealer_AgentTesla_Lokibot
{
    meta:
        description = "AgentTesla and Lokibot infostealer credential exfiltration strings"
        severity    = "critical"
    strings:
        $at1 = "SmtpClient" ascii
        $at2 = "smtp." ascii wide
        $at3 = "PW=" ascii
        $at4 = "Account=" ascii
        $loki1 = "kav.php" ascii
        $loki2 = "fre.php" ascii
        $loki3 = "ckav.ru" ascii
    condition:
        IsPE and (
            ($at1 and $at2 and ($at3 or $at4))
            or any of ($loki1, $loki2, $loki3)
        )
}

rule RAT_NJRat_Remcos_NetWire
{
    meta:
        description = "NJRat, Remcos, and NetWire remote access trojan commands and configuration"
        severity    = "critical"
    strings:
        $nj1 = "netsh firewall add allowedprogram" ascii wide
        $nj2 = "cmd.exe /c ping 0 -n 2 & del" ascii wide
        $rem1 = "Remcos Professional" ascii wide
        $rem2 = "Remote Security Administration" ascii wide
        $nw1 = "NetWire" ascii wide
        $nw2 = "LOG_DIRECTORY" ascii wide
    condition:
        any of ($nj1, $nj2, $rem1, $rem2, $nw1, $nw2)
}

rule RAT_Warzone_AsyncRAT_XWorm
{
    meta:
        description = "WarzoneRAT (AveMaria), AsyncRAT, and XWorm connection loops and mutexes"
        severity    = "critical"
    strings:
        $wz1 = "Ave_Maria" ascii wide
        $wz2 = "warzone160" ascii wide
        $async1 = "AsyncMutex_" ascii wide
        $async2 = "AsyncRAT" ascii wide
        $xw1 = "XWorm V" ascii wide
        $dc1 = "DcRat" ascii wide
    condition:
        any of ($wz1, $wz2, $async1, $async2, $xw1, $dc1)
}

/* ==========================================================================
   BATCH 3 RULES (Log4J Exploits, Banking Trojans, P2P Botnets & Network Worms)
   ========================================================================== */

rule Exploit_Log4J_JNDI_Payload
{
    meta:
        description = "Log4Shell (CVE-2021-44228) JNDI lookup strings and Khonsari ransomware markers"
        severity    = "critical"
    strings:
        $jndi1 = "${jndi:ldap://" ascii nocase
        $jndi2 = "${jndi:rmi://" ascii nocase
        $jndi3 = "${jndi:dns://" ascii nocase
        $jndi4 = "${jndi:nis://" ascii nocase
        $khon1 = ".khonsari" ascii wide
        $khon2 = "HOW_TO_DECRYPT_FILES.txt" ascii wide
    condition:
        any of ($jndi1, $jndi2, $jndi3, $jndi4) or ($khon1 and $khon2)
}

rule Banking_Dridex_Emotet_ZLoader
{
    meta:
        description = "Dridex, Emotet, and ZLoader modular banking trojan loader signatures"
        severity    = "critical"
    strings:
        $dridex1 = "Dridex" ascii wide
        $dridex2 = "JhiSharp.dll" ascii wide
        $emotet1 = "Emotet" ascii wide
        $zloader1 = "zloader" ascii wide
        $zloader2 = "SilentNight" ascii wide
        $ursnif1 = "client.bin" ascii
        $ursnif2 = "serp.bin" ascii
    condition:
        any of ($dridex1, $dridex2, $emotet1, $zloader1, $zloader2) or ($ursnif1 and $ursnif2)
}

rule Botnet_FritzFrog_Linux_P2P
{
    meta:
        description = "FritzFrog P2P Golang botnet and fileless memfd execution strings"
        severity    = "critical"
    strings:
        $f1 = "fritzfrog" ascii
        $f2 = "lib/f/f" ascii
        $f3 = "net/ssh" ascii
        $f4 = "memfd_create" ascii
        $f5 = "libexec" ascii
    condition:
        IsELF and (
            $f1 or ($f2 and $f3) or ($f4 and $f3 and $f5)
        )
}

rule Worm_Blaster_Sasser_EternalRocks
{
    meta:
        description = "Blaster, Sasser, and EternalRocks network worm signatures"
        severity    = "critical"
    strings:
        $blaster1 = "msblast.exe" ascii wide
        $blaster2 = "billy gates why do you make this possible" ascii
        $blaster3 = "I just want to say LOVE YOU SAN!" ascii
        $sasser1 = "avserve.exe" ascii wide
        $sasser2 = "avserve2.exe" ascii wide
        $erocks1 = "EternalRocks" ascii wide
        $erocks2 = "Doublepulsar" ascii wide
    condition:
        any of ($blaster1, $blaster2, $blaster3, $sasser1, $sasser2, $erocks1, $erocks2)
}

rule Email_Worm_ILOVEYOU_MyDoom_Brontok
{
    meta:
        description = "Classic email worm propagation and mass-mailer scripts"
        severity    = "critical"
    strings:
        $ilove1 = "LOVE-LETTER-FOR-YOU.TXT.vbs" ascii wide
        $ilove2 = "MAPI.Session" ascii
        $mydoom1 = "sync_scan" ascii
        $mydoom2 = "shimgapi.dll" ascii wide
        $brontok1 = "Rontokbro" ascii wide
        $brontok2 = "Tok-Cirrhatus" ascii wide
    condition:
        ($ilove1 and $ilove2) or ($mydoom1 and $mydoom2) or ($brontok1 or $brontok2)
}

/* ==========================================================================
   BATCH 4 & 5 RULES (Rogue AVs, Android Malware, File Infectors & LKM Rootkits)
   ========================================================================== */

rule Rogue_Scareware_FakeAV
{
    meta:
        description = "Rogue Antivirus and scareware extortion payloads"
        severity    = "high"
    strings:
        $r1 = "Antivirus 2010" ascii wide
        $r2 = "Internet Security Guard" ascii wide
        $r3 = "CleanThis" ascii wide
        $r4 = "FakeAdwCleaner" ascii wide
        $r5 = "Your computer is infected!" ascii wide
        $r6 = "Click here to remove all threats" ascii wide
    condition:
        2 of ($r1, $r2, $r3, $r4, $r5, $r6)
}

rule Android_SMS_Ransom_Locker
{
    meta:
        description = "Android lock-screen ransomware and SMS premium trojan markers"
        severity    = "critical"
    strings:
        $a1 = "TYPE_SYSTEM_ALERT" ascii
        $a2 = "DevicePolicyManager" ascii
        $a3 = "sendTextMessage" ascii
        $a4 = "android.provider.Telephony.SMS_RECEIVED" ascii
        $a5 = "LOCK_NOW" ascii
    condition:
        ($a1 and ($a2 or $a5)) or ($a3 and $a4)
}

rule Virus_Floxif_Melissa_Xpaj
{
    meta:
        description = "Macro viruses and polymorphic file infectors (Melissa, Floxif, Xpaj)"
        severity    = "critical"
    strings:
        $m1 = "ActiveDocument.VBProject.VBComponents" ascii
        $m2 = "Document_Open" ascii
        $f1 = "Floxif" ascii wide
        $x1 = "xpaj" ascii wide
    condition:
        ($m1 and $m2) or $f1 or $x1
}

rule Linux_Rootkit_LKM_SysCallHook
{
    meta:
        description = "Linux Loadable Kernel Module (LKM) rootkits and sys_call_table hijackers"
        severity    = "critical"
    strings:
        $k1 = "sys_call_table" ascii
        $k2 = "sys_getdents64" ascii
        $k3 = "kallsyms_lookup_name" ascii
        $k4 = "hide_process" ascii
        $k5 = "set_memory_rw" ascii
    condition:
        3 of ($k1, $k2, $k3, $k4, $k5)
}

rule Win32_ProcessHollowing_RunPE
{
    meta:
        description = "Process hollowing and RunPE memory injector API sequences"
        severity    = "critical"
    strings:
        $p1 = "ZwUnmapViewOfSection" ascii
        $p2 = "VirtualAllocEx" ascii
        $p3 = "WriteProcessMemory" ascii
        $p4 = "SetThreadContext" ascii
        $p5 = "ResumeThread" ascii
    condition:
        IsPE and (4 of ($p1, $p2, $p3, $p4, $p5))
}
