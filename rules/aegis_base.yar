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

// ELF magic (0x7f 'E' 'L' 'F'), little-endian at offset 0. Script-intent rules
// exclude compiled binaries to avoid matching incidental strings in them.
private rule IsELF { condition: uint32(0) == 0x464c457f }

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
        not IsELF and $a and ($b or $c)
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
        3 of them
}

rule Dropper_Curl_Pipe_Shell
{
    meta:
        description = "Remote script piped straight into a shell (dropper)"
        severity    = "medium"
    strings:
        $a = /(curl|wget)\s+[^\n|]{0,200}\|\s*(bash|sh|zsh)/
    condition:
        not IsELF and $a
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
        not IsELF and any of them
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
        not IsELF and any of them
}
