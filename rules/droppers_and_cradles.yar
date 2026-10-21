/*
   Aegis AV — High-Fidelity YARA-X Rules
   GandCrab / Emotet Macro Droppers, Malicious JS/VBS Downloaders, and PowerShell Download Cradles
   
   Recognised metadata:
     - severity    = "low" | "medium" | "high" | "critical"
     - description = "..."
     - threat_type = "..."
     - mitre_att   = "..."
*/

// ============================================================================
// Private Helpers
// ============================================================================

// Detect Microsoft Office compound documents (OLE CFBF), OOXML (ZIP archives), or RTF
private rule IsOfficeDocument
{
    condition:
        // OLE Composite Document File (CFBF) header: D0 CF 11 E0 A1 B1 1A E1
        (uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1) or
        // OOXML ZIP archive: PK\x03\x04
        uint32(0) == 0x04034b50 or
        // RTF document: "{\rt"
        uint32(0) == 0x74725c7b
}

// ============================================================================
// Category 1: Office Macro Droppers (Emotet, GandCrab & Generic Cradles)
// ============================================================================

rule Macro_Dropper_AutoExec_Suspicious
{
    meta:
        description = "Office document with auto-execution macro invoking suspicious shell or process execution"
        severity    = "high"
        threat_type = "Trojan.Dropper.Macro"
        mitre_att   = "T1204.002, T1059.005"
    strings:
        // Auto-exec triggers
        $trig1 = "AutoOpen" nocase ascii wide
        $trig2 = "Auto_Open" nocase ascii wide
        $trig3 = "AutoExec" nocase ascii wide
        $trig4 = "Document_Open" nocase ascii wide
        $trig5 = "Workbook_Open" nocase ascii wide
        $trig6 = "Document_Close" nocase ascii wide
        $trig7 = "UserForm_Initialize" nocase ascii wide
        $trig8 = "Workbook_BeforeClose" nocase ascii wide

        // Process creation / execution sinks
        $sink1 = "WScript.Shell" nocase ascii wide
        $sink2 = "Shell.Application" nocase ascii wide
        $sink3 = "winmgmts:" nocase ascii wide
        $sink4 = "Win32_Process" nocase ascii wide
        $sink5 = "Interaction.Shell" nocase ascii wide
        $sink6 = "MacScript" nocase ascii wide
        $sink7 = "CallByName" nocase ascii wide

        // Suspicious payload invocation markers
        $exec1 = "powershell" nocase ascii wide
        $exec2 = "cmd.exe" nocase ascii wide
        $exec3 = "certutil" nocase ascii wide
        $exec4 = "rundll32" nocase ascii wide
        $exec5 = "regsvr32" nocase ascii wide
        $exec6 = "bitsadmin" nocase ascii wide
        $exec7 = "mshta" nocase ascii wide
    condition:
        IsOfficeDocument and
        (any of ($trig*)) and
        (any of ($sink*)) and
        (any of ($exec*))
}

rule Macro_Dropper_Emotet_Heuristic
{
    meta:
        description = "Emotet macro dropper heuristic (WMI Win32_Process, obfuscated command line, multi-URL staging)"
        severity    = "critical"
        threat_type = "Trojan-Dropper.MSOffice.Emotet"
        malware     = "Emotet"
        mitre_att   = "T1059.005, T1047, T1105"
    strings:
        // WMI Process spawning pattern commonly abused by Emotet to detach process tree
        $wmi1 = "winmgmts" nocase ascii wide
        $wmi2 = "Win32_Process" nocase ascii wide
        $wmi3 = "Win32_ProcessStartup" nocase ascii wide
        $wmi4 = "Create" nocase ascii wide

        // Obfuscation / string assembly techniques
        $obf1 = "Chr(" nocase ascii wide
        $obf2 = "ChrW(" nocase ascii wide
        $obf3 = "Chr$(" nocase ascii wide
        $obf4 = "Replace(" nocase ascii wide
        $obf5 = "StrReverse(" nocase ascii wide

        // Emotet document element scraping (stored in shapes, labels, comments)
        $elem1 = "Shapes(" nocase ascii wide
        $elem2 = "InlineShapes(" nocase ascii wide
        $elem3 = ".AlternativeText" nocase ascii wide
        $elem4 = ".Tag" nocase ascii wide
        $elem5 = "ActiveDocument.Variables" nocase ascii wide
        $elem6 = "ActiveDocument.Comments" nocase ascii wide

        // Command invocation patterns
        $cmd1 = /powershell(\.exe)?\s+(-(w|windowstyle)\s+(1|hidden)|-(e|enc|encodedcommand)|-(nop|noprofile))/ nocase ascii wide
        $cmd2 = /cmd(\.exe)?\s+(\/c|\/k)\s+[\'\"%]/ nocase ascii wide
        $cmd3 = "%COMSPEC%" nocase ascii wide
        $cmd4 = "Environ(\"windir\")" nocase ascii wide
        $cmd5 = "Environ(\"temp\")" nocase ascii wide
    condition:
        IsOfficeDocument and
        (
            // Pattern 1: WMI process spawn + string obfuscation + command launch
            (2 of ($wmi*) and 2 of ($obf*) and any of ($cmd*)) or
            // Pattern 2: Document element scraping + obfuscation + command launch
            (any of ($elem*) and 2 of ($obf*) and any of ($cmd*)) or
            // Pattern 3: WMI Win32_Process + element scraping
            (all of ($wmi1, $wmi2, $wmi4) and any of ($elem*))
        )
}

rule Macro_Dropper_GandCrab_Delivery
{
    meta:
        description = "GandCrab ransomware macro dropper (phishing lure, certutil/PS fetch, staging in Temp/AppData)"
        severity    = "critical"
        threat_type = "Trojan-Ransom.MSOffice.GandCrab"
        malware     = "GandCrab"
        mitre_att   = "T1204.002, T1105, T1486"
    strings:
        // Phishing lures typical of GandCrab document campaigns
        $lure1 = "Enable Content" nocase ascii wide
        $lure2 = "Enable Editing" nocase ascii wide
        $lure3 = "Document created in earlier version" nocase ascii wide
        $lure4 = "Protected Document" nocase ascii wide
        $lure5 = "GDPR" nocase ascii wide

        // GandCrab staging locations & APIs
        $stage1 = "%TEMP%" nocase ascii wide
        $stage2 = "%APPDATA%" nocase ascii wide
        $stage3 = "%ALLUSERSPROFILE%" nocase ascii wide
        $stage4 = "Environ(\"TEMP\")" nocase ascii wide
        $stage5 = "Environ(\"APPDATA\")" nocase ascii wide
        $stage6 = "C:\\Users\\Public" nocase ascii wide

        // External API declarations for direct download / execution
        $api1 = "URLDownloadToFileA" ascii wide
        $api2 = "URLDownloadToFileW" ascii wide
        $api3 = "urlmon.dll" nocase ascii wide
        $api4 = "ShellExecuteA" ascii wide
        $api5 = "ShellExecuteW" ascii wide

        // Command-line downloader utilities
        $dl1 = /certutil(\.exe)?\s+(-urlcache\s+)?-split\s+-f\s+https?:\/\// nocase ascii wide
        $dl2 = /bitsadmin(\.exe)?\s+\/transfer\s+/ nocase ascii wide
        $dl3 = /powershell[^\n\r]{0,100}(DownloadFile|DownloadString)[^\n\r]{0,100}https?:\/\// nocase ascii wide

        // Proxy binary execution
        $proxy1 = /rundll32(\.exe)?\s+[^\n\r,]{1,80},[a-zA-Z0-9_]+/ nocase ascii wide
        $proxy2 = /regsvr32(\.exe)?\s+(\/s|\/u|\/n|\/i)/ nocase ascii wide
    condition:
        IsOfficeDocument and
        (
            // Direct API download pattern
            (any of ($api1, $api2) and $api3 and (any of ($api4, $api5) or any of ($stage*))) or
            // Certutil / Bitsadmin / PowerShell download with staging
            (any of ($dl*) and (any of ($stage*) or any of ($lure*))) or
            // Proxy execution paired with download/staging
            (any of ($proxy*) and any of ($dl*)) or
            // Lure + download + execution
            (any of ($lure*) and any of ($dl*) and any of ($proxy*))
        )
}

rule Excel_XLM_40_Macro_Dropper
{
    meta:
        description = "Excel 4.0 (XLM) macro dropper using CALL/EXEC/URLDownloadToFile"
        severity    = "high"
        threat_type = "Trojan-Dropper.MSExcel.XLM"
        mitre_att   = "T1204.002, T1059"
    strings:
        // XLM Macro formulas
        $exec1 = "=EXEC(" nocase ascii wide
        $exec2 = "=CALL(" nocase ascii wide
        $exec3 = "=RUN(" nocase ascii wide
        $exec4 = "=HALT(" nocase ascii wide
        $exec5 = "=FORMULA(" nocase ascii wide

        // High-risk API calls commonly passed into CALL()
        $api1 = "URLDownloadToFileA" nocase ascii wide
        $api2 = "ShellExecuteA" nocase ascii wide
        $api3 = "WinExec" nocase ascii wide
        $api4 = "urlmon" nocase ascii wide
        $api5 = "shell32" nocase ascii wide
        $api6 = "kernel32" nocase ascii wide

        // XLM macrosheet artifact in modern OOXML
        $ooxml_sheet = "macrosheets/sheet" nocase ascii
    condition:
        IsOfficeDocument and
        (
            ($ooxml_sheet and (any of ($exec*) or any of ($api*))) or
            ($exec2 and any of ($api1, $api2, $api3)) or
            ($exec1 and ($exec4 or any of ($api*))) or
            (3 of ($exec*))
        )
}

// ============================================================================
// Category 2: Malicious JavaScript & VBScript Downloaders
// ============================================================================

rule Malicious_JS_VBS_Dropper_WSH
{
    meta:
        description = "Windows Script Host (JS/VBS) downloader using XMLHTTP + ADODB.Stream + Shell.Run"
        severity    = "high"
        threat_type = "Trojan-Downloader.Script.Generic"
        mitre_att   = "T1059.005, T1059.007, T1105"
    strings:
        // HTTP Request components
        $http1 = "MSXML2.XMLHTTP" nocase ascii wide
        $http2 = "Microsoft.XMLHTTP" nocase ascii wide
        $http3 = "MSXML2.ServerXMLHTTP" nocase ascii wide
        $http4 = "WinHttp.WinHttpRequest.5.1" nocase ascii wide

        // Binary Stream writing components
        $stream1 = "ADODB.Stream" nocase ascii wide
        $stream2 = ".Type = 1" nocase ascii wide
        $stream3 = ".Type=1" nocase ascii wide
        $stream4 = ".SaveToFile" nocase ascii wide
        $stream5 = ".responseBody" nocase ascii wide

        // Shell execution components
        $sh1 = "WScript.Shell" nocase ascii wide
        $sh2 = "Shell.Application" nocase ascii wide
        $sh3 = ".Run" nocase ascii wide
        $sh4 = ".Exec" nocase ascii wide
        $sh5 = ".ShellExecute" nocase ascii wide

        // Staging indicators
        $env1 = "Scripting.FileSystemObject" nocase ascii wide
        $env2 = "GetSpecialFolder(2)" nocase ascii wide
        $env3 = "%TEMP%" nocase ascii wide
        $env4 = "%APPDATA%" nocase ascii wide
    condition:
        // Must combine HTTP retrieval + binary file persistence + execution
        (any of ($http*)) and
        ($stream1 and ($stream4 or $stream5 or any of ($stream2, $stream3))) and
        ((any of ($sh1, $sh2) and any of ($sh3, $sh4, $sh5)) or any of ($env*))
}

rule Malicious_Script_Obfuscated_Eval_Exec
{
    meta:
        description = "Obfuscated JavaScript / VBScript unpacker executing hidden code or processes"
        severity    = "high"
        threat_type = "Trojan-Downloader.Script.Obfuscated"
        mitre_att   = "T1027, T1059.005, T1059.007"
    strings:
        // Obfuscation indicators (JS & VBS)
        $js_eval1 = /eval\s*\(\s*(unescape|decodeURI|decodeURIComponent|atob|String\.fromCharCode)/ nocase ascii wide
        $js_eval2 = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)/ nocase ascii wide
        $js_func  = /Function\s*\(\s*[\'\"][^\'\"]*[\'\"]\s*\)\s*\(\s*\)/ nocase ascii wide

        $vbs_exec1 = /Execute(Global)?\s*\(\s*(Chr|ChrW|Replace|StrReverse)/ nocase ascii wide
        $vbs_exec2 = /Execute(Global)?\s+[a-zA-Z0-9_]+\s*\(/ nocase ascii wide

        // Malicious sink presence
        $sink1 = "ActiveXObject" nocase ascii wide
        $sink2 = "WScript.CreateObject" nocase ascii wide
        $sink3 = "WScript.Shell" nocase ascii wide
        $sink4 = "cmd.exe" nocase ascii wide
        $sink5 = "powershell" nocase ascii wide
        $sink6 = "MSXML2." nocase ascii wide
        $sink7 = "ADODB.Stream" nocase ascii wide
    condition:
        (any of ($js_eval*, $js_func) or any of ($vbs_exec*)) and
        (2 of ($sink*))
}

rule JS_VBS_GandCrab_Downloader
{
    meta:
        description = "GandCrab JavaScript / VBScript downloader variant"
        severity    = "critical"
        threat_type = "Trojan-Ransom.Script.GandCrab"
        malware     = "GandCrab"
        mitre_att   = "T1059.005, T1059.007, T1105, T1486"
    strings:
        // Phishing themes associated with GandCrab script droppers
        $theme1 = "invoice" nocase ascii wide
        $theme2 = "receipt" nocase ascii wide
        $theme3 = "order" nocase ascii wide
        $theme4 = "payment" nocase ascii wide
        $theme5 = "document" nocase ascii wide

        // Download indicators
        $dl1 = "GET" nocase ascii wide
        $dl2 = "http://" nocase ascii wide
        $dl3 = "https://" nocase ascii wide
        $dl4 = "open" nocase ascii wide
        $dl5 = "send" nocase ascii wide

        // Binary dropping and execution
        $exe1 = ".exe" nocase ascii wide
        $exe2 = ".dll" nocase ascii wide
        $sh1  = "WScript.Shell" nocase ascii wide
        $sh2  = ".Run" nocase ascii wide
        $env1 = "ExpandEnvironmentStrings" nocase ascii wide
        $env2 = "%TEMP%" nocase ascii wide
        $env3 = "%APPDATA%" nocase ascii wide

        // Sleep / evasion loop often used in GandCrab droppers
        $sleep = "WScript.Sleep" nocase ascii wide
    condition:
        ($sh1 and $sh2) and
        (any of ($theme*)) and
        (2 of ($dl*)) and
        (any of ($exe*)) and
        (any of ($env*)) and
        ($sleep or any of ($dl4, $dl5))
}

// ============================================================================
// Category 3: PowerShell Download Cradles
// ============================================================================

rule PowerShell_Download_Cradle_WebClient
{
    meta:
        description = "PowerShell download cradle via System.Net.WebClient (DownloadFile/DownloadString/DownloadData)"
        severity    = "high"
        threat_type = "Trojan-Downloader.PowerShell.WebClient"
        mitre_att   = "T1059.001, T1105"
    strings:
        // WebClient instantiation
        $wc1 = "Net.WebClient" nocase ascii wide
        $wc2 = "System.Net.WebClient" nocase ascii wide
        $wc3 = "[Net.WebClient]::new()" nocase ascii wide

        // Download methods
        $m1 = "DownloadFile(" nocase ascii wide
        $m2 = "DownloadString(" nocase ascii wide
        $m3 = "DownloadData(" nocase ascii wide
        $m4 = "OpenRead(" nocase ascii wide

        // Execution cradles
        $ex1 = "IEX" nocase ascii wide
        $ex2 = "Invoke-Expression" nocase ascii wide
        $ex3 = "[ScriptBlock]::Create" nocase ascii wide
        $ex4 = /\|\s*(iex|invoke-expression)/ nocase ascii wide

        // Tick-obfuscated execution
        $obf_iex1 = /`i`e`x/ nocase ascii wide
        $obf_iex2 = /`I`n`v`o`k`e-`E`x`p`r`e`s`s`i`o`n/ nocase ascii wide
        $obf_wc   = /`w`e`b`c`l`i`e`n`t/ nocase ascii wide
    condition:
        (
            (any of ($wc*) and any of ($m*)) or
            ($obf_wc or any of ($obf_iex*))
        ) and
        (
            any of ($ex*) or
            any of ($obf_iex*) or
            $m1 or $m3 or $m4 // DownloadFile / DownloadData / OpenRead are inherently droppers
        )
}

rule PowerShell_Download_Cradle_WebRequest_REST
{
    meta:
        description = "PowerShell download cradle via Invoke-WebRequest (iwr) or Invoke-RestMethod (irm)"
        severity    = "high"
        threat_type = "Trojan-Downloader.PowerShell.WebRequest"
        mitre_att   = "T1059.001, T1105"
    strings:
        // Invoke-WebRequest / aliases
        $iwr1 = /Invoke-WebRequest[^\n\r]{0,100}(-OutFile|-O\s+|\|\s*(iex|invoke-expression)|\.Content\s*\|\s*(iex|invoke-expression))/ nocase ascii wide
        $iwr2 = /(^|[\s;|&])iwr\s+[^\n\r]{0,100}(-OutFile|-O\s+|\|\s*(iex|invoke-expression)|\.Content\s*\|\s*(iex|invoke-expression))/ nocase ascii wide

        // Invoke-RestMethod / irm
        $irm1 = /Invoke-RestMethod[^\n\r]{0,100}\|\s*(iex|invoke-expression)/ nocase ascii wide
        $irm2 = /(^|[\s;|&])irm\s+[^\n\r]{0,100}\|\s*(iex|invoke-expression)/ nocase ascii wide

        // HttpClient async cradle
        $httpclient1 = "System.Net.Http.HttpClient" nocase ascii wide
        $httpclient2 = "GetStringAsync(" nocase ascii wide
        $httpclient3 = "GetByteArrayAsync(" nocase ascii wide
    condition:
        any of ($iwr*, $irm*) or
        ($httpclient1 and any of ($httpclient2, $httpclient3))
}

rule PowerShell_Download_Cradle_BitsTransfer
{
    meta:
        description = "PowerShell download cradle via Start-BitsTransfer or BITSAdmin"
        severity    = "medium"
        threat_type = "Trojan-Downloader.PowerShell.Bits"
        mitre_att   = "T1197, T1059.001"
    strings:
        $bits1 = /Start-BitsTransfer\s+[^\n\r]{0,100}-Source\s+['"]?https?:\/\// nocase ascii wide
        $bits2 = /bitsadmin(\.exe)?\s+(\/transfer|\/create|\/addfile)[^\n\r]{0,100}https?:\/\// nocase ascii wide
    condition:
        any of them
}

rule PowerShell_Download_Cradle_Obfuscated
{
    meta:
        description = "Obfuscated PowerShell download cradle (encoded commands, format string injection, reflection, compressed streams)"
        severity    = "critical"
        threat_type = "Trojan-Downloader.PowerShell.Obfuscated"
        mitre_att   = "T1027, T1059.001, T1105"
    strings:
        // Format string obfuscation for execution
        $fmt1 = /"\{[0-9]\}\{[0-9]\}"\s*-f\s*['"][iI]['"],\s*['"][eE][xX]['"]/ ascii wide
        $fmt2 = /"\(([0-9],?)+\)"\s*-f/ ascii wide

        // String reversal & array join cradle
        $rev1 = /\[string\]::join\(\s*['"]\s*,\s*\([^\)]*\[-1\.\.-[0-9]+\]\)\)/ nocase ascii wide
        $rev2 = /-join\s*\([^\)]*\[-1\.\.-[0-9]+\]\)/ nocase ascii wide

        // Reflection assembly load from memory
        $refl1 = "[System.Reflection.Assembly]::Load(" nocase ascii wide
        $refl2 = "[Reflection.Assembly]::Load(" nocase ascii wide
        $refl3 = "::LoadWithPartialName(" nocase ascii wide

        // Decompression streams often hiding cradles
        $zip1 = "System.IO.Compression.DeflateStream" nocase ascii wide
        $zip2 = "System.IO.Compression.GzipStream" nocase ascii wide
        $zip3 = "FromBase64String(" nocase ascii wide
        $zip4 = "MemoryStream" nocase ascii wide

        // Environment string slicing execution
        $env_slice1 = /\$env:ComSpec\[[0-9]+,[0-9]+,[0-9]+\]\s*-join/ nocase ascii wide
        $env_slice2 = /&(.*)\$env:COMSPEC/ nocase ascii wide

        // Encoded command flag with PowerShell executable
        $enc_flag = /powershell(\.exe)?\s+[^\n\r]{0,60}(-(e|enc|encodedcommand)\s+[A-Za-z0-9+\/]{40,}={0,2})/ nocase ascii wide
    condition:
        any of ($fmt*) or
        any of ($rev*) or
        (any of ($refl*) and $zip3) or
        (any of ($zip1, $zip2) and $zip3 and $zip4) or
        any of ($env_slice*) or
        $enc_flag
}

rule PowerShell_AMSI_ETW_Bypass_Tampering
{
    meta:
        description = "PowerShell in-memory AMSI or ETW bypass commonly chained before download cradles"
        severity    = "high"
        threat_type = "Defense-Evasion.PowerShell.AMSIBypass"
        mitre_att   = "T1562.001, T1059.001"
    strings:
        // Classic AmsiUtils reflection bypass
        $amsi1 = "AmsiUtils" nocase ascii wide
        $amsi2 = "amsiInitFailed" nocase ascii wide
        $amsi3 = "amsiContext" nocase ascii wide
        $amsi4 = "AmsiScanBuffer" nocase ascii wide

        // Memory patching primitives
        $mem1 = "VirtualProtect(" nocase ascii wide
        $mem2 = "[Runtime.InteropServices.Marshal]::Copy(" nocase ascii wide
        $mem3 = "[Runtime.InteropServices.Marshal]::WriteInt32(" nocase ascii wide
        $mem4 = "[Runtime.InteropServices.Marshal]::WriteByte(" nocase ascii wide

        // ETW patching
        $etw1 = "EtwEventWrite" nocase ascii wide
        $etw2 = "ntdll.dll" nocase ascii wide
    condition:
        ($amsi1 and ($amsi2 or $amsi3)) or
        ($amsi4 and (any of ($mem*))) or
        ($etw1 and $etw2 and (any of ($mem*)))
}
