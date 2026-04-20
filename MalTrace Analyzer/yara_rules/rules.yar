rule Suspicious_Functional_Signatures {
    meta:
        description = "Detects suspicious executable behavior"
        severity = "High"
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "CreateRemoteThread"
        $d = "VirtualAlloc"
        $e = "WScript.Shell" nocase
    condition:
        2 of them
}

rule RansomwareKeywords {
    meta:
        description = "Detects ransomware-related strings"
        severity = "Critical"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = ".locked" nocase
        $d = "ransom" nocase
    condition:
        2 of them
}

rule MimikatzDetection {
    meta:
        description = "Detects Mimikatz credential dumper"
        severity = "Critical"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
    condition:
        any of them
}

rule SuspiciousScript {
    meta:
        description = "Detects suspicious script behavior"
        severity = "Medium"
    strings:
        $a = "base64_decode" nocase
        $b = "eval(" nocase
        $c = "exec(" nocase
        $d = "os.system" nocase
    condition:
        2 of them
}