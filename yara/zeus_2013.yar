rule Zeus_BankingTrojan_26Nov2013_Sample {
    meta:
        description    = "Detects Zeus Banking Trojan sample from November 2013"
        author         = "Alister A. Rodrigues"
        date           = "2025-12-08"
        reference      = "MD5: ea039a854d20d7734c5add48f1a51c34"
        severity       = "high"
        malware_family = "Zeus"

    strings:
        $domain         = "corect.com" ascii wide
        $geo            = "j.maxmind.com" ascii wide
        $fake_desc      = "Adobe Flash Player Installer" ascii wide
        $fake_copyright = "1996-2011 Adobe, Inc." ascii wide
        $original_name  = "FlashUtil.exe" ascii wide

        $api1 = "GetAsyncKeyState" ascii
        $api2 = "CreateFileMappingA" ascii
        $api3 = "GetClipboardData" ascii
        $api4 = "VirtualQueryEx" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        (
            ($domain and $geo) or
            ($fake_desc and $fake_copyright and $original_name) or
            (3 of ($api*))
        )
}
