import "pe"

rule UNPROTECT_UAC_Bypass_Strings {
    meta:
        description = "Rule to detect UAC bypass attempt by regarding strings"
        author = "Thibault Seret"
        date = "2020-04-10"
    strings:
        $s1 = "SeIncreaseQuotaPrivilege" ascii fullword
        $s2 = "SeSecurityPrivilege" ascii fullword
        $s3 = "SeTakeOwnershipPrivilege" ascii fullword
        $s4 = "SeLoadDriverPrivilege" ascii fullword
        $s5 = "SeSystemProfilePrivilege" ascii fullword
        $s6 = "SeSystemtimePrivilege" ascii fullword
        $s7 = "SeProfileSingleProcessPrivilege" ascii fullword
        $s8 = "SeIncreaseBasePriorityPrivilege" ascii fullword
        $s9 = "SeCreatePagefilePrivilege" ascii fullword
        $s10 = "SeBackupPrivilege" ascii fullword
        $s11 = "SeRestorePrivilege" ascii fullword
        $s12 = "SeShutdownPrivilege" ascii fullword
        $s13 = "SeDebugPrivilege" ascii fullword
        $s14 = "SeSystemEnvironmentPrivilege" ascii fullword
        $s15 = "SeChangeNotifyPrivilege" ascii fullword
        $s16 = "SeRemoteShutdownPrivilege" ascii fullword
        $s17 = "SeUndockPrivilege" ascii fullword
        $s18 = "SeManageVolumePrivilege" ascii fullword
        $s19 = "SeImpersonatePrivilege" ascii fullword
        $s20 = "SeCreateGlobalPrivilege" ascii fullword
        $s21 = "SeIncreaseWorkingSetPrivilege" ascii fullword
        $s22 = "SeTimeZonePrivilege" ascii fullword
        $s23 = "SeCreateSymbolicLinkPrivilege" ascii fullword
    condition:
        5 of them
}

rule DLLHijacking {
  condition:
    // Check for presence of DLL_PROCESS_ATTACH in DllMain function
    uint16(0) == 0x6461 and (
      // Check for the presence of CreateThread, which is used to start the main function
      uint32(2) == 0x74006872 and uint32(6) == 0x00006563 and uint32(10) == 0x74616843 and
      
      // Check for the presence of Main function
      uint32(14) == 0x6E69006D and uint32(18) == 0x0064614D
    )
    // Check for presence of dllexport attribute
    and (pe.exports("DnsFreeConfigStructure") or pe.exports("DnsFreeConfigStructure@0"))
}

rule shadow_copy_deletion {
    meta:
      description = "Detect shadow copy deletion"
      author = "ditekSHen/Unprotect"

    strings:
        $x1 = "cmd.exe /c \"vssadmin.exe Delete Shadows /all /quiet\"" fullword ascii
        $x2 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all" ascii wide nocase
        $cmd3 = "Delete Shadows /all" ascii wide nocase
        $cmd4 = "} recoveryenabled no" ascii wide nocase
        $cmd5 = "} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii wide nocase
        $cmd8 = "resize shadowstorage /for=c: /on=c: /maxsize=" ascii wide nocase
        $cmd9 = "shadowcopy where \"ID='%s'\" delete" ascii wide nocase
        $cmd10 = "wmic.exe SHADOWCOPY /nointeractive" ascii wide nocase
        $cmd11 = "WMIC.exe shadowcopy delete" ascii wide nocase
        $cmd12 = "Win32_Shadowcopy | ForEach-Object {$_.Delete();}" ascii wide nocase
        $delr = /del \/s \/f \/q(( [A-Za-z]:\\(\*\.|[Bb]ackup))(VHD|bac|bak|wbcat|bkf)?)+/ ascii wide
        $wp1 = "delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "delete systemstatebackup" ascii wide nocase
      
    condition:
        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*)) or #delr > 4) or (4 of them)
}

