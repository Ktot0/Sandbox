import "pe"

rule Detect_SuspendThread: AntiDebug {
    meta: 
        description = "Detect SuspendThread as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "SuspendThread" fullword ascii
        $2 = "NtSuspendThread" fullword ascii
        $3 = "OpenThread" fullword ascii
        $4 ="SetThreadContext" fullword ascii
        $5 ="SetInformationThread" fullword ascii
        $x1 ="CreateToolHelp32Snapshot" fullword ascii
        $x2 ="EnumWindows" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $x1 and 2 of them 
}

rule Detect_GuardPages: AntiDebug {
    meta: 
        description = "Detect Guard Pages as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "GetSystemInfo" fullword ascii
        $2 = "VirtualAlloc" fullword ascii
        $3 = "RtlFillMemory" fullword ascii
        $4 ="VirtualProtect" fullword ascii
        $5 ="VirtualFree" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and 4 of them 
}

rule Detect_SetDebugFilterState: AntiDebug {
    meta: 
        description = "Detect SetDebugFilterState as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtSetDebugFilterState" fullword ascii
        $2 = "DbgSetDebugFilterState" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them 
}

rule Detect_OllyDBG_BadFormatTrick: AntiDebug {
    meta: 
        description = "Detect bad format not handled by Ollydbg"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "%s%s.exe" fullword ascii
    condition:   
       $1
}


rule AntiDebugging_Interrupt {
  condition:
    // Check for presence of __try and __except blocks
    uint32(0) == 0x00646120 and uint32(4) == 0x00646120 and
    // Check for presence of __debugbreak or interrupt instructions such as INT 3 or UD2
    (uint8(8) == 0xCC or uint8(8) == 0xF1 or uint8(8) == 0xCC)
}

rule Detect_EnumProcess: AntiDebug {
    meta: 
        description = "Detect EnumProcessas anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "EnumProcessModulesEx" fullword ascii
        $2 = "EnumProcesses" fullword ascii
        $3 = "EnumProcessModules" fullword ascii
    condition:   
        uint16(0) == 0x5A4D and filesize < 1000KB and any of them 
}

rule DebuggerCheck__GlobalFlags  {
    meta:
	description = "Rule to detect NtGlobalFlags debugger check"
        author = "Thibault Seret"
        date = "2020-09-26"
    strings:
        $s1 = "NtGlobalFlags"
    condition:
        any of them
}

rule Detect_CloseHandle: AntiDebug {
    meta: 
        description = "Detect CloseHandle as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtClose" fullword ascii
        $2 = "CloseHandle" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}

rule Detect_CsrGetProcessID: AntiDebug {
    meta: 
        description = "Detect CsrGetProcessID as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "CsrGetProcessID" fullword ascii
        $2 = "GetModuleHandle" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and 2 of them 
}

rule Detect_EventPairHandles: AntiDebug {
    meta: 
        description = "Detect EventPairHandlesas anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "EventPairHandles" fullword ascii
        $2 = "RtlCreateQueryDebugBuffer" fullword ascii
        $3 = "RtlQueryProcessHeapInformation" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and 2 of them 
}

rule Detect_OutputDebugStringA_iat: AntiDebug
{
	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "Detect in IAT OutputDebugstringA"
		Date = "20/04/2015"

	condition:
		pe.imports("kernel32.dll","OutputDebugStringA")
}

rule Detect_NtQueryObject: AntiDebug {
    meta: 
        description = "Detect NtQueryObject as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtQueryObject" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule Detect_NtSetInformationThread: AntiDebug {
    meta: 
        description = "Detect NtSetInformationThread as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtSetInformationThread" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule Detect_NtQueryInformationProcess: AntiDebug {
    meta: 
        description = "Detect NtQueryInformationProcess as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "NtQueryInformationProcess" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule Detect_IsDebuggerPresent : AntiDebug {
    meta:
        author = "naxonez"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
	$ ="IsDebugged"
    condition:
        uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}

rule detect_tlscallback {
    meta:
        description = "Simple rule to detect tls callback as anti-debug."
        author = "Thomas Roccia | @fr0gger_"
    strings:
        $str1 = "TLS_CALLBACK" nocase
        $str2 = "TLScallback" nocase
    condition:
        uint32(uint32(0x3C)) == 0x4550 and any of them
}

rule Detect_LocalSize: AntiDebug {
    meta: 
        description = "Detect LocalSize as anti-debug"
        author = "Unprotect"
        comment = "Experimental rule"
    strings:
        $1 = "LocalSize" fullword ascii
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and $1
}

rule Detect_Interrupt: AntiDebug {
    meta: 
        description = "Detect Interrupt instruction"
        author = "Unprotect"
        comment = "Experimental rule / the rule can be slow to use"
    strings:
        $int3 = { CC }
        $intCD = { CD }
        $int03 = { 03 }
        $int2D = { 2D }
        $ICE = { F1 }
    condition:   
       uint16(0) == 0x5A4D and filesize < 1000KB and any of them
}

