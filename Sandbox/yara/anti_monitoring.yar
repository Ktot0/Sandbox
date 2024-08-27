import "pe"

rule UNPROTECT_disable_process {
    meta:
	author = "Thomas Roccia | @fr0gger_"
	description = "Disable blacklisted processes"
    strings:
        $api1 = "CreateToolhelp32Snapshot" nocase
        $api2 = "Process32First" nocase
        $api3 = "Process32Next" nocase
        $api4 = "TerminateProcess" nocase
        $api5 = "NtGetNextProcess" nocase
        $p1 = "taskkill.exe" nocase
        $p2 = "tskill.exe" nocase
    condition:
        uint32(uint32(0x3C)) == 0x4550 and 2 of ($api*) or any of ($p*) 
}

rule ParentProcessEvasion
{
    strings:
        // Check for the CreateToolhelp32Snapshot() function call
        $create_snapshot = "CreateToolhelp32Snapshot"

        // Check for the Process32First() function call
        $process32_first = "Process32First"

        // Check for the Process32Next() function call
        $process32_next = "Process32Next"

        // Check for the GetCurrentProcessId() function call
        $get_current_pid = "GetCurrentProcessId"

    condition:
        // Check if all the required strings are present in the code
        all of them
}

rule SysmonEvasion
{
    strings:
        // Check for the LoadLibrary() function call
        $load_library = "LoadLibrary"

        // Check for the GetProcAddress() function call
        $get_proc_address = "GetProcAddress"

        // Check for the Unload() function call
        $unload = "Unload"

        // Check for the sysmondrv string
        $sysmondrv = "sysmondrv"

    condition:
        // Check if all the required strings are present in the code
        all of them
}


