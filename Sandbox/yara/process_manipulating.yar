import "pe"

rule HookInjection {
  condition:
    (
      // SetWindowsHookEx is often used to install hooks
      (uint32(0) == 0x00EC8B55 and (pe.exports("SetWindowsHookExA") or pe.exports("SetWindowsHookExW")))
      
      // UnhookWindowsHookEx is often used to remove hooks
      or (uint32(0) == 0x00EC8B55 and (pe.exports("UnhookWindowsHookEx")))
      
      // A hook function often calls CallNextHookEx
      or (uint32(0) == 0x00EC8B55 and (pe.exports("CallNextHookEx")))
    )
}

rule DLLProxying {
  condition:
    // Check for presence of DLL_PROCESS_ATTACH in DllMain function
    uint16(0) == 0x6461 and (
      // Check for the presence of LoadLibrary, which is used to load the legitimate DLL
      uint32(2) == 0x6C6C6100 and uint32(6) == 0x6574726F and
      
      // Check for the presence of GetProcAddress, which is used to retrieve the addresses of the functions in the legitimate DLL
      uint32(10) == 0x72630067 and uint32(14) == 0x61647079 and uint32(18) == 0x61636F00 and uint32(22) == 0x0072696E and
      
      // Check for the presence of a function that will be used to redirect function calls to the legitimate DLL
      // This example uses a function named "ProxyFunction", but the function name can be anything
      uint32(26) == 0x646E6900 and uint32(30) == 0x00667379
    )
    // Check for presence of dllexport attribute on the function that redirects calls to the legitimate DLL
    // This example uses a function named "ProxyFunction", but the function name can be anything
    and (pe.exports("ProxyFunction") or pe.exports("ProxyFunction@0"))
}

rule ModifyDLLExportName {
  strings:
    $map_and_load = "MapAndLoad"
    $entry_to_data = "ImageDirectoryEntryToData"
    $rva_to_va = "ImageRvaToVa"
    $modify = "ModifyDLLExportName"
    $virtual_protect = "VirtualProtect"
    $virtual_alloc = "VirtualAlloc"
  condition:
    all of them
}

