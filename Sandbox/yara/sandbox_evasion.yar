rule MalwareNameEvasion
{
    strings:
        // Check for the GetModuleFileName() function call
        $get_module_filename = "GetModuleFileName"

        // Check for the find_last_of() method call
        $find_last_of = "find_last_of"

        // Check for the std::string data type
        $string = "std::string"

        // Check for the "\\/" string
        $backslash_slash = "\\\\/"

        // Check for the "sample.exe" string
        $sample_exe = "sample.exe"

        // Check for the "malware.exe" string
        $malware_exe = "malware.exe"

    condition:
        // Check if all the required strings are present in the code
        all of them
}

rule check_installed_software {

  meta:
    author = "RussianPanda"
    date = "1/14/2024"
    reference = "https://unprotect.it/technique/checking-installed-software/"
    hash = "db44d4cd1ea8142790a6b26880b41ee23de5db5c2a63afb9ee54585882f1aa07"

  strings:
    $d1 = "DisplayVersion"
    $u1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    $reg = "RegOpenKeyExA"
    $h = {68 (01|02) 00 00 80}

  condition:
    uint16(0) == 0x5A4D
    and for any i in (1..#u1) : ($d1 in (@u1[i] - 200..@u1[i] + 200))
    and $reg and $h

}

rule Qemu_Detection
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Checks for QEMU Registry Key"
	strings:
		$desc1 = "HARDWARE\\Description\\System" nocase wide ascii
		$desc2 = "SystemBiosVersion" nocase wide ascii
		$desc3 = "QEMU" wide nocase ascii

		$dev1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$dev2 = "Identifier" nocase wide ascii
		$dev3 = "QEMU" wide nocase ascii
	condition:
		any of ($desc*) or any of ($dev*)
}

rule VBox_Detection
{
	meta:
		Author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
		Description = "Checks for VBOX Registry Key"
	strings:
		$desc1 = "HARDWARE\\Description\\System" nocase wide ascii
		$desc2 = "SystemBiosVersion" nocase wide ascii
		$desc3 = "VideoBiosVersion" nocase wide ascii

		$data1 = "VBOX" nocase wide ascii
		$data2 = "VIRTUALBOX" nocase wide ascii
		
		$dev1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$dev2 = "Identifier" nocase wide ascii
		$dev3 = "VBOX" nocase wide ascii

		$soft1 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
		$soft2 = "HARDWARE\\ACPI\\DSDT\\VBOX__"
		$soft3 = "HARDWARE\\ACPI\\FADT\\VBOX__"
		$soft4 = "HARDWARE\\ACPI\\RSDT\\VBOX__"
		$soft5 = "SYSTEM\\ControlSet001\\Services\\VBoxGuest"
		$soft6 = "SYSTEM\\ControlSet001\\Services\\VBoxService"
		$soft7 = "SYSTEM\\ControlSet001\\Services\\VBoxMouse"
		$soft8 = "SYSTEM\\ControlSet001\\Services\\VBoxVideo"

		$virtualbox1 = "VBoxHook.dll" nocase
	        $virtualbox2 = "VBoxService" nocase
        	$virtualbox3 = "VBoxTray" nocase
        	$virtualbox4 = "VBoxMouse" nocase
        	$virtualbox5 = "VBoxGuest" nocase
        	$virtualbox6 = "VBoxSF" nocase
        	$virtualbox7 = "VBoxGuestAdditions" nocase
        	$virtualbox8 = "VBOX HARDDISK"  nocase
        	$virtualbox9 = "VBoxVideo" nocase
		$virtualbox10 = "vboxhook" nocase
		$virtualbox11 = "vboxmrxnp" nocase
		$virtualbox12 = "vboxogl" nocase
		$virtualbox13 = "vboxoglarrayspu" nocase
		$virtualbox14 = "vboxoglcrutil"
		$virtualbox15 = "vboxoglerrorspu" nocase
		$virtualbox16 = "vboxoglfeedbackspu" nocase
		$virtualbox17 = "vboxoglpackspu" nocase
		$virtualbox18 = "vboxoglpassthroughspu" nocase
		$virtualbox19 = "vboxcontrol" nocase

        	// VirtualBox Mac Address
        	$virtualbox_mac_1a = "08-00-27"
        	$virtualbox_mac_1b = "08:00:27"
        	$virtualbox_mac_1c = "080027"	
	condition:
		any of ($desc*) and 
		1 of ($data*) or 
		any of ($dev*) or 
		any of ($soft*) or
		any of ($virtualbox*)
}

rule BuildCommDCBAndTimeouts 
{
    meta:
        author = "Unprotect"
        contributors = "Huntress Research Team | Unprotect Project"
        description = "Detects usage of BuildCommDCBAndTimeouts function call"
        status = "experimental"

    strings:
        $s1 = "jhl46745fghb" ascii wide nocase
        $s2 = "BuildCommDCBAndTimeouts" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and ($s2 or ($s2 and $s1))
}

rule HDDInfo_rule
{
	meta:
		description = "Detect DeviceIoControl call with Io Control Code  SMART_RCV_DRIVE_DATA (0x7C088)"
		author = "Nicola Bottura"
		date = "2024-02-17"
		reference = "https://nicolabottura.github.io/HDDInfo-Evasion-PoC.html"
		hash = "aa202ae4d12e03887bb81c3a9129f44c464f54c790990494885d29bcde0ef4c1"
	strings:
		$api = "DeviceIoControl" nocase wide ascii
		$ioctl = { 88 C0 07 }

	condition:
		all of ($*)
}

rule YARA_Detect_WindowsDefender_AVEmulator
{
    meta:
        description = "Goat files inside Defender AV Emulator's file system. Often used in PE malware as an evasion technique to evade executing in Windows Defender's AV Emulator."
        author = "@albertzsigovits"
        date = "2024-07-10"
        reference = "https://media.defcon.org/DEF%20CON%2026/DEF%20CON%2026%20presentations/Alexei-Bulazel-Reverse-Engineering-Windows-Defender-Updated.pdf"
        sha256 = "eb80da614515ff14b3fc312bef38b0d765ce3f4356db5b7b301a3b7c47f7c311"

    strings:
        $ = "\\INTERNAL\\__empty" ascii wide
        $ = "myapp.exe" ascii wide
        $ = "aaa_TouchMeNot_.txt" ascii wide
    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and 2 of them
}