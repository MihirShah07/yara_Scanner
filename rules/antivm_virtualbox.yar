rule antivm_virtualbox {
    meta:
        Author = "cyrus"
        description = "AntiVM checks for VirtualBox"
	version = "0.1"
    strings:
        $s1 = "VBoxService.exe" nocase
    condition:
        any of them
}