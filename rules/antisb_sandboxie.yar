rule antisb_sandboxie {
    meta:
        Author = "cyrus"
        description = "Anti-Sandbox checks for Sandboxie"
	version = "0.1"
    strings:
        $f1 = "SbieDLL.dll" nocase
    condition:
        all of them
}
