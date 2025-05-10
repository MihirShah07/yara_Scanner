rule antisb_threatExpert {
    meta:
        Author = "cyrus"
        description = "Anti-Sandbox checks for ThreatExpert"
	version = "0.1"
    strings:
        $f1 = "dbghelp.dll" nocase
    condition:
        all of them
}
