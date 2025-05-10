rule disable_uax {
    meta:
        Author = "cyrus"
        description = "Disable User Access Control"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}