rule check_patchlevel {
    meta:
        Author = "cyrus"
        description = "Check if hotfix are applied"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}