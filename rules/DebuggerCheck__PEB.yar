rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "cyrus"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}
