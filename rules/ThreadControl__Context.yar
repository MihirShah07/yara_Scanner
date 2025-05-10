rule ThreadControl__Context : AntiDebug ThreadControl {
	meta:
		weight = 1
		Author = "cyrus"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetThreadContext"
	condition:
		any of them
}
