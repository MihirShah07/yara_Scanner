rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
		Author = "cyrus"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}