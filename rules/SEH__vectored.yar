rule SEH__vectored : AntiDebug SEH {
	meta:
		weight = 1
		Author = "cyrus"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"
	condition:
		any of them
}