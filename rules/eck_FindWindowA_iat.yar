rule Check_FindWindowA_iat {

	meta:
		Author = "cyrus"
		Description = "it's checked if FindWindowA() is imported"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"

	strings:
		$ollydbg = "OLLYDBG"
		$windbg = "WinDbgFrameClass"

	condition:
		pe.imports("user32.dll","FindWindowA") and ($ollydbg or $windbg)
}