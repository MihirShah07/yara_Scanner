rule Unknown_Random {
	meta:
		author = "cyrus"
		description = "Look for Random function"
	strings:
		$c0 = { 55 8B EC 52 8B 45 08 69 15 ?? ?? ?? ?? 05 84 08 08 42 89 15 ?? ?? ?? ?? F7 E2 8B C2 5A C9 C2 04 00 }
	condition:
		$c0
}