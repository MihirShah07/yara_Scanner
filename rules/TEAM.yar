rule TEAN {
	meta:
		author = "cyrus"
		description = "Look for TEA Encryption"
	strings:
		$c0 = { 2037EFC6 }
	condition:
		$c0
}