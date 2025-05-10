rule Chacha_128_constant {
    meta:
		author = "spelissier"
		description = "Look for 128-bit key Chacha stream cipher constant"
		reference = "https://www.ecrypt.eu.org/stream/salsa20pf.html"
	strings:
		$c0 = "expand 16-byte k"
	condition:
		$c0
}