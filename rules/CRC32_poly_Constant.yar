
rule CRC32_poly_Constant {
	meta:
		author = "cyrus"
		description = "Look for CRC32 [poly]"
		version = "0.1"
	strings:
		$c0 = { 2083B8ED }
	condition:
		$c0
}