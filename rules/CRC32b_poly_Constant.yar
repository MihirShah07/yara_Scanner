rule CRC32b_poly_Constant {
	meta:
		author = "cyrus"
		description = "Look for CRC32b [poly]"
		version = "0.1"
	strings:
		$c0 = { B71DC104 }
	condition:
		$c0
}
