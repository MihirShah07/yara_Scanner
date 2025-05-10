rule CRC32c_poly_Constant {
	meta:
		author = "cyrus"
		description = "Look for CRC32c (Castagnoli) [poly]"
	strings:
		$c0 = { 783BF682 }
	condition:
		$c0
}