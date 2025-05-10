rule Crypt32_CryptBinaryToString_API {
	meta:
		author = "cyrus"
		description = "Looks for crypt32 CryptBinaryToStringA function"
	strings:
		$crypt32 = "crypt32.dll" wide ascii nocase
		$CryptBinaryToStringA = "CryptBinaryToStringA" wide ascii
	condition:
		$crypt32 and ($CryptBinaryToStringA)
}