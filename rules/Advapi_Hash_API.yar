rule Advapi_Hash_API {
	meta:
		author = "cyrus"
		description = "Looks for advapi API functions"
	strings:
		$advapi32 = "advapi32.dll" wide ascii nocase
		$CryptCreateHash = "CryptCreateHash" wide ascii
		$CryptHashData = "CryptHashData" wide ascii
		$CryptAcquireContext = "CryptAcquireContext" wide ascii
	condition:
		$advapi32 and ($CryptCreateHash and $CryptHashData and $CryptAcquireContext)
}