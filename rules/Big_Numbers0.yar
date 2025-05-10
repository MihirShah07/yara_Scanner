rule Big_Numbers0
{
	meta:
		author = "cyrus"
		description = "Looks for big numbers 20:sized"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}