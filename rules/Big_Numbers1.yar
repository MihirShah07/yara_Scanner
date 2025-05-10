rule Big_Numbers1
{
	meta:
		author = "cyrus"
		description = "Looks for big numbers 32:sized"
	strings:
		$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
	condition:
		$c0
}