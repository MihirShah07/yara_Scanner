rule Big_Numbers3
{
	meta:
		author = "cyrus"
		description = "Looks for big numbers 64:sized"
	strings:
        	$c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
	condition:
		$c0
}