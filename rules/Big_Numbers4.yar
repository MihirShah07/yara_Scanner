rule Big_Numbers4
{
	meta:
		author = "cyrus"
		description = "Looks for big numbers 128:sized"
	strings:
        	$c0 = /[0-9a-fA-F]{128}/ fullword wide ascii
	condition:
		$c0
}