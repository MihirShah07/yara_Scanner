rule Big_Numbers5
{
	meta:
		author = "cyrus"
		description = "Looks for big numbers 256:sized"
	strings:
        	$c0 = /[0-9a-fA-F]{256}/ fullword wide ascii
	condition:
		$c0
}