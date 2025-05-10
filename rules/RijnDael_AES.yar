rule RijnDael_AES
{	meta:
		author = "cyrus"
		description = "RijnDael AES"
	strings:
		$c0 = { A5 63 63 C6 84 7C 7C F8 }
	condition:
		$c0
}