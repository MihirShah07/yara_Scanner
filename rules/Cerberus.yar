import "pe"

rule Cerberus : RAT memory
{
	meta:
		description = "Cerberus"
		filetype = "memory"
		version = "1.0" 

	strings:
		$checkin = "Ypmw1Syv023QZD"
		$clientpong = "wZ2pla"
		$serverping = "wBmpf3Pb7RJe"
		$generic = "cerberus" nocase

	condition:
		any of them
}
