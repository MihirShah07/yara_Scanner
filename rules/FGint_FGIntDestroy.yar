rule FGint_FGIntDestroy
{	meta:
		author = "cyrus"
		description = "FGint FGIntDestroy"
	strings:
		$c0 = { 53 8B D8 8D 43 04 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 5B C3 }
	condition:
		$c0
}