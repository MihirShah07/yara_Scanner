rule FGint_ECAddPoints
{	meta:
		author = "cyrus"
		description = "FGint ECAddPoints"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 A8 53 56 57 8B 75 0C 8D 7D F0 A5 A5 8B F1 8D 7D F8 A5 A5 8B F2 8D 7D A8 A5 A5 A5 A5 A5 8B F0 8D 7D BC A5 A5 A5 A5 A5 8B 5D 08 8D 45 BC 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 A8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 F0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E8 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 E0 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 45 D8 8B 15 ?? ?? ?? ?? E8 }
	condition:
		$c0
}