rule dragos_crashoverride_suspcious {
	meta:
		description = "CRASHOVERRIDE v1 Wiper"
		author = "cyrus"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"
	strings:
		$s0 = "SYS_BASCON.COM" fullword nocase wide
		$s1 = ".pcmp" fullword nocase wide
		$s2 = ".pcmi" fullword nocase wide
		$s3 = ".pcmt" fullword nocase wide
		$s4 = ".cin" fullword nocase wide
	condition:
		pe.exports("Crash") and any of ($s*)
}
