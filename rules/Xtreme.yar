import "pe"

rule Xtreme
{
    meta:
        description = "Xtreme RAT"
	author = "botherder https://github.com/botherder"

    strings:
        $string1 = /(X)tremeKeylogger/ wide ascii
        $string2 = /(X)tremeRAT/ wide ascii
        $string3 = /(X)TREMEUPDATE/ wide ascii
        $string4 = /(S)TUBXTREMEINJECTED/ wide ascii

        $unit1 = /(U)nitConfigs/ wide ascii
        $unit2 = /(U)nitGetServer/ wide ascii
        $unit3 = /(U)nitKeylogger/ wide ascii
        $unit4 = /(U)nitCryptString/ wide ascii
        $unit5 = /(U)nitInstallServer/ wide ascii
        $unit6 = /(U)nitInjectServer/ wide ascii
        $unit7 = /(U)nitBinder/ wide ascii
        $unit8 = /(U)nitInjectProcess/ wide ascii

    condition:
        5 of them
}






rule XtremeRAT : Family
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        XtremeRATCode or XtremeRATStrings
}

rule xtremrat : rat
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Xtrem RAT v3.5"
		date = "2012-07-12" 
		version = "1.0" 
		filetype = "memory"

	strings:
		$a = "XTREME" wide
		$b = "XTREMEBINDER" wide
		$c = "STARTSERVERBUFFER" wide
		$d = "SOFTWARE\\XtremeRAT" wide
		$e = "XTREMEUPDATE" wide
		$f = "XtremeKeylogger" wide
		$g = "myversion|3.5" wide
		$h = "xtreme rat" wide nocase
	condition:
		2 of them
}

rule xtreme_rat_0
{ 
	meta:
		maltype = "Xtreme RAT"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="5156"
		$data="windows\\system32\\sethc.exe"

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\Microsoft Word.exe"
	condition:
		all of them
}

rule xtreme_rat_1
{ 
	meta:
		maltype = "Xtreme RAT"
		ref = "https://github.com/reed1713"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/xtreme-rat-targets-israeli-government/"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="5156"
		$data="windows\\system32\\sethc.exe"

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\Microsoft Word.exe"
	condition:
		all of them
}
