/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpu11lf3ye
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpu11lf3ye_Lacon {
   meta:
      description = "tmpu11lf3ye - file Lacon.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "9b3f73a12a793d1648f3209e1e3f10bbb548b1ec21d53b8ac060b7b95ae4ef1f"
   strings:
      $s1 = "VKVBA6.DLL" fullword ascii /* score: '23.00'*/
      $s2 = "NoCall.exe" fullword wide /* score: '18.00'*/
      $s3 = "C:\\Program Fixs\\Mi" fullword ascii /* score: '10.00'*/
      $s4 = "shlwapi.dKPatht" fullword ascii /* score: '7.00'*/
      $s5 = "DllFunc" fullword ascii /* score: '5.00'*/
      $s6 = "_\"~__vba$EachVar" fullword ascii /* score: '4.00'*/
      $s7 = "soft Visu" fullword ascii /* score: '4.00'*/
      $s8 = "RedimgAn[" fullword ascii /* score: '4.00'*/
      $s9 = "mghdPbddg" fullword ascii /* score: '4.00'*/
      $s10 = "OLateMemI" fullword ascii /* score: '4.00'*/
      $s11 = "_CIcosadj_fptan" fullword ascii /* score: '4.00'*/
      $s12 = "VwsSwY?" fullword ascii /* score: '4.00'*/
      $s13 = "Jdiv_]XE" fullword ascii /* score: '4.00'*/
      $s14 = "tion  Installer" fullword ascii /* score: '4.00'*/
      $s15 = "sExitWi'" fullword ascii /* score: '4.00'*/
      $s16 = "reeObjL" fullword ascii /* score: '4.00'*/
      $s17 = "OAryUnlock" fullword ascii /* score: '4.00'*/
      $s18 = "EVENT_SINK_" fullword ascii /* score: '4.00'*/
      $s19 = "ddddP4" fullword ascii /* score: '2.00'*/
      $s20 = "\\`2222" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}

