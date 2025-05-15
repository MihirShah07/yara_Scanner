/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1voe7mob
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp1voe7mob_Nyxem_E {
   meta:
      description = "tmp1voe7mob - file Nyxem.E.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "62f8364c46300bce2e75c4cc65039de3f060b854764dd90f0fa656efaf31bea9"
   strings:
      $s1 = "C:\\WINNT\\SYSTEM32\\MSVBVM60.DLL\\3" fullword ascii /* score: '30.00'*/
      $s2 = "\\c$\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\WinZip Quick Pick.exe" fullword wide /* score: '27.00'*/
      $s3 = "\\Rundll16.exe" fullword wide /* score: '24.00'*/
      $s4 = "\\BearShare\\*.dll" fullword wide /* score: '24.00'*/
      $s5 = "\\c$\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\WinZip Quick Pick.lnk" fullword wide /* score: '23.00'*/
      $s6 = "PCClient.exe" fullword wide /* score: '22.00'*/
      $s7 = "PCCIOMON.exe" fullword wide /* score: '22.00'*/
      $s8 = "pccguide.exe" fullword wide /* score: '22.00'*/
      $s9 = "Pop3trap.exe" fullword wide /* score: '22.00'*/
      $s10 = "PCCClient.exe" fullword wide /* score: '22.00'*/
      $s11 = "Avgserv9.exe" fullword wide /* score: '22.00'*/
      $s12 = "\\TREND MICRO\\OfficeScan\\*.dll" fullword wide /* score: '22.00'*/
      $s13 = "movies.exe" fullword wide /* score: '22.00'*/
      $s14 = "C:\\WINNT\\SYSTEM32\\MSWINSCK.OCX" fullword ascii /* score: '21.00'*/
      $s15 = "\\HyperTechnologies\\Deep Freeze\\*.exe" fullword wide /* score: '21.00'*/
      $s16 = "ns1.hotmail.com" fullword wide /* score: '21.00'*/
      $s17 = "ns1.yahoo.com" fullword wide /* score: '21.00'*/
      $s18 = "HOTMAIL.COM" fullword wide /* score: '21.00'*/
      $s19 = "\\Morpheus\\*.dll" fullword wide /* score: '21.00'*/
      $s20 = "\\Grisoft\\AVG7\\*.dll" fullword wide /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

