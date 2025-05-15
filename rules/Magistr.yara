/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpb74jnwxb
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpb74jnwxb_Magistr {
   meta:
      description = "tmpb74jnwxb - file Magistr.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "068f2ee28af7645dbf2a1684f0a5fc5ccb6aa1027f71da4468e0cba56c65e058"
   strings:
      $s1 = "%s32%d%d.dll" fullword ascii /* score: '24.00'*/
      $s2 = "UPGRDHLP.EXE" fullword wide /* score: '22.00'*/
      $s3 = "CleanupResourceLoader" fullword ascii /* score: '13.00'*/
      $s4 = "dllacces.cpp" fullword ascii /* score: '10.00'*/
      $s5 = "oYour computer has to be restarted to finish the %s components setup." fullword wide /* score: '10.00'*/
      $s6 = "SetDLLAccessPath" fullword ascii /* score: '9.00'*/
      $s7 = "pnrscmgr" fullword ascii /* score: '8.00'*/
      $s8 = "DLL already open" fullword ascii /* score: '7.00'*/
      $s9 = "RealShared" fullword ascii /* score: '7.00'*/
      $s10 = "UPGRDHLP" fullword wide /* score: '6.50'*/
      $s11 = "19H%YS%>" fullword ascii /* score: '5.00'*/
      $s12 = "\\Preferences" fullword ascii /* score: '5.00'*/
      $s13 = "DT_Common" fullword ascii /* score: '4.00'*/
      $s14 = "Symbol not found" fullword ascii /* score: '4.00'*/
      $s15 = "PNCreateInstance" fullword ascii /* score: '4.00'*/
      $s16 = "UpgrdHlpSatellite" fullword ascii /* score: '4.00'*/
      $s17 = "RMACreateInstance" fullword ascii /* score: '4.00'*/
      $s18 = "PN Upgrade Helper" fullword ascii /* score: '4.00'*/
      $s19 = "SVWh\\^A" fullword ascii /* score: '4.00'*/
      $s20 = "QRPh0#A" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

