/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp6h0hkgls
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule BlueScreen {
   meta:
      description = "tmp6h0hkgls - file BlueScreen.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "14e6ac84d824c0cf6ea8ebb5b3be10f8893449474096e59ff0fd878d49d0c160"
   strings:
      $s1 = "StartBlueScreen.exe" fullword wide /* score: '22.00'*/
      $s2 = "32.dll" fullword ascii /* score: '17.00'*/
      $s3 = "!.sys" fullword ascii /* score: '12.00'*/
      $s4 = "\\\\.\\NirSoftBlueSc" fullword ascii /* score: '10.00'*/
      $s5 = "SHELL\\" fullword ascii /* score: '9.00'*/
      $s6 = "Get+@o" fullword ascii /* score: '6.00'*/
      $s7 = "\\registry\\machine\\SYST" fullword ascii /* score: '5.00'*/
      $s8 = "%Ot%:6" fullword ascii /* score: '5.00'*/
      $s9 = "LibraryA" fullword ascii /* score: '4.00'*/
      $s10 = "Yr?+sEsGi^v" fullword ascii /* score: '4.00'*/
      $s11 = "rvices\\7driv" fullword ascii /* score: '4.00'*/
      $s12 = "$qntoskrnl." fullword ascii /* score: '4.00'*/
      $s13 = "rolSet\\oo" fullword ascii /* score: '4.00'*/
      $s14 = "cify 5 |0nd-lkh" fullword ascii /* score: '4.00'*/
      $s15 = "Reques?" fullword ascii /* score: '4.00'*/
      $s16 = "athK??" fullword ascii /* score: '4.00'*/
      $s17 = "ot be run1DOS mode." fullword ascii /* score: '4.00'*/
      $s18 = "L4kObjft]" fullword ascii /* score: '4.00'*/
      $s19 = "fComp`" fullword ascii /* score: '4.00'*/
      $s20 = "sourceFin" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

