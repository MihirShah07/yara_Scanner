/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpsp4fbnw1
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpsp4fbnw1_RedBoot {
   meta:
      description = "tmpsp4fbnw1 - file RedBoot.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1001a8c7f33185217e6e1bdbb8dba9780d475da944684fb4bf1fc04809525887"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "kernel32.dllD" fullword ascii /* score: '16.00'*/
      $s3 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s4 = "GetNativeSystemInf" fullword ascii /* score: '12.00'*/
      $s5 = "opera?" fullword ascii /* score: '9.00'*/
      $s6 = "gwpkdai" fullword ascii /* score: '8.00'*/
      $s7 = "alnumsci" fullword ascii /* score: '8.00'*/
      $s8 = "+qRUN$KI2HENnHPY" fullword ascii /* score: '7.00'*/
      $s9 = "YYYY?2" fullword ascii /* score: '7.00'*/
      $s10 = "ALWFGRP" fullword ascii /* score: '6.50'*/
      $s11 = "VWHYYBY" fullword ascii /* score: '6.50'*/
      $s12 = "DOMMIVFAIT" fullword ascii /* score: '6.50'*/
      $s13 = "3.3.14.2" fullword wide /* score: '6.00'*/
      $s14 = "uK+ @Gg" fullword ascii /* score: '5.00'*/
      $s15 = "nphski" fullword ascii /* score: '5.00'*/
      $s16 = "GDEFGHIJKLMN6" fullword ascii /* score: '5.00'*/
      $s17 = "EY|!+ " fullword ascii /* score: '5.00'*/
      $s18 = "S%saMUc%" fullword ascii /* score: '5.00'*/
      $s19 = "cntrlv" fullword ascii /* score: '5.00'*/
      $s20 = "=PR%V%" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

