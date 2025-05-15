/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpfy1jjjjz
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpfy1jjjjz_Vobus {
   meta:
      description = "tmpfy1jjjjz - file Vobus.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "ef12832d67a099282b6aad1bf2858375dd4b53c67638daf12a253bc9f918b77f"
   strings:
      $s1 = "qsfy6P.exe" fullword wide /* score: '22.00'*/
      $s2 = "FC:\\Windows\\system32\\stdole2.tlb" fullword ascii /* score: '21.00'*/
      $s3 = "C:\\Windows\\system32\\MSMASK32.oca" fullword ascii /* score: '17.00'*/
      $s4 = "dd-mm-yyyy" fullword wide /* reversed goodware string 'yyyy-mm-dd' */ /* score: '14.00'*/
      $s5 = "Printemps,Et" fullword wide /* score: '11.00'*/
      $s6 = "MSMASK32.OCX" fullword ascii /* score: '10.00'*/
      $s7 = "Returns/sets the foreground color used to display header-cells." fullword ascii /* score: '9.00'*/
      $s8 = "GetMoonPhaseExact" fullword ascii /* score: '9.00'*/
      $s9 = "GetMoonPhaseDetail" fullword ascii /* score: '9.00'*/
      $s10 = "23&>@\"56" fullword ascii /* score: '9.00'*/ /* hex encoded string '#V' */
      $s11 = "CellSelectHeaderForeColor" fullword wide /* score: '9.00'*/
      $s12 = "+7*972+,7E" fullword ascii /* score: '9.00'*/ /* hex encoded string 'yr~' */
      $s13 = "\"\"&>@*33" fullword ascii /* score: '9.00'*/ /* hex encoded string '3' */
      $s14 = "*33!67&++#++" fullword ascii /* score: '9.00'*/ /* hex encoded string '3g' */
      $s15 = "NewCellHeaderStyle" fullword ascii /* score: '9.00'*/
      $s16 = "GetZodiacInfo" fullword ascii /* score: '9.00'*/
      $s17 = "NewLanguageText" fullword ascii /* score: '9.00'*/
      $s18 = "CellHeaderStyle" fullword wide /* score: '9.00'*/
      $s19 = "GetQuarterInfo" fullword ascii /* score: '9.00'*/
      $s20 = "GetMoonPhaseInfo" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

