/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp595lkbs9
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Launcher {
   meta:
      description = "tmp595lkbs9 - file Launcher.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "d5b962dfe37671b5134f0b741a662610b568c2b5374010ee92b5b7857d87872c"
   strings:
      $s1 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s2 = "support@rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "LAUNCHER.EXE {Program/WAV to launch} {every x minutes to launch}" fullword wide /* score: '14.00'*/
      $s4 = "CFgJ.sbaft" fullword ascii /* score: '7.00'*/
      $s5 = "TFRMCOPYRIGHT" fullword wide /* score: '6.50'*/
      $s6 = "XYayhN1" fullword ascii /* score: '5.00'*/
      $s7 = "BX* f@" fullword ascii /* score: '5.00'*/
      $s8 = "+ NpIG" fullword ascii /* score: '5.00'*/
      $s9 = "h5>+ u" fullword ascii /* score: '5.00'*/
      $s10 = "PZGn${U" fullword ascii /* score: '4.00'*/
      $s11 = "@.NyFN]be)$" fullword ascii /* score: '4.00'*/
      $s12 = "%eggU*G;" fullword ascii /* score: '4.00'*/
      $s13 = "(ZD)bqED?" fullword ascii /* score: '4.00'*/
      $s14 = "LTNO5)m" fullword ascii /* score: '4.00'*/
      $s15 = "{vQZQ^v5zS'wS6i" fullword ascii /* score: '4.00'*/
      $s16 = "LfTs']]'" fullword ascii /* score: '4.00'*/
      $s17 = "]A_bNro6cS" fullword ascii /* score: '4.00'*/
      $s18 = "ocos/UP" fullword ascii /* score: '4.00'*/
      $s19 = "9_JHeDl(%" fullword ascii /* score: '4.00'*/
      $s20 = "zrvRZf5A" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

