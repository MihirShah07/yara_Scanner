/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpd3nc69p7
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Blaster_A {
   meta:
      description = "tmpd3nc69p7 - file Blaster.A.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "258f82166d20c68497a66d82349fc81899fde8fe8c1cc66e59f739a9ea2c95a9"
   strings:
      $s1 = "CRTDLL.DLL" fullword ascii /* score: '23.00'*/
      $s2 = "msblast.exe" fullword ascii /* score: '22.00'*/
      $s3 = "ExitProcessK" fullword ascii /* score: '15.00'*/
      $s4 = "GetComm" fullword ascii /* score: '12.00'*/
      $s5 = "lRegeKey" fullword ascii /* score: '7.00'*/
      $s6 = "Tickeunt" fullword ascii /* score: '6.00'*/
      $s7 = "gates&h" fullword ascii /* score: '4.00'*/
      $s8 = " fix2r]oftireU" fullword ascii /* score: '4.00'*/
      $s9 = "prQX{0wtf" fullword ascii /* score: '4.00'*/
      $s10 = "to say LOVE YOU SAN!!" fullword ascii /* score: '4.00'*/
      $s11 = "wNtwsupd" fullword ascii /* score: '4.00'*/
      $s12 = "SvValue" fullword ascii /* score: '4.00'*/
      $s13 = "\\.A|IGY\\" fullword ascii /* score: '2.00'*/
      $s14 = ";!`0!@" fullword ascii /* score: '1.00'*/
      $s15 = "d%you make" fullword ascii /* score: '1.00'*/
      $s16 = "4,8@HT" fullword ascii /* score: '1.00'*/
      $s17 = "one-Wd" fullword ascii /* score: '1.00'*/
      $s18 = "=W}$h>" fullword ascii /* score: '1.00'*/
      $s19 = "t(x1%Sr" fullword ascii /* score: '1.00'*/
      $s20 = "possiQ" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      8 of them
}

