/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpn6fnvyjk
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpn6fnvyjk_Time {
   meta:
      description = "tmpn6fnvyjk - file Time.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "dc476ae39effdd80399b6e36f1fde92c216a5bbdb6b8b2a7ecbe753e91e4c993"
   strings:
      $s1 = "traveler.exe" fullword wide /* score: '22.00'*/
      $s2 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "support@rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s4 = "traveler" fullword wide /* score: '8.00'*/
      $s5 = "TFRMCOPYRIGHT" fullword wide /* score: '6.50'*/
      $s6 = "TFRMSPLASH" fullword wide /* score: '6.50'*/
      $s7 = "K* :5%" fullword ascii /* score: '5.00'*/
      $s8 = "PclREVt" fullword ascii /* score: '4.00'*/
      $s9 = "arqHcbq" fullword ascii /* score: '4.00'*/
      $s10 = "xUtse+e" fullword ascii /* score: '4.00'*/
      $s11 = "bfvjU[1J\\+" fullword ascii /* score: '4.00'*/
      $s12 = "pRhPlFZc" fullword ascii /* score: '4.00'*/
      $s13 = ":VfWWXkvBW" fullword ascii /* score: '4.00'*/
      $s14 = "+9.DIk" fullword ascii /* score: '4.00'*/
      $s15 = "re;DBd$6b$m.OrJ" fullword ascii /* score: '4.00'*/
      $s16 = "POoDXgu=^" fullword ascii /* score: '4.00'*/
      $s17 = "RZLABEL_HANDCURSOR" fullword wide /* score: '4.00'*/
      $s18 = "RJL Software, Inc." fullword wide /* score: '4.00'*/
      $s19 = "Randomly changes the time" fullword wide /* score: '4.00'*/
      $s20 = "Copyright 2001, RJL Software, Inc." fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

