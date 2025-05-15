/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpieiqg3ng
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpieiqg3ng_xpaj {
   meta:
      description = "tmpieiqg3ng - file xpaj.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "9db7ef2d1495dba921f3084b05d95e418a16f4c5e8de93738abef2479ad5b0da"
   strings:
      $s1 = "O6w.ojA" fullword ascii /* score: '7.00'*/
      $s2 = "xxyfO3_?us" fullword ascii /* score: '4.00'*/
      $s3 = "RIyB9xsu" fullword ascii /* score: '4.00'*/
      $s4 = ".RbYmk6yXR" fullword ascii /* score: '4.00'*/
      $s5 = "Gnlr4<<" fullword ascii /* score: '4.00'*/
      $s6 = "LhFk:C{G" fullword ascii /* score: '4.00'*/
      $s7 = "dzfF>.I" fullword ascii /* score: '4.00'*/
      $s8 = "vZli8FMk" fullword ascii /* score: '4.00'*/
      $s9 = "98.ctB" fullword ascii /* score: '4.00'*/
      $s10 = "XbZlUXL" fullword ascii /* score: '4.00'*/
      $s11 = "+HfvD>E.n" fullword ascii /* score: '4.00'*/
      $s12 = "\"nHOk5.O" fullword ascii /* score: '4.00'*/
      $s13 = "oomDiiiN" fullword ascii /* score: '4.00'*/
      $s14 = ".qGq&}{" fullword ascii /* score: '4.00'*/
      $s15 = "nDCf~!'xm&" fullword ascii /* score: '4.00'*/
      $s16 = "qe'uxpU1JI" fullword ascii /* score: '4.00'*/
      $s17 = "iBPEN^$" fullword ascii /* score: '4.00'*/
      $s18 = "xlls6vV" fullword ascii /* score: '4.00'*/
      $s19 = "lzFx<Zd" fullword ascii /* score: '4.00'*/
      $s20 = "DqEg@e)" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

