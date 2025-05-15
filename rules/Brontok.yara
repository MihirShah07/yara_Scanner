/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp3y6_s8x9
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp3y6_s8x9_Brontok {
   meta:
      description = "tmp3y6_s8x9 - file Brontok.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "941ebf1dc12321bbe430994a55f6e22a1b83cea2fa7d281484ea2dab06353112"
   strings:
      $s1 = "Jgpfffwww" fullword ascii /* score: '6.00'*/
      $s2 = "Rekfffwww" fullword ascii /* score: '6.00'*/
      $s3 = "Elxfffwww" fullword ascii /* score: '6.00'*/
      $s4 = "baStrI2" fullword ascii /* score: '5.00'*/
      $s5 = "aqrtO!" fullword ascii /* score: '4.00'*/
      $s6 = "fptun, 4" fullword ascii /* score: '4.00'*/
      $s7 = ";k{Rekmmm|||" fullword ascii /* score: '4.00'*/
      $s8 = "puhtc;S" fullword ascii /* score: '4.00'*/
      $s9 = "UKPXCN" fullword ascii /* score: '3.50'*/
      $s10 = "Jgpwww" fullword ascii /* score: '3.00'*/
      $s11 = "etFix8" fullword ascii /* score: '2.00'*/
      $s12 = "l}_xy|q" fullword ascii /* score: '1.00'*/
      $s13 = "r[6ky)u" fullword ascii /* score: '1.00'*/
      $s14 = "rXw[pi" fullword ascii /* score: '1.00'*/
      $s15 = "Opdo<:" fullword ascii /* score: '1.00'*/
      $s16 = ")>Djx#" fullword ascii /* score: '1.00'*/
      $s17 = "_dq= H" fullword ascii /* score: '1.00'*/
      $s18 = "5|_-zm>H^" fullword ascii /* score: '1.00'*/
      $s19 = "&qX\\1p" fullword ascii /* score: '1.00'*/
      $s20 = "I=/ERh" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

