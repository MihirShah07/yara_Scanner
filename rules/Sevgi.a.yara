/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpzv8jlidh
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpzv8jlidh_Sevgi_a {
   meta:
      description = "tmpzv8jlidh - file Sevgi.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "750e37d1fdd64e9ea015272a0db6720ac9a8d803dc0caad29d0653756a8e5b17"
   strings:
      $s1 = "Decompress error" fullword ascii /* score: '10.00'*/
      $s2 = "** E ," fullword ascii /* score: '9.00'*/
      $s3 = "defghijs" fullword ascii /* score: '8.00'*/
      $s4 = "tuvwxyz" fullword ascii /* score: '8.00'*/
      $s5 = "p:\"F3>" fullword ascii /* score: '7.00'*/
      $s6 = "GHIJSTUV" fullword ascii /* score: '6.50'*/
      $s7 = "f-_%o%" fullword ascii /* score: '5.00'*/
      $s8 = "!s*K- " fullword ascii /* score: '5.00'*/
      $s9 = "G$+ Xd" fullword ascii /* score: '5.00'*/
      $s10 = "n'$jz5VwVzrfu\"F" fullword ascii /* score: '4.00'*/
      $s11 = "sAdaopZr" fullword ascii /* score: '4.00'*/
      $s12 = "AMACO,!" fullword ascii /* score: '4.00'*/
      $s13 = "owOrg)Ex" fullword ascii /* score: '4.00'*/
      $s14 = "{sexR?f1Qb" fullword ascii /* score: '4.00'*/
      $s15 = "ipboarYdI" fullword ascii /* score: '4.00'*/
      $s16 = "TAlignme" fullword ascii /* score: '4.00'*/
      $s17 = "IUnrk9ow" fullword ascii /* score: '4.00'*/
      $s18 = "alDispk" fullword ascii /* score: '4.00'*/
      $s19 = "TUVWXYZc" fullword ascii /* score: '4.00'*/
      $s20 = "KWindow" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

