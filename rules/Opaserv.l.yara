/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpd87uozsm
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Opaserv_l {
   meta:
      description = "tmpd87uozsm - file Opaserv.l.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "de709dacac623c637448dc91f6dfd441a49c89372af2c53e2027e4af5310b95d"
   strings:
      $s1 = "jsocket" fullword ascii /* score: '8.00'*/
      $s2 = "USER3x28DL" fullword ascii /* score: '7.00'*/
      $s3 = "kCXG <x" fullword ascii /* score: '4.00'*/
      $s4 = "kfiPWHA" fullword ascii /* score: '4.00'*/
      $s5 = "This ex" fullword ascii /* score: '4.00'*/
      $s6 = "SBIN{D" fullword ascii /* score: '4.00'*/
      $s7 = "GHQST T" fullword ascii /* score: '4.00'*/
      $s8 = "umNPewDke" fullword ascii /* score: '4.00'*/
      $s9 = "Eefd-SN" fullword ascii /* score: '4.00'*/
      $s10 = "ADVePIX" fullword ascii /* score: '4.00'*/
      $s11 = "Chbks?um" fullword ascii /* score: '4.00'*/
      $s12 = "A$b%u;" fullword ascii /* score: '3.50'*/
      $s13 = "\\+t\"M*ZY" fullword ascii /* score: '2.00'*/
      $s14 = "Y[O]@b" fullword ascii /* score: '1.00'*/
      $s15 = "'F_C) " fullword ascii /* score: '1.00'*/
      $s16 = "{qAAu4h" fullword ascii /* score: '1.00'*/
      $s17 = "SVD8[X" fullword ascii /* score: '1.00'*/
      $s18 = "v_c^PYo" fullword ascii /* score: '1.00'*/
      $s19 = "B*~7[6yo" fullword ascii /* score: '1.00'*/
      $s20 = "*/ 7#%" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

