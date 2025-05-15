/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_i11cmtm
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp_i11cmtm_Kiray {
   meta:
      description = "tmp_i11cmtm - file Kiray.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "166865fdb90e7964e7ea57a282343026d878230215e5694145f88a8afb56132f"
   strings:
      $s1 = "kiray.exe" fullword wide /* score: '22.00'*/
      $s2 = "Macromedia Flash" fullword wide /* score: '4.00'*/
      $s3 = "Flash 6.0" fullword wide /* score: '4.00'*/
      $s4 = "\\P/{Gl" fullword ascii /* score: '2.00'*/
      $s5 = "|`\\ _i" fullword ascii /* score: '1.00'*/
      $s6 = "Fmxw7=" fullword ascii /* score: '1.00'*/
      $s7 = ";^t6Zj" fullword ascii /* score: '1.00'*/
      $s8 = "0UkJH]" fullword ascii /* score: '1.00'*/
      $s9 = " :*w.N" fullword ascii /* score: '1.00'*/
      $s10 = "2lDPaDO" fullword ascii /* score: '1.00'*/
      $s11 = " s\"j'X+" fullword ascii /* score: '1.00'*/
      $s12 = ";5k#@w*U @" fullword ascii /* score: '1.00'*/
      $s13 = "4,0,7,0" fullword wide /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}

