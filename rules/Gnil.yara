/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpzk4bxw0u
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpzk4bxw0u_Gnil {
   meta:
      description = "tmpzk4bxw0u - file Gnil.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "24c0638ff7571c7f4df5bcddd50bc478195823e934481fa3ee96eb1d1c4b4a1b"
   strings:
      $s1 = "}zHfnQ4]-(" fullword ascii /* score: '4.00'*/
      $s2 = "CyiSa(m" fullword ascii /* score: '4.00'*/
      $s3 = "RSQWPUVh" fullword ascii /* score: '4.00'*/
      $s4 = ":!%d=QD5" fullword ascii /* score: '4.00'*/
      $s5 = "gxiAS/-" fullword ascii /* score: '4.00'*/
      $s6 = "_.aPf%" fullword ascii /* score: '4.00'*/
      $s7 = "PQGSWvxue" fullword ascii /* score: '4.00'*/
      $s8 = "\\-6\"ghu&" fullword ascii /* score: '2.00'*/
      $s9 = "\\P03g$" fullword ascii /* score: '2.00'*/
      $s10 = "KvIUs6" fullword ascii /* score: '2.00'*/
      $s11 = "d~;Dyy8" fullword ascii /* score: '1.00'*/
      $s12 = "1FMNi_" fullword ascii /* score: '1.00'*/
      $s13 = "[,sK+J" fullword ascii /* score: '1.00'*/
      $s14 = "UF()+L" fullword ascii /* score: '1.00'*/
      $s15 = ">k.+LEXV;" fullword ascii /* score: '1.00'*/
      $s16 = "V:bODP" fullword ascii /* score: '1.00'*/
      $s17 = "*:n~%y" fullword ascii /* score: '1.00'*/
      $s18 = "9S=AI`" fullword ascii /* score: '1.00'*/
      $s19 = "ewl+)| " fullword ascii /* score: '1.00'*/
      $s20 = "!(a@+Cx0v" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

