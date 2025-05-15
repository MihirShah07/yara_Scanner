/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpn8b74pij
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MyDoom_A {
   meta:
      description = "tmpn8b74pij - file MyDoom.A.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "fff0ccf5feaf5d46b295f770ad398b6d572909b00e2b8bcd1b1c286c70cd9151"
   strings:
      $s1 = "W|.dll" fullword ascii /* score: '17.00'*/
      $s2 = "USERPROFI" fullword ascii /* score: '9.50'*/
      $s3 = "ghijklm" fullword ascii /* score: '8.00'*/
      $s4 = "fuvztMv.qyy7Fb" fullword ascii /* score: '7.00'*/
      $s5 = "\\Jvaqbjf\\Phe" fullword ascii /* score: '5.00'*/
      $s6 = "immyerr3" fullword ascii /* score: '5.00'*/
      $s7 = "isdigi" fullword ascii /* score: '5.00'*/
      $s8 = "}m`VOKJLQYdr" fullword ascii /* score: '4.00'*/
      $s9 = "D\"veTyp$v" fullword ascii /* score: '4.00'*/
      $s10 = "gold-Pxc" fullword ascii /* score: '4.00'*/
      $s11 = "pqrstNwxyzg" fullword ascii /* score: '4.00'*/
      $s12 = "ZVZR-X\\" fullword ascii /* score: '4.00'*/
      $s13 = "bgxvgKC" fullword ascii /* score: '4.00'*/
      $s14 = "(sync.c,v 0.1 2004" fullword ascii /* score: '4.00'*/
      $s15 = "KxExi%aF" fullword ascii /* score: '4.00'*/
      $s16 = "DATAEPCGo" fullword ascii /* score: '4.00'*/
      $s17 = "HByt\"nAdn" fullword ascii /* score: '4.00'*/
      $s18 = "pViewOf" fullword ascii /* score: '4.00'*/
      $s19 = "smith[C" fullword ascii /* score: '4.00'*/
      $s20 = "GSizeZClos" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      8 of them
}

