/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpeo5hjkp_
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpeo5hjkp__Klez_e {
   meta:
      description = "tmpeo5hjkp_ - file Klez.e.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "3113fa9a3cf00ed423a2c686a2ffb19586f6a047747de65a93436a7dca8fcfa7"
   strings:
      $s1 = "e:\\windows\\SyStem32\\dLlcache\\ddd.exe" fullword ascii /* score: '30.00'*/
      $s2 = "dummy.exe" fullword ascii /* score: '22.00'*/
      $s3 = "Vet32.exe" fullword wide /* score: '19.00'*/
      $s4 = "Version 5.2.5.0" fullword wide /* score: '12.00'*/
      $s5 = " 1989-2000 Computer Associates International, Inc." fullword wide /* score: '9.00'*/
      $s6 = "InoculateIT is a trademark of Computer Associates International, Inc." fullword wide /* score: '9.00'*/
      $s7 = "Computer Associates International, Inc." fullword wide /* score: '7.00'*/
      $s8 = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN" fullword ascii /* score: '6.50'*/
      $s9 = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN" ascii /* score: '6.50'*/
      $s10 = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN" ascii /* score: '6.50'*/
      $s11 = "NNTNNNNNNNNN" fullword ascii /* score: '6.50'*/
      $s12 = "NNNNNNNNNNNNNNNNNNN" fullword ascii /* score: '6.50'*/
      $s13 = "TZNNNNNN" fullword ascii /* score: '6.50'*/
      $s14 = "NNNNNNNNNTZ6" fullword ascii /* score: '5.00'*/
      $s15 = "Win32 Anti-Virus scanner" fullword wide /* score: '5.00'*/
      $s16 = "aFFFj3PFF{qU{Yk" fullword ascii /* score: '4.00'*/
      $s17 = "SVWj_^3" fullword ascii /* score: '4.00'*/
      $s18 = "NNNNNNNNNNNN:" fullword ascii /* score: '4.00'*/
      $s19 = "YYPSWhF" fullword ascii /* score: '4.00'*/
      $s20 = "2NNNNNNNNNN" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

