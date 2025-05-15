/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpcd3lng1b
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpcd3lng1b_Rokku {
   meta:
      description = "tmpcd3lng1b - file Rokku.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "438888ef36bad1079af79daf152db443b4472c5715a7b3da0ba24cc757c53499"
   strings:
      $s1 = "getcwd=" fullword ascii /* score: '9.00'*/
      $s2 = "* 0zBY" fullword ascii /* score: '9.00'*/
      $s3 = "mnopqry" fullword ascii /* score: '8.00'*/
      $s4 = "dmesfyy" fullword ascii /* score: '8.00'*/
      $s5 = "hkiojsy" fullword ascii /* score: '8.00'*/
      $s6 = "ehiimjy" fullword ascii /* score: '8.00'*/
      $s7 = "OMeAq+ *" fullword ascii /* score: '8.00'*/
      $s8 = "ddgghhkkmmnnp" fullword ascii /* score: '8.00'*/
      $s9 = "ynomial" fullword ascii /* score: '8.00'*/
      $s10 = "ntelt{DAuth" fullword ascii /* score: '7.00'*/
      $s11 = "Error while matchj" fullword ascii /* score: '7.00'*/
      $s12 = "Q4httpi\"" fullword ascii /* score: '7.00'*/
      $s13 = "YCOMPLET<s" fullword ascii /* score: '7.00'*/
      $s14 = "KMTWEAD" fullword ascii /* score: '6.50'*/
      $s15 = "NDTODLT" fullword ascii /* score: '6.50'*/
      $s16 = "EBDPTIB" fullword ascii /* score: '6.50'*/
      $s17 = "AKDEYGH" fullword ascii /* score: '6.50'*/
      $s18 = "NRMSTWF" fullword ascii /* score: '6.50'*/
      $s19 = "7g %s:" fullword ascii /* score: '6.50'*/
      $s20 = "ICNOUWUB" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

