/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp01vme5uo
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp01vme5uo_Xanax {
   meta:
      description = "tmp01vme5uo - file Xanax.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "910c03d210381f0443bfcefe682717f28378dcfe5415071dd127a9837a97b0a6"
   strings:
      $s1 = "Win32.HLLP.Xanax (c) 2001 Gigabyte" fullword ascii /* score: '7.00'*/
      $s2 = ">@.sgZ" fullword ascii /* score: '4.00'*/
      $s3 = "ooof2ooo" fullword ascii /* score: '4.00'*/
      $s4 = "oXZmnn'O" fullword ascii /* score: '4.00'*/
      $s5 = "w'pooo1{o" fullword ascii /* score: '4.00'*/
      $s6 = "Wfbz{A'" fullword ascii /* score: '4.00'*/
      $s7 = "qvvwG^J" fullword ascii /* score: '4.00'*/
      $s8 = "ypoor1" fullword ascii /* score: '2.00'*/
      $s9 = "[}2mml" fullword ascii /* score: '1.00'*/
      $s10 = "4BP\\g}%" fullword ascii /* score: '1.00'*/
      $s11 = "xzO n^:" fullword ascii /* score: '1.00'*/
      $s12 = "n@+bXt" fullword ascii /* score: '1.00'*/
      $s13 = "uT6'cD" fullword ascii /* score: '1.00'*/
      $s14 = "7O]L^i" fullword ascii /* score: '1.00'*/
      $s15 = "1.(C%h" fullword ascii /* score: '1.00'*/
      $s16 = "2?[c*[" fullword ascii /* score: '1.00'*/
      $s17 = " (08@P`p" fullword ascii /* score: '1.00'*/
      $s18 = "_!gCUw" fullword ascii /* score: '1.00'*/
      $s19 = "U[hv@W" fullword ascii /* score: '1.00'*/
      $s20 = "st*th," fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

