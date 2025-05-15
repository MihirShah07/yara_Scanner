/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpq76wttut
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpq76wttut_Xyeta {
   meta:
      description = "tmpq76wttut - file Xyeta.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "3ab3833e31e4083026421c641304369acfd31b957b78af81f3c6ef4968ef0e15"
   strings:
      $s1 = "el32.dll(" fullword ascii /* score: '16.00'*/
      $s2 = "formance" fullword ascii /* score: '8.00'*/
      $s3 = "# ;h-E" fullword ascii /* score: '5.00'*/
      $s4 = "6Ymihtrk3hqdr" fullword ascii /* score: '4.00'*/
      $s5 = "FboTd-;" fullword ascii /* score: '4.00'*/
      $s6 = "vourVxIx" fullword ascii /* score: '4.00'*/
      $s7 = "&tMPag&" fullword ascii /* score: '4.00'*/
      $s8 = "bgIu #P " fullword ascii /* score: '4.00'*/
      $s9 = "SXYC|d^" fullword ascii /* score: '4.00'*/
      $s10 = "qpetQt$" fullword ascii /* score: '4.00'*/
      $s11 = "IOIo yl" fullword ascii /* score: '4.00'*/
      $s12 = "oDwhBqc" fullword ascii /* score: '4.00'*/
      $s13 = "oGUK:zEm" fullword ascii /* score: '4.00'*/
      $s14 = "elzD!7`" fullword ascii /* score: '4.00'*/
      $s15 = "Gevi{%'" fullword ascii /* score: '4.00'*/
      $s16 = "@5CyWH,a0" fullword ascii /* score: '4.00'*/
      $s17 = "iVqfhj4iX" fullword ascii /* score: '4.00'*/
      $s18 = "hYDIBFTe" fullword ascii /* score: '4.00'*/
      $s19 = "G7hurh_#F" fullword ascii /* score: '4.00'*/
      $s20 = "VirtualAW" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

