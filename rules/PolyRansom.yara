/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp4zj3xs4x
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule PolyRansom {
   meta:
      description = "tmp4zj3xs4x - file PolyRansom.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1898f2cae1e3824cb0f7fd5368171a33aba179e63501e480b4da9ea05ebf0423"
   strings:
      $s1 = "ZUGpO760" fullword ascii /* score: '5.00'*/
      $s2 = "vzwcum" fullword ascii /* score: '5.00'*/
      $s3 = "7?2UGpO76Q" fullword ascii /* score: '4.00'*/
      $s4 = "S.NmG`" fullword ascii /* score: '4.00'*/
      $s5 = "XUGpO76V" fullword ascii /* score: '4.00'*/
      $s6 = "TlLmRlM" fullword ascii /* score: '4.00'*/
      $s7 = "-jtyShFr" fullword ascii /* score: '4.00'*/
      $s8 = "snYXB?9c" fullword ascii /* score: '4.00'*/
      $s9 = "mUWKeVUH" fullword ascii /* score: '4.00'*/
      $s10 = "AMxX+a)" fullword ascii /* score: '4.00'*/
      $s11 = "adcth>O" fullword ascii /* score: '4.00'*/
      $s12 = "CgXS%kr4k" fullword ascii /* score: '4.00'*/
      $s13 = "AnMt)-o" fullword ascii /* score: '4.00'*/
      $s14 = "6azPV?" fullword ascii /* score: '4.00'*/
      $s15 = "aMiGgLiG`" fullword ascii /* score: '4.00'*/
      $s16 = "DtnB|#%\\" fullword ascii /* score: '4.00'*/
      $s17 = "N:.nci" fullword ascii /* score: '4.00'*/
      $s18 = "%r,F<w" fullword ascii /* score: '3.50'*/
      $s19 = "\\sv'/Q" fullword ascii /* score: '2.00'*/
      $s20 = "\\sO'?n" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

