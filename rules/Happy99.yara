/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpty140pcp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpty140pcp_Happy99 {
   meta:
      description = "tmpty140pcp - file Happy99.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4ebe3e1af5e147c580ecce052fe7d7d0219d5e5a2f5e6d8a7f7291735923db18"
   strings:
      $s1 = "Ska.dll" fullword ascii /* score: '20.00'*/
      $s2 = "begin 644 Happy99.exe" fullword ascii /* score: '19.00'*/
      $s3 = "\\Ska.exe" fullword ascii /* score: '13.00'*/
      $s4 = "\\liste.ska" fullword ascii /* score: '8.00'*/
      $s5 = "=.dattY" fullword ascii /* score: '5.00'*/
      $s6 = "Happy New Year 1999 !!" fullword ascii /* score: '4.00'*/
      $s7 = "=.text#=.edat" fullword ascii /* score: '4.00'*/
      $s8 = "=connt =sendtbB" fullword ascii /* score: '4.00'*/
      $s9 = "*qZERO" fullword ascii /* score: '1.00'*/
      $s10 = "0F0^0p0{0" fullword ascii /* score: '1.00'*/
      $s11 = "=END t" fullword ascii /* score: '1.00'*/
      $s12 = "Rt'Rt/t" fullword ascii /* score: '1.00'*/
      $s13 = "3.363C3J3P3Y3" fullword ascii /* score: '1.00'*/
      $s14 = "2-2;2M2Z2l2" fullword ascii /* score: '1.00'*/
      $s15 = "161H1O1U1[1a1s1y1" fullword ascii /* score: '1.00'*/
      $s16 = "4*464;4A4L4Y4e4w4|4" fullword ascii /* score: '1.00'*/
      $s17 = "828?8v8|8" fullword ascii /* score: '1.00'*/
      $s18 = "=ZEROt" fullword ascii /* score: '1.00'*/
      $s19 = "6(6d636N6Z6_6i6o6s6x6" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

