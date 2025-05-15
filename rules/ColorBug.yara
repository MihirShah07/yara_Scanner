/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpzwobzpqi
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ColorBug {
   meta:
      description = "tmpzwobzpqi - file ColorBug.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "775ba68597507cf3c24663f5016d257446abeb66627f20f8f832c0860cad84de"
   strings:
      $s1 = "cb.exe" fullword ascii /* score: '16.00'*/
      $s2 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii /* score: '11.00'*/
      $s3 = "\\Control Panel\\Colors" fullword ascii /* score: '5.00'*/
      $s4 = "StringL" fullword ascii /* score: '4.00'*/
      $s5 = "IStringsAdaptert" fullword ascii /* score: '4.00'*/
      $s6 = "TObjectL" fullword ascii /* score: '4.00'*/
      $s7 = "ExceptionPJ@" fullword ascii /* score: '4.00'*/
      $s8 = "TFileStreamSVWU" fullword ascii /* score: '4.00'*/
      $s9 = "ColourBugger" fullword ascii /* score: '4.00'*/
      $s10 = "?&?I?b?" fullword ascii /* score: '1.00'*/
      $s11 = ">(>\\>k>" fullword ascii /* score: '1.00'*/
      $s12 = "4$4,4044484<4@4D4H4L4P4d4" fullword ascii /* score: '1.00'*/
      $s13 = "0\"0?0n0" fullword ascii /* score: '1.00'*/
      $s14 = "7;7c7}7" fullword ascii /* score: '1.00'*/
      $s15 = ";2;I;|;" fullword ascii /* score: '1.00'*/
      $s16 = ">+?>?P?" fullword ascii /* score: '1.00'*/
      $s17 = "1\"1<1n1" fullword ascii /* score: '1.00'*/
      $s18 = "1$2H2f2v2|2" fullword ascii /* score: '1.00'*/
      $s19 = "=.===T=" fullword ascii /* score: '1.00'*/
      $s20 = "? ?K?P?i?t?|?" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

