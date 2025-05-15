/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp2l4yavby
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Netres_a {
   meta:
      description = "tmp2l4yavby - file Netres.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1c0e2b7981ffa9e86185b7a7aac93f13629d92d8f58769569483202b3a926ce5"
   strings:
      $s1 = "AntiVP.exe" fullword ascii /* score: '22.00'*/
      $s2 = "C:\\v1.log" fullword ascii /* score: '22.00'*/
      $s3 = "!!!.exe" fullword ascii /* score: '21.00'*/
      $s4 = " - Dock zone has no control\"Unable to find a Table Of Contents" fullword wide /* score: '19.00'*/
      $s5 = "c:\\windows\\system\\" fullword ascii /* score: '16.00'*/
      $s6 = "c:\\windows\\system\\*.*" fullword ascii /* score: '16.00'*/
      $s7 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another formDocked control must have a name%Error remo" wide /* score: '16.00'*/
      $s8 = "Free pics.htm                                   .exe" fullword ascii /* score: '14.00'*/
      $s9 = "c:\\windows\\restop" fullword ascii /* score: '13.00'*/
      $s10 = "c:\\windows\\restop\\" fullword ascii /* score: '13.00'*/
      $s11 = "Borland User Components" fullword wide /* score: '12.00'*/
      $s12 = "StartNextLogon" fullword ascii /* score: '12.00'*/
      $s13 = ".jpg                                   .exe" fullword ascii /* score: '11.00'*/
      $s14 = ".xls                              .exe" fullword ascii /* score: '11.00'*/
      $s15 = ".doc                                       .exe" fullword ascii /* score: '11.00'*/
      $s16 = ".jpg                    .exe" fullword ascii /* score: '11.00'*/
      $s17 = ".jpg                                .exe" fullword ascii /* score: '11.00'*/
      $s18 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii /* score: '11.00'*/
      $s19 = ".doc                                 .exe" fullword ascii /* score: '11.00'*/
      $s20 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

