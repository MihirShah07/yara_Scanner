/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpnfc8tkzz
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule CrazyNCS {
   meta:
      description = "tmpnfc8tkzz - file CrazyNCS.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "6820c71df417e434c5ad26438c901c780fc5a80b28a466821b47d20b8424ef08"
   strings:
      $s1 = "RJL Software - www.rjlsoftware.com" fullword wide /* score: '26.00'*/
      $s2 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "support@rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s4 = "CRAZY_NCS.EXE /c{Caps Interval} /s{Scroll Interval} /n{Num Interval}" fullword wide /* score: '11.00'*/
      $s5 = "_k:\"=l" fullword ascii /* score: '7.00'*/
      $s6 = "EVETERD" fullword ascii /* score: '6.50'*/
      $s7 = "TFRMCOPYRIGHT" fullword wide /* score: '6.50'*/
      $s8 = "VJSbKC7" fullword ascii /* score: '5.00'*/
      $s9 = "UyICSW5" fullword ascii /* score: '5.00'*/
      $s10 = "kEUwNYv" fullword ascii /* score: '4.00'*/
      $s11 = "PGUqiDS]p" fullword ascii /* score: '4.00'*/
      $s12 = "FNGtNsP:*" fullword ascii /* score: '4.00'*/
      $s13 = "PRPkWh.M." fullword ascii /* score: '4.00'*/
      $s14 = "RERMkpI" fullword ascii /* score: '4.00'*/
      $s15 = "NtOT'A'>'?," fullword ascii /* score: '4.00'*/
      $s16 = "FKTB/O/" fullword ascii /* score: '4.00'*/
      $s17 = "IAqa}~5" fullword ascii /* score: '4.00'*/
      $s18 = "gfOHMz@hC" fullword ascii /* score: '4.00'*/
      $s19 = "RtmRuG.U" fullword ascii /* score: '4.00'*/
      $s20 = "Copyright 1998,1999,2000 RJL Software, Inc. All Rights Reserved." fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

