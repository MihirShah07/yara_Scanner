/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp21qpebbf
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp21qpebbf_MadMan {
   meta:
      description = "tmp21qpebbf - file MadMan.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "17d81134a5957fb758b9d69a90b033477a991c8b0f107d9864dc790ca37e6a23"
   strings:
      $s1 = "!Infected Program!" fullword ascii /* score: '9.00'*/
      $s2 = "Goat file (EXE). Size=000003E8h/0000001000d bytes." fullword ascii /* score: '4.00'*/
      $s3 = "5y1s721" fullword ascii /* score: '1.00'*/
      $s4 = "/8'A?K2" fullword ascii /* score: '1.00'*/
      $s5 = "8'A5B7O5" fullword ascii /* score: '1.00'*/
      $s6 = "=2A3K\"" fullword ascii /* score: '1.00'*/
      $s7 = "11q7y1" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7KB and
      all of them
}

