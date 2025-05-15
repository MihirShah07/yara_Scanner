/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp7hsm2j_s
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Whiter_a {
   meta:
      description = "tmp7hsm2j_s - file Whiter.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "fe974c995cfb27e8c91123081986847f6d3d4252b6a8d1e1385c558f2aeb7057"
   strings:
      $s1 = "\\whismng.exe" fullword ascii /* score: '16.00'*/
      $s2 = "WhistlerMutex" fullword ascii /* score: '15.00'*/
      $s3 = "notepad.exe %s" fullword ascii /* score: '14.00'*/
      $s4 = "c:\\zwxp" fullword ascii /* score: '10.00'*/
      $s5 = "c:\\wxp" fullword ascii /* score: '10.00'*/
      $s6 = " -next" fullword ascii /* score: '5.00'*/
      $s7 = "You did a piracy, you deserve it." fullword ascii /* score: '4.00'*/
      $s8 = "VWuBh," fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      all of them
}

