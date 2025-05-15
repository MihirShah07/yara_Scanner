/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpecv07z69
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Blaster_E {
   meta:
      description = "tmpecv07z69 - file Blaster.E.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2e481059b9bc9686c676d69a80202eed5022c9a53ecd8cac215e70c601dd7fdc"
   strings:
      $s1 = "CRTDLL.DLL" fullword ascii /* score: '23.00'*/
      $s2 = "mslaugh.exe" fullword ascii /* score: '22.00'*/
      $s3 = "ExitProcessThread" fullword ascii /* score: '15.00'*/
      $s4 = "GetComm" fullword ascii /* score: '12.00'*/
      $s5 = "ANG3L - hop" fullword ascii /* score: '9.00'*/
      $s6 = "iocSOFTK" fullword ascii /* score: '4.00'*/
      $s7 = "kimble.Q" fullword ascii /* score: '4.00'*/
      $s8 = "LastEr=r" fullword ascii /* score: '4.00'*/
      $s9 = "RtlUnwi%" fullword ascii /* score: '4.00'*/
      $s10 = "SvValue" fullword ascii /* score: '4.00'*/
      $s11 = "self andKont forge" fullword ascii /* score: '4.00'*/
      $s12 = "u r strain" fullword ascii /* score: '3.00'*/
      $s13 = "Moduln" fullword ascii /* score: '3.00'*/
      $s14 = "MIw~f#n#F" fullword ascii /* score: '1.00'*/
      $s15 = "lRege{" fullword ascii /* score: '1.00'*/
      $s16 = "?\"u#j\"" fullword ascii /* score: '1.00'*/
      $s17 = "okui3_" fullword ascii /* score: '1.00'*/
      $s18 = "Gvx/[G" fullword ascii /* score: '1.00'*/
      $s19 = "t(x1%Sr" fullword ascii /* score: '1.00'*/
      $s20 = "=W}$h>" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      8 of them
}

