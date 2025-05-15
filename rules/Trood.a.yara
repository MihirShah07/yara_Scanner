/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpt4kuoldq
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpt4kuoldq_Trood_a {
   meta:
      description = "tmpt4kuoldq - file Trood.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "24dd269b4d5edeb591ad992db33553d90f1848f58c06c9dd9fb3cdb4eaf812f5"
   strings:
      $s1 = "TCPIPUPD.EXE" fullword wide /* score: '22.00'*/
      $s2 = "\\systray.exe" fullword ascii /* score: '16.00'*/
      $s3 = "\\systray.sys" fullword ascii /* score: '16.00'*/
      $s4 = "\\systray.tmp" fullword ascii /* score: '15.00'*/
      $s5 = "Content-Type: application/x-msdownload;" fullword ascii /* score: '11.00'*/
      $s6 = "name=\"TCPIPUPD.EXE\"" fullword ascii /* score: '11.00'*/
      $s7 = "filename=\"TCPIPUPD.EXE\"" fullword ascii /* score: '11.00'*/
      $s8 = "Latest version of TCP/IP already present." fullword ascii /* score: '10.00'*/
      $s9 = "Content-Disposition: attachement;" fullword ascii /* score: '9.00'*/
      $s10 = "boundary=\"----This_is_created_by_VX_e-mail_service\"" fullword ascii /* score: '7.00'*/
      $s11 = "`imports" fullword ascii /* score: '7.00'*/
      $s12 = "------This_is_created_by_VX_e-mail_service--" fullword ascii /* score: '7.00'*/
      $s13 = "------This_is_created_by_VX_e-mail_service" fullword ascii /* score: '7.00'*/
      $s14 = "The system doesn't need an update." fullword ascii /* score: '7.00'*/
      $s15 = "TCPIPUPD" fullword wide /* score: '6.50'*/
      $s16 = "Rresource" fullword ascii /* score: '6.00'*/
      $s17 = "Prelocs" fullword ascii /* score: '6.00'*/
      $s18 = "Troodon" fullword ascii /* score: '6.00'*/
      $s19 = "Copyright (C) Microsoft Corp. 1999-2000" fullword wide /* score: '6.00'*/
      $s20 = "\\systray.me" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      8 of them
}

