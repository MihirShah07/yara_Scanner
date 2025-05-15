/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmphl22r6fi
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmphl22r6fi_Nople {
   meta:
      description = "tmphl22r6fi - file Nople.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "d2518df72d5cce230d98a435977d9283b606a5a4cafe8cd596641f96d8555254"
   strings:
      $s1 = "c:\\winnt\\noplease_flash_movie.exe" fullword ascii /* score: '24.00'*/
      $s2 = "c:\\winnt\\noplease_flash_movie.exe service" fullword ascii /* score: '23.00'*/
      $s3 = "%s\\c$\\winnt\\noplease_flash_movie.exe" fullword ascii /* score: '15.00'*/
      $s4 = "LogOffevent" fullword ascii /* score: '9.00'*/
      $s5 = "Remote Procedure Call agent" fullword ascii /* score: '8.00'*/
      $s6 = "srvcall" fullword ascii /* score: '4.00'*/
      $s7 = "ContinuwEvent" fullword ascii /* score: '4.00'*/
      $s8 = "PauseEvent" fullword ascii /* score: '4.00'*/
      $s9 = "EasterEgg" fullword ascii /* score: '4.00'*/
      $s10 = "Es hora de formatear" fullword ascii /* score: '4.00'*/
      $s11 = "tu disco" fullword ascii /* score: '3.00'*/
      $s12 = "ESSSSj" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

