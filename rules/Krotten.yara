/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp9o_fotv7
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp9o_fotv7_Krotten {
   meta:
      description = "tmp9o_fotv7 - file Krotten.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "e79f164ccc75a5d5c032b4c5a96d6ad7604faffb28afe77bc29b9173fa3543e4"
   strings:
      $x1 = "Kernel crash found. ExecutedCommandCode=%u" fullword ascii /* score: '31.00'*/
      $s2 = "ExecutedCommandCode=%u" fullword ascii /* score: '26.00'*/
      $s3 = "C:\\WINDOWS\\Web\\rundll32.exe" fullword ascii /* score: '25.00'*/
      $s4 = "Photo.exe" fullword ascii /* score: '22.00'*/
      $s5 = "C:\\WINDOWS\\Cursors\\avp.exe" fullword ascii /* score: '21.00'*/
      $s6 = "Can't execute menu command" fullword ascii /* score: '18.00'*/
      $s7 = "svchost" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s8 = "http://poetry.rotten.com/lightning/" fullword ascii /* score: '17.00'*/
      $s9 = "No opened process" fullword ascii /* score: '15.00'*/
      $s10 = "LM..SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" fullword ascii /* score: '15.00'*/
      $s11 = "Can't execute directory operation" fullword ascii /* score: '15.00'*/
      $s12 = "C:\\OKZDdMvPhQTgQT5" fullword ascii /* score: '13.00'*/
      $s13 = "C:\\z515rKKNwyyrEkx" fullword ascii /* score: '13.00'*/
      $s14 = "C:\\g1rFryAhrVg2xrt" fullword ascii /* score: '13.00'*/
      $s15 = "C:\\g6QpgrhJDdQZeF0" fullword ascii /* score: '13.00'*/
      $s16 = "C:\\eDFUqDqCUaUK66W" fullword ascii /* score: '13.00'*/
      $s17 = "C:\\xsQCwdXAvxpla8P" fullword ascii /* score: '13.00'*/
      $s18 = "Invalid command" fullword ascii /* score: '12.00'*/
      $s19 = "nCR..regfile\\shell\\open\\command" fullword ascii /* score: '12.00'*/
      $s20 = "Can't read process' memory" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

