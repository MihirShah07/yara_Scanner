/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmptjla7efu
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmptjla7efu_Gruel_a {
   meta:
      description = "tmptjla7efu - file Gruel.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "5714efd4746f7796bbc52a272f8e354f67edfb50129d5fdaa1396e920956d0d6"
   strings:
      $x1 = "C:\\windows\\system32\\*.dll" fullword wide /* score: '37.00'*/
      $x2 = "C:\\windows\\system32\\command.com" fullword wide /* score: '36.00'*/
      $x3 = "C:\\WINNT\\SYSTEM32\\Rundll33.exe" fullword wide /* score: '34.00'*/
      $x4 = "C:\\WINNT\\system32\\*.dll" fullword wide /* score: '34.00'*/
      $x5 = "C:\\WINNT\\system32\\command.com" fullword wide /* score: '33.00'*/
      $x6 = "C:\\windows\\system32\\ntoskrnl.exe" fullword wide /* score: '32.00'*/
      $x7 = "C:\\windows\\system32\\*.exe" fullword wide /* score: '32.00'*/
      $x8 = "C:\\windows\\system32\\*.com" fullword wide /* score: '31.00'*/
      $s9 = "C:\\WINNT\\System32\\msvbvm60.dll\\3" fullword ascii /* score: '30.00'*/
      $s10 = "Windows Found KERNEL32 Seriuos Error, please contact support@microsoft.com" fullword wide /* score: '29.00'*/
      $s11 = "C:\\WINNT\\system32\\ntoskrnl.exe" fullword wide /* score: '29.00'*/
      $s12 = "C:\\WINNT\\system32\\*.exe" fullword wide /* score: '29.00'*/
      $s13 = "C:\\Rundll32.exe" fullword wide /* score: '28.00'*/
      $s14 = "C:\\AUTOEXEC.bat" fullword wide /* score: '28.00'*/
      $s15 = "C:\\WINNT\\system32\\*.com" fullword wide /* score: '28.00'*/
      $s16 = "Your computer now is mine, Why? Because I didn't had nothing to do and I thought, why not make the evil? Remember NOW YOUR PC IS" wide /* score: '28.00'*/
      $s17 = "rundll32.exe shell32.dll,Control_RunDLL mmsys.cpl @1" fullword wide /* score: '27.00'*/
      $s18 = "rundll32.exe shell32.dll,Control_RunDLL netcpl.cpl" fullword wide /* score: '27.00'*/
      $s19 = "rundll32.exe shell32.dll,Control_RunDLL mmsys.cpl,,0" fullword wide /* score: '27.00'*/
      $s20 = "rundll32.exe shell32.dll,Control_RunDLL main.cpl @0" fullword wide /* score: '27.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

