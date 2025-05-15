/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpz07vw32b
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpz07vw32b_White_a {
   meta:
      description = "tmpz07vw32b - file White.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "c0acebefd398f733123173adebaac32c9be2c2d52fcb17f6aff72be04f3569c4"
   strings:
      $x1 = "c:\\windows\\system\\rundll64.exe" fullword wide /* score: '32.00'*/
      $s2 = "yourlife.exe" fullword wide /* score: '22.00'*/
      $s3 = "White.exe" fullword wide /* score: '22.00'*/
      $s4 = "Fuck!!!" fullword ascii /* score: '18.00'*/
      $s5 = "@*\\AC:\\Program Files\\Microsoft Visual Studio\\VB98\\__worm__\\Worm\\amiworm.vbp" fullword wide /* score: '17.00'*/
      $s6 = "c:\\no_kill_hwp.wrm" fullword wide /* score: '16.00'*/
      $s7 = "c:\\nhkr.wrm" fullword wide /* score: '16.00'*/
      $s8 = "vb6ko.dll" fullword ascii /* score: '13.00'*/
      $s9 = "rundll64" fullword ascii /* score: '13.00'*/
      $s10 = "[Korea] - KING!" fullword ascii /* score: '12.00'*/
      $s11 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca" fullword ascii /* score: '12.00'*/
      $s12 = "echo y|format c: /q > nul" fullword wide /* score: '12.00'*/
      $s13 = "Sub to Get Winsock Control" fullword ascii /* score: '11.00'*/
      $s14 = "MSWINSCK.OCX" fullword ascii /* score: '10.00'*/
      $s15 = "MSMAPI.MAPISession" fullword ascii /* score: '10.00'*/
      $s16 = "MSMAPI32.OCX" fullword ascii /* score: '10.00'*/
      $s17 = "Software\\Microsoft\\windows\\currentversion\\run" fullword wide /* score: '10.00'*/
      $s18 = "Create by NHKR _ Need for VB DLL File #6.0" fullword ascii /* score: '9.00'*/
      $s19 = "unPack Error. I can't fix the error. Please reDownload." fullword wide /* score: '9.00'*/
      $s20 = "MAPISession1" fullword ascii /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

