/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpz_noug_3
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpz_noug_3_Merkur {
   meta:
      description = "tmpz_noug_3 - file Merkur.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "7e89fabfdbe214bf6a6f9730f3e451e69f752b62bbd54c0a81d2aae2320abd2c"
   strings:
      $x1 = "c:\\AutoExec.exe" fullword wide /* score: '36.00'*/
      $x2 = "c:\\program files\\eDonkey2000\\incoming\\IPspoofer.exe" fullword wide /* score: '35.00'*/
      $x3 = "c:\\program files\\kazaa\\my shared folder\\IPspoofer.exe" fullword wide /* score: '32.00'*/
      $x4 = "c:\\program files\\bearshare\\shared\\IPspoofer.exe" fullword wide /* score: '32.00'*/
      $s5 = "c:\\program files\\eDonkey2000\\incoming\\Virtual Sex Simulator.exe" fullword wide /* score: '30.00'*/
      $s6 = "regedit /s c:\\Windows\\system32\\regme.reg" fullword wide /* score: '29.00'*/
      $s7 = "n4= /dcc send -c $nick c:\\Windows\\screensaver.exe" fullword wide /* score: '29.00'*/
      $s8 = "c:\\program files\\kazaa\\my shared folder\\Virtual Sex Simulator.exe" fullword wide /* score: '27.00'*/
      $s9 = "c:\\program files\\bearshare\\shared\\Virtual Sex Simulator.exe" fullword wide /* score: '27.00'*/
      $s10 = "c:\\mIRC\\script.ini" fullword wide /* score: '27.00'*/
      $s11 = "@*\\AC:\\Documents and Settings\\Ben\\Desktop\\Win32.mercury@mm.vbp" fullword wide /* score: '25.00'*/
      $s12 = "c:\\Windows\\System\\AVupdate.exe" fullword wide /* score: '24.00'*/
      $s13 = "c:\\windows\\screensaver.exe" fullword wide /* score: '24.00'*/
      $s14 = "c:\\Program Files\\mIRC\\script.ini" fullword wide /* score: '24.00'*/
      $s15 = "c:\\WINDOWS\\taskman.exe" fullword wide /* score: '21.00'*/
      $s16 = "c:\\Program Files\\uninstall.exe" fullword wide /* score: '21.00'*/
      $s17 = "c:\\Windows\\Notepad.exe" fullword wide /* score: '21.00'*/
      $s18 = "c:\\Windows\\system32\\regme.reg" fullword wide /* score: '21.00'*/
      $s19 = "\"AVupdate\"=\"\\\"c:\\Windows\\System\\AVupdate.exe\"\"" fullword wide /* score: '20.00'*/
      $s20 = "c:\\pr0n.bat" fullword wide /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

