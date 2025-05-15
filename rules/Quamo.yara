/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp9xx6_29t
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp9xx6_29t_Quamo {
   meta:
      description = "tmp9xx6_29t - file Quamo.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "fc2ced1d89845dcfae55b6e854cd0e622fdf98baeeb4a67a60852ecd1212f93b"
   strings:
      $s1 = "@*\\AC:\\TEMP\\Q3\\Project1.vbp" fullword wide /* score: '24.00'*/
      $s2 = "quake4demo.exe" fullword wide /* score: '22.00'*/
      $s3 = "honey.exe" fullword wide /* score: '22.00'*/
      $s4 = "f:\\quake4demo.exe" fullword wide /* score: '21.00'*/
      $s5 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s6 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s7 = "\\quake4demo.exe" fullword wide /* score: '16.00'*/
      $s8 = "\\honey.exe" fullword wide /* score: '16.00'*/
      $s9 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\quake" fullword wide /* score: '16.00'*/
      $s10 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Q4" fullword wide /* score: '16.00'*/
      $s11 = "c:\\eiram" fullword wide /* score: '10.00'*/
      $s12 = "GetSpecialFolder" fullword wide /* score: '9.00'*/
      $s13 = "GetNameSpace" fullword wide /* score: '9.00'*/
      $s14 = "Hey you, take a look at the attached file.  You won't believe your eyes when you open it!" fullword wide /* score: '9.00'*/
      $s15 = "Did you see the pictures of me and my battery operated boyfriend?" fullword wide /* score: '9.00'*/
      $s16 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Q4" fullword wide /* score: '9.00'*/
      $s17 = "RegWrite" fullword wide /* PEStudio Blacklist: strings */ /* score: '9.00'*/
      $s18 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\quake" fullword wide /* score: '9.00'*/
      $s19 = "GetFolder" fullword wide /* score: '9.00'*/
      $s20 = "GetExtensionName" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

