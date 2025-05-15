/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpeaq5vd6e
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Maldal_a {
   meta:
      description = "tmpeaq5vd6e - file Maldal.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "abac285f290f0cfcd308071c9dfa9b7b4b48d10b4a3b4d75048804e59a447787"
   strings:
      $s1 = "MyAccount.exe" fullword wide /* score: '25.00'*/
      $s2 = "LucKey.exe" fullword wide /* score: '25.00'*/
      $s3 = "DALLAH.exe" fullword wide /* score: '22.00'*/
      $s4 = "DaLLAh.ExE" fullword wide /* score: '22.00'*/
      $s5 = " http://finance.com" fullword wide /* score: '21.00'*/
      $s6 = "<span style='position:absolute'><Iframe src='Http://geocities.com\\angel_dalal\\index.htm' width='0' height='0'></Iframe></span>" wide /* score: '20.00'*/
      $s7 = "Scripting.filesystemobject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s8 = "scripting.filesystemobject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s9 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Desktop" fullword wide /* score: '18.00'*/
      $s10 = "Scripting.FileSystemObject" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s11 = "A:\\mallait.exe" fullword wide /* score: '17.00'*/
      $s12 = "A:\\MALAL.exe" fullword wide /* score: '17.00'*/
      $s13 = "Script.ini" fullword wide /* score: '16.00'*/
      $s14 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts\\00000001\\SMTP Display Name" fullword wide /* score: '15.00'*/
      $s15 = "mirc.ini" fullword wide /* score: '15.00'*/
      $s16 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\cache" fullword wide /* score: '14.00'*/
      $s17 = "Flopy.vbs" fullword wide /* score: '14.00'*/
      $s18 = "WScript.Network" fullword wide /* score: '13.00'*/
      $s19 = "regwrite" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s20 = "\\MY FILES\\Virus_ZaCkeR\\ZACKER.EXE\\DaLLah\\Ebn_DaLLah.vbp" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

