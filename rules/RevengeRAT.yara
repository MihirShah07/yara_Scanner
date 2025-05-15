/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpyipf9_ha
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule RevengeRAT {
   meta:
      description = "tmpyipf9_ha - file RevengeRAT.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "9b4826b8876ca2f1378b1dfe47b0c0d6e972bf9f0b3a36e299b26fbc86283885"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, Publickeytoken=b77a5c561934" ascii /* score: '27.00'*/
      $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, Publickeytoken=b77a5c561934" ascii /* score: '27.00'*/
      $s3 = "YSystem.Int16, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii /* score: '27.00'*/
      $s4 = "System.Windows.Forms.Dll" fullword wide /* score: '26.00'*/
      $s5 = "svchost\\svchost.exe" fullword wide /* score: '20.00'*/
      $s6 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s7 = "Nuclear Explosion.exe" fullword ascii /* score: '19.00'*/
      $s8 = "\\Microsoft.NET\\Framework\\v2.0.50727\\RegSvcs.exe" fullword wide /* score: '19.00'*/
      $s9 = "\\Users\\Public\\Desktop\\" fullword wide /* score: '19.00'*/
      $s10 = "System.Drawing.IconLib.ColorProcessing" fullword ascii /* score: '18.00'*/
      $s11 = "System.Diagnostics.Process.Start(\"" fullword wide /* score: '18.00'*/
      $s12 = "' is not a valid win32 executable or dll." fullword wide /* score: '17.00'*/
      $s13 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide /* score: '16.00'*/
      $s14 = "schtasks /create /sc minute /mo 1 /tn \"svchost\" /tr \"" fullword wide /* score: '16.00'*/
      $s15 = "Process_INFORMATION" fullword ascii /* score: '15.00'*/
      $s16 = "uRClgZblR.txt" fullword wide /* score: '14.00'*/
      $s17 = "jnFwUno.txt" fullword wide /* score: '14.00'*/
      $s18 = "/target:winexe" fullword wide /* score: '14.00'*/
      $s19 = "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0" fullword wide /* score: '14.00'*/
      $s20 = "\\ProgramData\\svchost\\XjtnxDp.ico" fullword wide /* score: '13.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 12000KB and
      8 of them
}

