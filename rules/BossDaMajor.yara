/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpraaold6h
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule BossDaMajor {
   meta:
      description = "tmpraaold6h - file BossDaMajor.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "730a41a7656f606a22e9f0d68782612d6e00ab8cfe1260160b9e0b00bc2e442a"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii /* score: '58.00'*/
      $x2 = "x.run \"cmd.exe /c echo MsgBox\"\"Mr Major Wanna See You!\"\",1+16,\"\"This is not easy to turn me muted\"\">\"\"%TEMP%\\defrez." ascii /* score: '47.00'*/
      $x3 = "x.run \"cmd.exe /c echo MsgBox\"\"Mr Major Wanna See You!\"\",1+16,\"\"This is not easy to turn me muted\"\">\"\"%TEMP%\\defrez." ascii /* score: '44.00'*/
      $x4 = "x.RegWrite\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\",\"explorer.exe, wscript.exe \"\"C:\\Program" ascii /* score: '41.00'*/
      $x5 = "taskkill /f /im dllhost.exe" fullword ascii /* score: '41.00'*/
      $x6 = "x.RegWrite\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\",\"explorer.exe, wscript.exe \"\"C:\\Program" ascii /* score: '41.00'*/
      $x7 = "taskkill /f /im opera.exe" fullword ascii /* score: '36.00'*/
      $x8 = "taskkill /f /im bing.exe" fullword ascii /* score: '34.00'*/
      $x9 = "taskkill /f /im notepad.exe" fullword ascii /* score: '31.00'*/
      $x10 = "wscript.exe \"C:\\Program Files\\mrsmajor\\CPUUsage.vbs\"" fullword ascii /* score: '31.00'*/
      $x11 = "taskkill /f /im chrome.exe" fullword ascii /* score: '31.00'*/
      $x12 = "taskkill /f /im yandex.exe" fullword ascii /* score: '31.00'*/
      $x13 = "taskkill /f /im iexplore.exe" fullword ascii /* score: '31.00'*/
      $x14 = "taskkill /f /im mspaint.exe" fullword ascii /* score: '31.00'*/
      $x15 = "taskkill /f /im msedge.exe" fullword ascii /* score: '31.00'*/
      $x16 = "taskkill /f /im microsoftedge.exe" fullword ascii /* score: '31.00'*/
      $x17 = "taskkill /f /im taskmgr.exe" fullword ascii /* score: '31.00'*/
      $x18 = "taskkill /f /im firefox.exe" fullword ascii /* score: '31.00'*/
      $s19 = "c:\\users\\guest\\documents\\visual studio 2015\\Projects\\WindowsApplication2\\WindowsApplication2\\obj\\Debug\\WindowsApplicat" ascii /* score: '29.00'*/
      $s20 = " ObjShell.ShellExecute \"wscript.exe\", \"\"\"\" & buhu & \"\"\" RunAsAdministrator\", , \"runas\", 1  " fullword ascii /* score: '28.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and all of them
}

