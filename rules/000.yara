/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp21pjc9mz
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp21pjc9mz_000 {
   meta:
      description = "tmp21pjc9mz - file 000.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4ea1f2ecf7eb12896f2cbf8683dae8546d2b8dc43cf7710d68ce99e127c0a966"
   strings:
      $x1 = "C:\\Users\\FlyTech\\Documents\\Visual Studio 2015\\Projects\\Creep\\Creep\\obj\\Debug\\000.pdb" fullword ascii /* score: '33.00'*/
      $x2 = "C:\\Users\\FlyTech\\Documents\\Visual Studio 2015\\Projects\\Messager\\Messager\\obj\\Debug\\Messager.pdb" fullword ascii /* score: '33.00'*/
      $x3 = "taskkill /f /im explorer.exe" fullword ascii /* score: '31.00'*/
      $x4 = "taskkill /f /im taskmgr.exe" fullword ascii /* score: '31.00'*/
      $s5 = "copy %temp%\\rniw.exe \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\rniw.exe\"" fullword ascii /* score: '28.00'*/
      $s6 = "copy %temp%\\text.txt \"%userprofile%\\Desktop\\UR NEXT UR NEXT UR NEXT UR NEXT UR NEXT UR NEXT UR NEXT UR N%cr%XT.txt\"" fullword ascii /* score: '28.00'*/
      $s7 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s8 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s9 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s10 = "if %cr%==28 copy %temp%\\one.rtf %userprofile%\\Desktop\\OPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENM" ascii /* score: '24.00'*/
      $s11 = "if %cr%==28 copy %temp%\\one.rtf %userprofile%\\Desktop\\OPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENMEOPENM" ascii /* score: '24.00'*/
      $s12 = "del /f /s /q %userprofile%\\Desktop\\*" fullword ascii /* score: '22.00'*/
      $s13 = "Messager.exe" fullword wide /* score: '22.00'*/
      $s14 = "for /d %%p in (%userprofile%\\Desktop\\*) Do rd /Q /S \"%%p\"" fullword ascii /* score: '22.00'*/
      $s15 = "rniw.exe" fullword wide /* score: '22.00'*/
      $s16 = ":000, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s17 = "000.exe" fullword wide /* score: '19.00'*/
      $s18 = "del /f /s /q \"C:\\Program Files\\WindowsApps\\\"" fullword ascii /* score: '18.00'*/
      $s19 = "-InitOnceExecuteOnce" fullword ascii /* score: '18.00'*/
      $s20 = "windl.bat" fullword wide /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      1 of ($x*) and 4 of them
}

