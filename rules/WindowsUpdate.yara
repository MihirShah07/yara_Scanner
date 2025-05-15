/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpl2044fpk
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule WindowsUpdate {
   meta:
      description = "tmpl2044fpk - file WindowsUpdate.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "0fda176b199295f72fafc3bc25cefa27fa44ed7712c3a24ca2409217e430436d"
   strings:
      $s1 = "Project1.exe" fullword ascii /* score: '22.00'*/
      $s2 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true/pm</dpiAware>" fullword ascii /* score: '12.00'*/
      $s3 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2</dpiAwareness>" fullword ascii /* score: '12.00'*/
      $s4 = "<!--The ID below indicates app support for Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s5 = "        <requestedExecutionLevel" fullword ascii /* score: '11.00'*/
      $s6 = "        processorArchitecture=\"*\"/>" fullword ascii /* score: '10.00'*/
      $s7 = "        publicKeyToken=\"6595b64144ccf1df\"" fullword ascii /* score: '8.00'*/
      $s8 = "6JcR3w" fullword ascii /* score: '8.00'*/
      $s9 = "!Win32 .EXE." fullword ascii /* score: '8.00'*/
      $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s11 = "        version=\"6.0.0.0\"" fullword ascii /* score: '7.00'*/
      $s12 = "TUPDATEFORM" fullword wide /* score: '6.50'*/
      $s13 = "        name=\"Microsoft.Windows.Common-Controls\"" fullword ascii /* score: '6.00'*/
      $s14 = "CiuSwS46" fullword ascii /* score: '5.00'*/
      $s15 = "# 15Sr>" fullword ascii /* score: '5.00'*/
      $s16 = "$|+%j%" fullword ascii /* score: '5.00'*/
      $s17 = "x? -0]y" fullword ascii /* score: '5.00'*/
      $s18 = "W AQjo]tY" fullword ascii /* score: '4.00'*/
      $s19 = "uZ6]ZCFx=yp0" fullword ascii /* score: '4.00'*/
      $s20 = " {DCHF\"0" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

