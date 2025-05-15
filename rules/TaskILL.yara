/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpadlrgrmy
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpadlrgrmy_TaskILL {
   meta:
      description = "tmpadlrgrmy - file TaskILL.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4663715548c70eec7e9cbf272171493d47a75d2652e38cca870412ea9e749fe9"
   strings:
      $x1 = "C:\\Users\\OriginalPgr\\Desktop\\TaskILL.exe\\TaskILL.exe\\obj\\Debug\\TaskILL.exe.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s4 = "TaskILL.exe.exe" fullword wide /* score: '22.00'*/
      $s5 = "TaskILL.exe" fullword wide /* score: '22.00'*/
      $s6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s7 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s8 = "TaskILL.exe.My.Resources" fullword ascii /* score: '14.00'*/
      $s9 = "TaskILL.exe.Resources.resources" fullword ascii /* score: '14.00'*/
      $s10 = "TaskILL.exe.My" fullword ascii /* score: '14.00'*/
      $s11 = "TaskILL.exe.Resources" fullword wide /* score: '14.00'*/
      $s12 = "mountvol c:\\ /d" fullword wide /* score: '14.00'*/
      $s13 = "      <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s14 = "      <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s15 = "      <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s16 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s17 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s18 = "      <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s19 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
      $s20 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      1 of ($x*) and 4 of them
}

