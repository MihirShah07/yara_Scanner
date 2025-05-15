/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpbs8j54q1
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Illerka_C {
   meta:
      description = "tmpbs8j54q1 - file Illerka.C.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "cde188d6c4d6e64d6abfdea1e113314f9cdf9417bca36eb7201e6b766e5f5a7f"
   strings:
      $x1 = "C:\\Users\\Michael B\\Documents\\Visual Studio 2015\\Projects\\Illerka.C\\Illerka.C\\obj\\x86\\Release\\Illerka.C.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s5 = "Illerka.C.exe" fullword wide /* score: '19.00'*/
      $s6 = ".avi;.bat;.cmd;.exe;.htm;.html;.lnk;.mpg;.mpeg;.mov;.mp3;.mp4;.mkv;.msi;.m3u;.rar;.reg;.txt;.vbs;.wav;.zip;.7z" fullword wide /* score: '16.00'*/
      $s7 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s8 = "            compatibility then delete the requestedExecutionLevel node." fullword ascii /* score: '14.00'*/
      $s9 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s10 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations" fullword wide /* score: '13.00'*/
      $s11 = "most compatible environment.-->" fullword ascii /* score: '12.00'*/
      $s12 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s13 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s14 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s15 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s16 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s17 = "            Specifying requestedExecutionLevel node will disable file and registry virtualization." fullword ascii /* score: '11.00'*/
      $s18 = "            requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s19 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s20 = "      <!-- If your application is designed to work with Windows 7, uncomment the following supportedOS node-->" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

