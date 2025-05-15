/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpef2sa0w4
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ChilledWindows {
   meta:
      description = "tmpef2sa0w4 - file ChilledWindows.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "ccb9502bf8ba5becf8b758ca04a5625c30b79e2d10d2677cc43ae4253e1288ec"
   strings:
      $x1 = "C:\\Users\\gamel\\documents\\visual studio 2015\\Projects\\ChilledWindowsWPF\\ChilledWindows\\obj\\Release\\ChilledWindows.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "ChilledWindows.exe" fullword wide /* score: '22.00'*/
      $s4 = "EChilledWindows, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii /* score: '21.00'*/
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s6 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s7 = "Image1.jpg" fullword ascii /* score: '10.00'*/
      $s8 = "image1.jpg" fullword wide /* score: '10.00'*/
      $s9 = "kyo-tux-aeon-system-windows%20(1).ico" fullword wide /* score: '10.00'*/
      $s10 = "EYej;9U" fullword ascii /* score: '9.00'*/
      $s11 = "* c>o\"" fullword ascii /* score: '9.00'*/
      $s12 = "get_Chilled_Windows" fullword ascii /* score: '9.00'*/
      $s13 = "#%%qmLQ%\"" fullword ascii /* score: '8.00'*/
      $s14 = "+}sSCqUM+ " fullword ascii /* score: '8.00'*/
      $s15 = "ChilledWindows.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s16 = "Vp|J:\"" fullword ascii /* score: '7.00'*/
      $s17 = "Jp[j:\":" fullword ascii /* score: '7.00'*/
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s19 = "Window_KeyDown" fullword ascii /* score: '7.00'*/
      $s20 = "ChilledWindows.Properties" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 13000KB and
      1 of ($x*) and 4 of them
}

