/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpj7lxafbw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule CookieClickerHack {
   meta:
      description = "tmpj7lxafbw - file CookieClickerHack.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "13adae722719839af8102f98730f3af1c5a56b58069bfce8995acd2123628401"
   strings:
      $x1 = "C:\\Users\\boris\\documents\\visual studio 2017\\Projects\\CookieClicker_Hack2017\\CookieClicker_Hack2017\\obj\\Debug\\CookieCli" ascii /* score: '33.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "C:\\Users\\boris\\documents\\visual studio 2017\\Projects\\CookieClicker_Hack2017\\CookieClicker_Hack2017\\obj\\Debug\\CookieCli" ascii /* score: '26.00'*/
      $s4 = "CookieClicker_Hack2017.exe" fullword wide /* score: '22.00'*/
      $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s6 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s7 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s8 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s9 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s10 = "017.pdb" fullword ascii /* score: '11.00'*/
      $s11 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s12 = "get_attackstart6" fullword ascii /* score: '9.00'*/
      $s13 = "get_attacjstart5" fullword ascii /* score: '9.00'*/
      $s14 = "get_attackstart4" fullword ascii /* score: '9.00'*/
      $s15 = "get_attackstart2" fullword ascii /* score: '9.00'*/
      $s16 = "!!!!777333999XXXOOOOCCC" fullword ascii /* score: '9.00'*/
      $s17 = "!!!!bbb___444^^^SSSSKKKIII" fullword ascii /* score: '9.00'*/
      $s18 = "get_attackstart7" fullword ascii /* score: '9.00'*/
      $s19 = "get_attackstart3" fullword ascii /* score: '9.00'*/
      $s20 = "get_attackstart" fullword ascii /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      1 of ($x*) and 4 of them
}

