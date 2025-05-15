/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpb26vbdzd
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule YouAreAnIdiot {
   meta:
      description = "tmpb26vbdzd - file YouAreAnIdiot.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1f69810b8fe71e30a8738278adf09dd982f7de0ab9891d296ce7ea61b3fa4f69"
   strings:
      $x1 = "C:\\Users\\KenYue\\documents\\visual studio 2010\\Projects\\YouAreAnIdiot\\YouAreAnIdiot\\obj\\x86\\Debug\\YouAreAnIdiot.pdb" fullword ascii /* score: '33.00'*/
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Windows.Forms.AxH" ascii /* score: '32.00'*/
      $s3 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3azSystem.Windows.Forms.AxH" ascii /* score: '30.00'*/
      $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s5 = "ost+State, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPABj" fullword ascii /* score: '24.00'*/
      $s6 = "YouAreAnIdiot.exe" fullword wide /* score: '22.00'*/
      $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s8 = "4044444474" ascii /* score: '17.00'*/ /* hex encoded string '@DDDt' */
      $s9 = " requestedExecutionLevel " fullword ascii /* score: '16.00'*/
      $s10 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s11 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s12 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s13 = "!System.Windows.Forms.AxHost+State" fullword ascii /* score: '12.00'*/
      $s14 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s15 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s16 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s17 = "            requestedExecutionLevel " fullword ascii /* score: '11.00'*/
      $s18 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s19 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s20 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

