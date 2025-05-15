/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp51l1m5pw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule CrimsonRAT {
   meta:
      description = "tmp51l1m5pw - file CrimsonRAT.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "dc31e710277eac1b125de6f4626765a2684d992147691a33964e368e5f269cba"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s2 = "hbraeiwas.exe" fullword wide /* score: '22.00'*/
      $s3 = "dlrarhsiva.exe" fullword ascii /* score: '22.00'*/
      $s4 = "G:\\hbraeiwas\\hbraeiwas\\obj\\Debug\\hbraeiwas.pdb" fullword ascii /* score: '19.00'*/
      $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s6 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s8 = "My.Computer" fullword ascii /* score: '11.00'*/
      $s9 = "dlrarhsiva.exePK" fullword ascii /* score: '11.00'*/
      $s10 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s11 = "System.Windows.Forms.Form" fullword ascii /* score: '10.00'*/
      $s12 = "mdkhm.zip" fullword wide /* score: '10.00'*/
      $s13 = "get_dlrarhsiva8" fullword ascii /* score: '9.00'*/
      $s14 = "get_apppath" fullword ascii /* score: '9.00'*/
      $s15 = "getWind" fullword ascii /* score: '9.00'*/
      $s16 = "hbraeiwas" fullword wide /* score: '8.00'*/
      $s17 = "dlrarhsiva" fullword wide /* score: '8.00'*/
      $s18 = "m_ThreadStaticValue" fullword ascii /* score: '7.00'*/
      $s19 = "m_MyWebServicesObjectProvider" fullword ascii /* score: '7.00'*/
      $s20 = "hbraeiwas.Resources.resources" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

