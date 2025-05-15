/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp59edxe9s
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp59edxe9s_NJRat {
   meta:
      description = "tmp59edxe9s - file NJRat.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "7a84dd83f4f00cf0723b76a6a56587bdce6d57bd8024cc9c55565a442806cf69"
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide /* score: '42.00'*/
      $s2 = "Execute ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '26.00'*/
      $s3 = "WindowsServices.exe" fullword wide /* score: '25.00'*/
      $s4 = "processhacker" fullword wide /* PEStudio Blacklist: strings */ /* score: '24.00'*/
      $s5 = "Stub.exe" fullword ascii /* score: '22.00'*/
      $s6 = "Tools.exe" fullword wide /* score: '22.00'*/
      $s7 = "Execute ERROR " fullword wide /* score: '21.00'*/
      $s8 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s9 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide /* score: '18.00'*/
      $s10 = "Download ERROR" fullword wide /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s11 = "Executed As " fullword wide /* score: '18.00'*/
      $s12 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s13 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s14 = "CsAntiProcess" fullword ascii /* score: '15.00'*/
      $s15 = "SpyTheSpy" fullword wide /* PEStudio Blacklist: strings */ /* score: '14.00'*/
      $s16 = "procexp" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s17 = "wireshark" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.00'*/
      $s18 = "smsniff" fullword wide /* score: '13.00'*/
      $s19 = "getvalue" fullword wide /* score: '13.00'*/
      $s20 = "startitit2-23969.portmap.host" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 90KB and
      1 of ($x*) and 4 of them
}

