/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpwxgyfva_
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule EternalRocks {
   meta:
      description = "tmpwxgyfva_ - file EternalRocks.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"
   strings:
      $s1 = "EternalRocks.exe" fullword wide /* score: '22.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s3 = "sTargetIP" fullword ascii /* score: '14.00'*/
      $s4 = "EVENT_TRIGGER_AT_LOGON" fullword ascii /* score: '12.00'*/
      $s5 = "RunOnlyIfLoggedOn" fullword ascii /* score: '12.00'*/
      $s6 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s7 = "EternalRocks.shadowbrokers.zip" fullword ascii /* score: '10.00'*/
      $s8 = "* *&*K*S*\\*b*m*" fullword ascii /* score: '9.00'*/
      $s9 = "PSH_USEHBMHEADER" fullword ascii /* score: '9.00'*/
      $s10 = "%%%/%7%F%N%Y%^%d%l%w%" fullword ascii /* score: '8.00'*/
      $s11 = " Use LocalHeaderSignature instead" fullword ascii /* score: '8.00'*/
      $s12 = "P\\+t\"E:\"zq" fullword ascii /* score: '7.00'*/
      $s13 = "PSH_HASHELP" fullword ascii /* score: '7.00'*/
      $s14 = "EVENT_TRIGGER_AT_SYSTEMSTART" fullword ascii /* score: '7.00'*/
      $s15 = "ConfuserEx v1.0.0" fullword ascii /* score: '7.00'*/
      $s16 = "1aV.kOu>e" fullword ascii /* score: '7.00'*/
      $s17 = "PSH_RTLREADING" fullword ascii /* score: '7.00'*/
      $s18 = "OnSystemStart" fullword ascii /* score: '7.00'*/
      $s19 = "VSe.uiW}" fullword ascii /* score: '7.00'*/
      $s20 = "RunDaily" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 15000KB and
      8 of them
}

