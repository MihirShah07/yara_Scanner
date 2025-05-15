/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp84i68jb9
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Yarner_a {
   meta:
      description = "tmp84i68jb9 - file Yarner.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "c8b59505e578d555976b6176732c1f19fd76860cf465cf1427e1dfa50622e067"
   strings:
      $s1 = "#Incompatible version of WINSOCK.DLL" fullword ascii /* score: '26.00'*/
      $s2 = "notedpad.exe" fullword ascii /* score: '22.00'*/
      $s3 = "yawsetup.exe" fullword wide /* score: '22.00'*/
      $s4 = "http://www.netmastersllc.com" fullword ascii /* score: '21.00'*/
      $s5 = "toad.com" fullword ascii /* score: '21.00'*/
      $s6 = "48C9E7F3,41.254 VS051236.EXE" fullword ascii /* score: '16.00'*/
      $s7 = "01. YAW 2.0 - Unser Dialerwarner in neuer Version" fullword ascii /* score: '15.00'*/
      $s8 = "Host Lookup Failed" fullword ascii /* score: '15.00'*/
      $s9 = "TNMUUProcessor" fullword ascii /* score: '15.00'*/
      $s10 = "217.5.234.178" fullword ascii /* score: '14.00'*/ /* hex encoded string '!u#Ax' */
      $s11 = "glich Fehler beim Lesen von %s%s%s: %s" fullword wide /* score: '13.50'*/
      $s12 = "Email   info@netmastersllc.com" fullword ascii /* score: '13.00'*/
      $s13 = "PostMessage.Body.Strings" fullword ascii /* score: '12.00'*/
      $s14 = "OnHeaderIncompleteh'A" fullword ascii /* score: '12.00'*/
      $s15 = "Error creating Data Connection" fullword ascii /* score: '12.00'*/
      $s16 = "THeaderInComplete" fullword ascii /* score: '12.00'*/
      $s17 = "PostMessage.Subject" fullword ascii /* score: '12.00'*/
      $s18 = "!Operation not supported on socket" fullword ascii /* score: '12.00'*/
      $s19 = " Non-Authoritative Host not found" fullword ascii /* score: '12.00'*/
      $s20 = "HViele haben ihn und viele moegen ihn - unseren Dialerwarner YAW. YAW ist" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

