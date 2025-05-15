/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpx444k5n6
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpx444k5n6_Fantom {
   meta:
      description = "tmpx444k5n6 - file Fantom.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "f4234a501edcd30d3bc15c983692c9450383b73bdd310059405c5e3a43cc730b"
   strings:
      $s1 = "criticalupdate01.exe" fullword wide /* score: '18.00'*/
      $s2 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s4 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s5 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s7 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii /* score: '6.50'*/
      $s8 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s9 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s10 = " Class Hierarchy Descriptor'" fullword ascii /* score: '6.00'*/
      $s11 = " Base Class Descriptor at (" fullword ascii /* score: '6.00'*/
      $s12 = " Complete Object Locator'" fullword ascii /* score: '5.00'*/
      $s13 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '5.00'*/
      $s14 = " -Cp}RRd" fullword ascii /* score: '5.00'*/
      $s15 = "system critical updates" fullword wide /* score: '5.00'*/
      $s16 = " delete[]" fullword ascii /* score: '4.00'*/
      $s17 = "gaYC8\\%v" fullword ascii /* score: '4.00'*/
      $s18 = "ZBZAB}w%" fullword ascii /* score: '4.00'*/
      $s19 = "wTVQ/u&'" fullword ascii /* score: '4.00'*/
      $s20 = "!yOXcX!a" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

