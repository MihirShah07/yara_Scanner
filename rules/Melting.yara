/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpkibl02qy
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpkibl02qy_Melting {
   meta:
      description = "tmpkibl02qy - file Melting.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "92a284981c7ca33f1af45ce61738479fbcbb5a4111f5498e2cb54931c8a36c76"
   strings:
      $x1 = "C:\\Users\\Domas\\Desktop\\ScreenMelter\\x64\\Release\\ScreenMelter.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s4 = "ScreenMelter" fullword wide /* score: '4.00'*/
      $s5 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s6 = "      </requestedPrivileges>" fullword ascii /* score: '2.00'*/
      $s7 = "      <requestedPrivileges>" fullword ascii /* score: '2.00'*/
      $s8 = " H3E H3E" fullword ascii /* score: '1.00'*/
      $s9 = "u0HcH<H" fullword ascii /* score: '1.00'*/
      $s10 = ">RichNK" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      1 of ($x*) and all of them
}

