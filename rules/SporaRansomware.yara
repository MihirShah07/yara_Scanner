/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp095z2z56
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule SporaRansomware {
   meta:
      description = "tmp095z2z56 - file SporaRansomware.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "7ad9ed23a91643b517e82ad5740d24eca16bcae21cfe1c0da78ee80e0d1d3f02"
   strings:
      $x1 = "process call create \"cmd.exe /c vssadmin.exe delete shadows /all /quiet & bcdedit.exe /set {default} recoveryenabled no & bcded" wide /* score: '38.00'*/
      $s2 = "/c explorer.exe \"%s\" & type \"%s\" > \"%%tmp%%\\%s\" & start \"%s\" \"%%tmp%%\\%s\"" fullword wide /* score: '23.50'*/
      $s3 = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.exe" fullword wide /* score: '16.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "\\%s.KEY" fullword wide /* score: '13.50'*/
      $s6 = "%s\\%s.KEY" fullword wide /* score: '12.50'*/
      $s7 = "\\%s.LST" fullword wide /* score: '10.50'*/
      $s8 = "%s\\%s.LST" fullword wide /* score: '9.50'*/
      $s9 = "/c \"%s\" /u" fullword wide /* score: '8.00'*/
      $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s11 = "%s%02X%01X-%01X%01X" fullword wide /* score: '5.00'*/
      $s12 = "SUVWj.3" fullword ascii /* score: '4.00'*/
      $s13 = "diGrv\\" fullword ascii /* score: '4.00'*/
      $s14 = "uNUUh~:@" fullword ascii /* score: '4.00'*/
      $s15 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s16 = "      </requestedPrivileges>" fullword ascii /* score: '2.00'*/
      $s17 = "      <requestedPrivileges>" fullword ascii /* score: '2.00'*/
      $s18 = "J3$c/g" fullword ascii /* score: '1.00'*/
      $s19 = "%02hu.%02hu.%04hu|" fullword ascii /* score: '1.00'*/
      $s20 = "{data}" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

