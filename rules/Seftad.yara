/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmprzez9kcl
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmprzez9kcl_Seftad {
   meta:
      description = "tmprzez9kcl - file Seftad.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2ebe23ba9897d9c127b9c0a737ba63af8d0bcd76ec866610cc0b5de2f62b87bd"
   strings:
      $s1 = " CorExitProcess" fullword ascii /* score: '17.00'*/
      $s2 = "lead to inevitable data loss !!!" fullword ascii /* score: '13.00'*/
      $s3 = "with its help your sign-on password will be generated." fullword ascii /* score: '12.00'*/
      $s4 = "Browse www.safe-data.ru to get an access to your system and files." fullword ascii /* score: '12.00'*/
      $s5 = "Any attempt to restore the drives using other way will " fullword ascii /* score: '11.00'*/
      $s6 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '11.00'*/
      $s7 = "Sector read failed" fullword ascii /* score: '10.00'*/
      $s8 = "All the hard drives were encrypted." fullword ascii /* score: '9.00'*/
      $s9 = "SELECT * FROM Win32_DiskPartition Where BootPartition = true" fullword wide /* score: '8.00'*/
      $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
      $s11 = "DDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii /* score: '6.50'*/
      $s12 = "$hjmc<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" fullword ascii /* score: '6.00'*/
      $s13 = "Please remember Your ID: 773923, " fullword ascii /* score: '4.00'*/
      $s14 = "uTVWh%7@" fullword ascii /* score: '4.00'*/
      $s15 = "Your PC is blocked." fullword ascii /* score: '4.00'*/
      $s16 = "Missing boot code" fullword ascii /* score: '4.00'*/
      $s17 = "  </trustInfo>" fullword ascii /* score: '4.00'*/
      $s18 = "DDINGX" fullword ascii /* score: '3.50'*/
      $s19 = "      </requestedPrivileges>" fullword ascii /* score: '2.00'*/
      $s20 = "      <requestedPrivileges>" fullword ascii /* score: '2.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

