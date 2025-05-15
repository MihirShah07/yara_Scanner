/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_wdbgu09
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule NotPetya {
   meta:
      description = "tmp_wdbgu09 - file NotPetya.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "63545fa195488ff51955f09833332b9660d18f8afb16bdf579134661962e548a"
   strings:
      $x1 = "-d C:\\Windows\\System32\\rundll32.exe \"C:\\Windows\\%s\",#1 " fullword wide /* score: '35.50'*/
      $x2 = "process call create \"C:\\Windows\\System32\\rundll32.exe \\\"C:\\Windows\\%s\\\" #1 " fullword wide /* score: '34.50'*/
      $x3 = "C:\\Users\\PC\\documents\\visual studio 2010\\Projects\\NotPetya\\Release\\NotPetya.pdb" fullword ascii /* score: '33.00'*/
      $s4 = "%SystemRoot%\\perfc.dat #1" fullword ascii /* score: '23.00'*/
      $s5 = "%SystemRoot%\\perfc.dat" fullword ascii /* score: '23.00'*/
      $s6 = "shutdown.exe /r /f" fullword wide /* score: '22.00'*/
      $s7 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\" " fullword wide /* score: '22.00'*/
      $s8 = "\\\\.\\pipe\\%ws" fullword wide /* score: '19.00'*/
      $s9 = "dllhost.dat" fullword wide /* score: '19.00'*/
      $s10 = "  One of your disks contains errors and needs to be repaired. This process" fullword ascii /* score: '18.00'*/
      $s11 = "eddddddd" ascii /* reversed goodware string 'ddddddde' */ /* score: '18.00'*/
      $s12 = "u%s \\\\%s -accepteula -s " fullword wide /* score: '17.50'*/
      $s13 = "  WARNING: DO NOT TURN OFF YOUR PC! IF YOU ABORT THIS PROCESS, YOU COULD" fullword ascii /* score: '15.00'*/
      $s14 = "wbem\\wmic.exe" fullword wide /* score: '15.00'*/
      $s15 = "perfc.dat" fullword ascii /* score: '14.00'*/
      $s16 = "schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d" fullword wide /* score: '14.00'*/
      $s17 = " Ooops, your important files are encrypted." fullword ascii /* score: '12.00'*/
      $s18 = "wowsmith123456@posteo.net." fullword wide /* score: '12.00'*/
      $s19 = "Ooops, your important files are encrypted." fullword wide /* score: '12.00'*/
      $s20 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

