/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1_r99brx
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MrsMajor3_0 {
   meta:
      description = "tmp1_r99brx - file MrsMajor3.0.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "4a75f2db1dbd3c1218bb9994b7e1c690c4edd4e0c1a675de8d2a127611173e69"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii /* score: '58.00'*/
      $s2 = " or \"requireAdministrator\" --> <v3:requestedExecutionLevel level=\"requireAdministrator\" /> </v3:requestedPrivileges> </v3:se" ascii /* score: '28.00'*/
      $s3 = "MrsMajor3.0.exe" fullword wide /* score: '19.00'*/
      $s4 = "> <dependency> <dependentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0" ascii /* score: '15.00'*/
      $s5 = "v3=\"urn:schemas-microsoft-com:asm.v3\"> <v3:security> <v3:requestedPrivileges> <!-- level can be \"asInvoker\", \"highestAvaila" ascii /* score: '14.00'*/
      $s6 = "---ttt" fullword ascii /* reversed goodware string 'ttt---' */ /* score: '11.00'*/
      $s7 = "Downloads\\" fullword wide /* score: '10.00'*/
      $s8 = "cessorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /> </dependentAssembly> </dependency> <v3:trustInfo " ascii /* score: '9.00'*/
      $s9 = "Denormal floating-point operand" fullword wide /* score: '9.00'*/
      $s10 = "Invalid floating-point operation" fullword wide /* score: '9.00'*/
      $s11 = "stttpaa" fullword ascii /* score: '8.00'*/
      $s12 = "Memory page error" fullword wide /* score: '7.00'*/
      $s13 = "YZAXAYH" fullword ascii /* score: '6.50'*/
      $s14 = "PYZAXAYH" fullword ascii /* score: '6.50'*/
      $s15 = "PPPPPPH" fullword ascii /* score: '6.50'*/
      $s16 = " inflate 1.2.8 Copyright 1995-2013 Mark Adler " fullword ascii /* score: '6.00'*/
      $s17 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersi" ascii /* score: '6.00'*/
      $s18 = "ajjjpq" fullword ascii /* score: '5.00'*/
      $s19 = "1 -RKNB" fullword ascii /* score: '5.00'*/
      $s20 = "QNlXIF0" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

