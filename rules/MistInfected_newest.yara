/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpijd2j09m
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MistInfected_newest {
   meta:
      description = "tmpijd2j09m - file MistInfected_newest.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "5f7471c215b433f1b28dd4b328b99362099b6df7cb9e5c1d86a756388e0c7aeb"
   strings:
      $x1 = "C:\\Users\\stroz_000\\OneDrive\\CPPProjs\\MessageBoxHelloWorld\\Release\\MessageBoxHelloWorld.pdb" fullword ascii /* score: '33.00'*/
      $s2 = "\\system32\\drivers\\mistdrv.sys" fullword wide /* score: '27.00'*/
      $s3 = "MistDriver!DriverEntry: Driver loaded and payload %d loaded on %02d/%02d/%02d on %02d:%02d:%02d" fullword ascii /* score: '19.00'*/
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s5 = "VVVVVPVVj" fullword ascii /* base64 encoded string 'UUU=Uc' */ /* score: '14.00'*/
      $s6 = "MistDriver!DriverEntry: ZwReadFile failed with code 0x%x" fullword ascii /* score: '13.00'*/
      $s7 = "MistDriver!OnPostFilterWrite: Overwriting file %wZ with garbage" fullword ascii /* score: '12.00'*/
      $s8 = "Mist Kernel Driver" fullword wide /* score: '12.00'*/
      $s9 = "MistDriver!DriverEntry: ZwWriteFile1 failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s10 = "MistDriver!DriverEntry: ZwWriteFile2 failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s11 = "MistDriver!DriverEntry: ZwCreateFile failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s12 = "MistDriver!DriverEntry: FltRegisterFilter failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s13 = "MistDriver!OnFilterUnload: Driver unloaded" fullword ascii /* score: '10.00'*/
      $s14 = "MistDriver!DriverEntry: FltStartFiltering failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s15 = "System\\CurrentControlSet\\Services\\mistdrv\\Instances" fullword wide /* score: '10.00'*/
      $s16 = "System\\CurrentControlSet\\Services\\mistdrv\\Instances\\DefInst" fullword wide /* score: '10.00'*/
      $s17 = "mistdrv" fullword wide /* score: '8.00'*/
      $s18 = "@*.TXT" fullword wide /* score: '8.00'*/
      $s19 = "MistDriver!OnPreFilterCreate: Disallowing access to %wZ" fullword ascii /* score: '7.00'*/
      $s20 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      1 of ($x*) and 4 of them
}

