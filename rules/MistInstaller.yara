/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1ephnj5f
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MistInstaller {
   meta:
      description = "tmp1ephnj5f - file MistInstaller.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "323060680fed9a3205e3e36d2b62b7b5b6c6e6245e4555dcc733cf6ef390f41c"
   strings:
      $s1 = "\\system32\\drivers\\mistdrv.sys" fullword wide /* score: '27.00'*/
      $s2 = "MistDriver!DriverEntry: Driver loaded and payload %d loaded on %02d/%02d/%02d on %02d:%02d:%02d" fullword ascii /* score: '19.00'*/
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
      $s4 = "MistDriver!DriverEntry: ZwReadFile failed with code 0x%x" fullword ascii /* score: '13.00'*/
      $s5 = "Initialization failed. Code -76." fullword wide /* score: '13.00'*/
      $s6 = "Initialization failed. Code -1." fullword wide /* score: '13.00'*/
      $s7 = "Initialization failed. Code -2." fullword wide /* score: '13.00'*/
      $s8 = "Initialization failed. Code -59." fullword wide /* score: '13.00'*/
      $s9 = "MistDriver!OnPostFilterWrite: Overwriting file %wZ with garbage" fullword ascii /* score: '12.00'*/
      $s10 = "Mist Kernel Driver" fullword wide /* score: '12.00'*/
      $s11 = "MistDriver!DriverEntry: ZwWriteFile2 failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s12 = "MistDriver!DriverEntry: FltStartFiltering failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s13 = "MistDriver!DriverEntry: FltRegisterFilter failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s14 = "MistDriver!DriverEntry: ZwWriteFile1 failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s15 = "MistDriver!DriverEntry: ZwCreateFile failed with code 0x%x" fullword ascii /* score: '10.00'*/
      $s16 = "MistDriver!OnFilterUnload: Driver unloaded" fullword ascii /* score: '10.00'*/
      $s17 = "System\\CurrentControlSet\\Services\\mistdrv\\Instances" fullword wide /* score: '10.00'*/
      $s18 = "System\\CurrentControlSet\\Services\\mistdrv\\Instances\\DefInst" fullword wide /* score: '10.00'*/
      $s19 = "mistdrv" fullword wide /* score: '8.00'*/
      $s20 = "@*.TXT" fullword wide /* score: '8.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

