/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmployomvnn
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule PCToaster {
   meta:
      description = "tmployomvnn - file PCToaster.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "85a58aa96dccd94316a34608ba996656a22c8158d5156b6e454d9d69e6ff38c3"
   strings:
      $s1 = "http://java.com/download" fullword ascii /* score: '23.00'*/
      $s2 = "bin\\javaw.exe" fullword ascii /* score: '18.00'*/
      $s3 = "CmdLine:" fullword ascii /* score: '12.00'*/
      $s4 = "<requestedExecutionLevel level=\"highestAvailable\"   uiAccess=\"False\" />" fullword ascii /* score: '11.00'*/
      $s5 = "pctoaster1/scr.txt+N" fullword ascii /* score: '11.00'*/
      $s6 = "Requested %d MB / %d%%, Available: %d MB, Heap size: %d MB" fullword ascii /* score: '11.00'*/
      $s7 = "scr.txt+N" fullword ascii /* score: '11.00'*/
      $s8 = "Heap %s:" fullword ascii /* score: '9.50'*/
      $s9 = "Resource %d:" fullword ascii /* score: '9.50'*/
      $s10 = "xshoyui" fullword ascii /* score: '8.00'*/
      $s11 = "scr.txtPK" fullword ascii /* score: '8.00'*/
      $s12 = "pctoaster1/scr.txtPK" fullword ascii /* score: '8.00'*/
      $s13 = "Error msg:" fullword ascii /* score: '7.00'*/
      $s14 = "Startup error message not defined." fullword ascii /* score: '7.00'*/
      $s15 = "Instance already exists." fullword ascii /* score: '7.00'*/
      $s16 = "The registry refers to a nonexistent Java Runtime Environment installation or the runtime is corrupted." fullword ascii /* score: '7.00'*/
      $s17 = "Reduced %d MB heap size to 32-bit maximum %d MB" fullword ascii /* score: '7.00'*/
      $s18 = "SOFTWARE\\IBM\\Java2 Runtime Environment" fullword ascii /* score: '7.00'*/
      $s19 = "Runtime used:" fullword ascii /* score: '7.00'*/
      $s20 = "appendToPathVar failed." fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

