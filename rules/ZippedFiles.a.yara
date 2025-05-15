/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpleenlicx
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ZippedFiles_a {
   meta:
      description = "tmpleenlicx - file ZippedFiles.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "8f533a5adb18c8e02779636e9d7dbb4a6cf13e4f60ee435b9afc3504b308d68a"
   strings:
      $s1 = "Explore.exe" fullword ascii /* score: '22.00'*/
      $s2 = "_setup.exe" fullword ascii /* score: '19.00'*/
      $s3 = "zipped_files.exe" fullword ascii /* score: '19.00'*/
      $s4 = "OnExecuteMacro" fullword ascii /* score: '18.00'*/
      $s5 = "c:\\zipped_files.zip" fullword ascii /* score: '16.00'*/
      $s6 = "Cannot drag a form\"An error returned from DDE  ($0%x)/DDE Error - conversation not established ($0%x)0Error occurred when DDE r" wide /* score: '11.00'*/
      $s7 = "Bits index out of range/Menu '%s' is already being used by another form" fullword wide /* score: '10.00'*/
      $s8 = "netscan" fullword ascii /* score: '9.00'*/
      $s9 = "mainfrm" fullword ascii /* score: '8.00'*/
      $s10 = "TThread8" fullword ascii /* score: '8.00'*/
      $s11 = "vvirusutil" fullword ascii /* score: '8.00'*/
      $s12 = "pmainfrm" fullword ascii /* score: '8.00'*/
      $s13 = "mapiutils" fullword ascii /* score: '8.00'*/
      $s14 = "EDdeError" fullword ascii /* score: '7.00'*/
      $s15 = "Service %s" fullword ascii /* score: '7.00'*/
      $s16 = ":$:0:4:D:L:P:T:X:\\:`:d:h:l:z:" fullword ascii /* score: '7.00'*/
      $s17 = ":(:8:D:H:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii /* score: '7.00'*/
      $s18 = " scandir" fullword ascii /* score: '7.00'*/
      $s19 = "DdeServiceh" fullword ascii /* score: '7.00'*/
      $s20 = "TVirusThread" fullword ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

