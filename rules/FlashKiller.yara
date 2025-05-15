/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmprwfjaafa
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule FlashKiller {
   meta:
      description = "tmprwfjaafa - file FlashKiller.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "353df4f186c06a626373b0978d15ec6357510fd0d4ac54b63217b37142ab52d3"
   strings:
      $s1 = "0)0@0X0a0" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 10KB and
      all of them
}

