/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpgwovy3zs
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule CryptoWall {
   meta:
      description = "tmpgwovy3zs - file CryptoWall.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "e036d68b8f8b7afc6c8b6252876e1e290f11a26d4ad18ac6f310662845b2c734"
   strings:
      $s1 = "C:\\out.png" fullword wide /* score: '13.00'*/
      $s2 = "HELP_DECRYPT.TXT" fullword wide /* score: '13.00'*/
      $s3 = "eyea-a&u\"" fullword ascii /* score: '9.00'*/
      $s4 = "HELP_DECRYPT.URL" fullword wide /* score: '9.00'*/
      $s5 = "HELP_DECRYPT.PNG" fullword wide /* score: '9.00'*/
      $s6 = "HELP_DECRYPT.HTML" fullword wide /* score: '6.00'*/
      $s7 = "'%gv%'" fullword ascii /* score: '5.00'*/
      $s8 = " AtUawwBW" fullword ascii /* score: '4.00'*/
      $s9 = "ababc#9" fullword ascii /* score: '4.00'*/
      $s10 = "kKoCjb@" fullword ascii /* score: '4.00'*/
      $s11 = "afZeV!%" fullword ascii /* score: '4.00'*/
      $s12 = "CjUC1 @" fullword ascii /* score: '4.00'*/
      $s13 = "6hehbz4fp" fullword ascii /* score: '4.00'*/
      $s14 = "sFkA1np" fullword ascii /* score: '4.00'*/
      $s15 = "A#.NHQ`A" fullword ascii /* score: '4.00'*/
      $s16 = "!McQchmd" fullword ascii /* score: '4.00'*/
      $s17 = "x9jSeq@gP" fullword ascii /* score: '4.00'*/
      $s18 = "oWaTl 3." fullword wide /* score: '4.00'*/
      $s19 = "E(|\"U-" fullword ascii /* score: '1.00'*/
      $s20 = "s))?1?1" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

