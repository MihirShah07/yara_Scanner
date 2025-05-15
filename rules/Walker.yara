/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp221l9wjp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp221l9wjp_Walker {
   meta:
      description = "tmp221l9wjp - file Walker.com"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "b87b48dcbf779b06c6ca6491cd31328cf840578d29a6327b7a44f9043ce1eb07"
   strings:
      $s1 = "WALKER V1.00 - This absolutely harmless and selfdestructive program is written by UJHPTTLZ in the city of Istanbul, 1992" fullword ascii /* score: '12.00'*/
      $s2 = "Darkest Avenger" fullword ascii /* score: '9.00'*/
      $s3 = "PSVPSQRVW" fullword ascii /* score: '6.50'*/
      $s4 = "U812 COM " fullword ascii /* score: '4.00'*/
      $s5 = "!_^ZY[X" fullword ascii /* score: '1.00'*/
      $s6 = "It is dedicated to her GROOVE!" fullword ascii /* score: '0.00'*/
      $s7 = "This is not dedicated to Sara Gordon" fullword ascii /* score: '0.00'*/
   condition:
      uint16(0) == 0xcde9 and filesize < 10KB and
      all of them
}

