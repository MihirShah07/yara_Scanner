/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpy9a6cjko
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Lentin_d {
   meta:
      description = "tmpy9a6cjko - file Lentin.d.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "aa2e8d70654e30cf11e2b57e92cea72a9823a048f75fc9029da04e1e4d8a9810"
   strings:
      $s1 = "www.friendship.com" fullword wide /* score: '21.00'*/
      $s2 = "friendship.scr" fullword wide /* score: '18.00'*/
      $s3 = "ANTIVIR" fullword ascii /* PEStudio Blacklist: strings */ /* score: '11.50'*/
      $s4 = "GetLa{/" fullword ascii /* score: '9.00'*/
      $s5 = "NORTON" fullword ascii /* PEStudio Blacklist: strings */ /* score: '8.50'*/
      $s6 = "RUNRLU32APSm" fullword ascii /* score: '7.00'*/
      $s7 = " attachn" fullword ascii /* score: '6.00'*/
      $s8 = "ime error" fullword ascii /* score: '6.00'*/
      $s9 = "whofii" fullword ascii /* score: '5.00'*/
      $s10 = "mm* 3yy" fullword ascii /* score: '5.00'*/
      $s11 = "tuvwxyz0" fullword ascii /* score: '5.00'*/
      $s12 = "\\*.doc" fullword ascii /* score: '5.00'*/
      $s13 = "MCAFEE" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.50'*/
      $s14 = "irtu!3" fullword ascii /* score: '4.00'*/
      $s15 = "qXXMvLW" fullword ascii /* score: '4.00'*/
      $s16 = "+ABCDEFGHIJKLM" fullword ascii /* score: '4.00'*/
      $s17 = "ytxt<BR>Se" fullword ascii /* score: '4.00'*/
      $s18 = "tMTXk\\`" fullword ascii /* score: '4.00'*/
      $s19 = "4Mtld\\TL4M" fullword ascii /* score: '4.00'*/
      $s20 = "Oword \"" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

