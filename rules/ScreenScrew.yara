/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpn8ypnnlv
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ScreenScrew {
   meta:
      description = "tmpn8ypnnlv - file ScreenScrew.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "e03520794f00fb39ef3cfff012f72a5d03c60f89de28dbe69016f6ed151b5338"
   strings:
      $s1 = "screenscrew.exe" fullword wide /* score: '22.00'*/
      $s2 = "support@rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s4 = ";!\"^33$." fullword ascii /* score: '9.00'*/ /* hex encoded string '3' */
      $s5 = "TFRMCOPYRIGHT" fullword wide /* score: '6.50'*/
      $s6 = "TFRMSPLASH" fullword wide /* score: '6.50'*/
      $s7 = "GdhxEcvn" fullword ascii /* score: '4.00'*/
      $s8 = "HtiH34oa" fullword ascii /* score: '4.00'*/
      $s9 = "VS %I/" fullword ascii /* score: '4.00'*/
      $s10 = "bVYLG]&" fullword ascii /* score: '4.00'*/
      $s11 = "RBzjr=>" fullword ascii /* score: '4.00'*/
      $s12 = ";p-=\\.gAs" fullword ascii /* score: '4.00'*/
      $s13 = "%dKHS!Qz&" fullword ascii /* score: '4.00'*/
      $s14 = "JeaP=zAWd" fullword ascii /* score: '4.00'*/
      $s15 = "=xcmN,>,L" fullword ascii /* score: '4.00'*/
      $s16 = "XdT~kDJy!" fullword ascii /* score: '4.00'*/
      $s17 = "hLTW&rCl" fullword ascii /* score: '4.00'*/
      $s18 = "kSWD.U%z" fullword ascii /* score: '4.00'*/
      $s19 = "HRsz\"~" fullword ascii /* score: '4.00'*/
      $s20 = "F.RCx#" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

