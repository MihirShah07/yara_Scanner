/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp0ux_3vba
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp0ux_3vba_Silver {
   meta:
      description = "tmp0ux_3vba - file Silver.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1772928750d316f1046f5e83a73fa3e121686ccfebdca9496e5a62c2c5af23d4"
   strings:
      $s1 = "bncTsj2" fullword ascii /* score: '5.00'*/
      $s2 = "sghf=\\" fullword ascii /* score: '4.00'*/
      $s3 = "uyrix]9H" fullword ascii /* score: '4.00'*/
      $s4 = "BNMJL0q" fullword ascii /* score: '4.00'*/
      $s5 = "Exxw>H>" fullword ascii /* score: '4.00'*/
      $s6 = "n2M|M3Wn" fullword ascii /* score: '1.00'*/
      $s7 = "?$b-v(" fullword ascii /* score: '1.00'*/
      $s8 = "5V`|93?W" fullword ascii /* score: '1.00'*/
      $s9 = "K`_+9a2" fullword ascii /* score: '1.00'*/
      $s10 = "W1`9PO" fullword ascii /* score: '1.00'*/
      $s11 = "&=EQog" fullword ascii /* score: '1.00'*/
      $s12 = "/6.r*a" fullword ascii /* score: '1.00'*/
      $s13 = ")c(|\\z&p" fullword ascii /* score: '1.00'*/
      $s14 = "AmNFSk" fullword ascii /* score: '1.00'*/
      $s15 = "#9)0bJ" fullword ascii /* score: '1.00'*/
      $s16 = "Shj;N^k" fullword ascii /* score: '1.00'*/
      $s17 = "`Q{ANE" fullword ascii /* score: '1.00'*/
      $s18 = "sm')JzpD" fullword ascii /* score: '1.00'*/
      $s19 = "ggR<vX" fullword ascii /* score: '1.00'*/
      $s20 = "\"+k+}q" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

