/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpv_or7l5w
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ViraLock {
   meta:
      description = "tmpv_or7l5w - file ViraLock.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "418395efd269bc6534e02c92cb2c568631ada6e54bc55ade4e4a5986605ff786"
   strings:
      $s1 = "y%X:\"d" fullword ascii /* score: '7.00'*/
      $s2 = "lDUwLDEw<<" fullword ascii /* score: '4.00'*/
      $s3 = "jARj%_-" fullword ascii /* score: '4.00'*/
      $s4 = "YYFTLegD" fullword ascii /* score: '4.00'*/
      $s5 = "MwdT}G$\\Mw" fullword ascii /* score: '4.00'*/
      $s6 = "JiBr%_-" fullword ascii /* score: '4.00'*/
      $s7 = "kIbyZ:`XA0y{{9RiB*HH" fullword ascii /* score: '4.00'*/
      $s8 = "EwlT}w4\\Ew<TM" fullword ascii /* score: '4.00'*/
      $s9 = "BiBbhXY(y{{1" fullword ascii /* score: '4.00'*/
      $s10 = "YbyZ:hXI(qck" fullword ascii /* score: '4.00'*/
      $s11 = "EBFiD3~" fullword ascii /* score: '4.00'*/
      $s12 = "R6BRQfut9\"M-B" fullword ascii /* score: '4.00'*/
      $s13 = "w$TEwdT}w" fullword ascii /* score: '4.00'*/
      $s14 = "P\\f;u]dJzvtlX" fullword ascii /* score: '4.00'*/
      $s15 = "<uOtDMwt\\uw" fullword ascii /* score: '4.00'*/
      $s16 = "o,\\}gddEw4\\}G<\\}" fullword ascii /* score: '4.00'*/
      $s17 = "Hacka:aJ20@" fullword ascii /* score: '4.00'*/
      $s18 = "LDEOD\\uw" fullword ascii /* score: '4.00'*/
      $s19 = "MCIW5T]" fullword ascii /* score: '4.00'*/
      $s20 = "XnlW>G}i" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

