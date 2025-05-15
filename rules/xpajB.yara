/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpapyc4lvk
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpapyc4lvk_xpajB {
   meta:
      description = "tmpapyc4lvk - file xpajB.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "e04c85cd4bffa1f5465ff62c9baf0b29b7b2faddf7362789013fbac8c90268bf"
   strings:
      $s1 = "* L<9PP" fullword ascii /* score: '9.00'*/
      $s2 = "ehbncgall" fullword ascii /* score: '8.00'*/
      $s3 = "bknlcmfc" fullword ascii /* score: '8.00'*/
      $s4 = " True Color " fullword wide /* score: '6.00'*/
      $s5 = " (Microsoft Corp.). Windows" fullword wide /* score: '6.00'*/
      $s6 = " (Microsoft Corp.)." fullword wide /* score: '6.00'*/
      $s7 = "iibelv" fullword ascii /* score: '5.00'*/
      $s8 = "Thua[EQ,/E" fullword ascii /* score: '4.00'*/
      $s9 = "NStE5\\{" fullword ascii /* score: '4.00'*/
      $s10 = "K*UZdFt@?" fullword ascii /* score: '4.00'*/
      $s11 = "2j&WSZfPCJ" fullword ascii /* score: '4.00'*/
      $s12 = ".UtmoH!" fullword ascii /* score: '4.00'*/
      $s13 = " jWWWWWW" fullword ascii /* score: '4.00'*/
      $s14 = "ksio<Gx" fullword ascii /* score: '4.00'*/
      $s15 = "NWdcI2F" fullword ascii /* score: '4.00'*/
      $s16 = "ghudI*|" fullword ascii /* score: '4.00'*/
      $s17 = "%|W:ZGIeFT?" fullword ascii /* score: '4.00'*/
      $s18 = "NwDl]Vc" fullword ascii /* score: '4.00'*/
      $s19 = "E+tVmv?" fullword ascii /* score: '4.00'*/
      $s20 = "dXST\"7}" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

