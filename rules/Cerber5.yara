/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_kjnze3z
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp_kjnze3z_Cerber5 {
   meta:
      description = "tmp_kjnze3z - file Cerber5.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "b3e1e9d97d74c416c2a30dd11858789af5554cf2de62f577c13944a19623777d"
   strings:
      $s1 = "PDFWriter.EXE" fullword wide /* score: '22.00'*/
      $s2 = "2, 7, 7, 1" fullword wide /* score: '9.00'*/ /* hex encoded string ''q' */
      $s3 = "?1[88oU:\\w" fullword ascii /* score: '7.00'*/
      $s4 = "U770.DHO" fullword ascii /* score: '7.00'*/
      $s5 = "Combine PDFs" fullword wide /* score: '7.00'*/
      $s6 = "Dbokl76" fullword ascii /* score: '5.00'*/
      $s7 = "v0P- Ke=" fullword ascii /* score: '5.00'*/
      $s8 = " RS+ RV?88e" fullword ascii /* score: '5.00'*/
      $s9 = "vernel32" fullword ascii /* score: '5.00'*/
      $s10 = "N/[aO -" fullword ascii /* score: '5.00'*/
      $s11 = "xsRjunRh" fullword ascii /* score: '4.00'*/
      $s12 = "demuus@yandex.ru0" fullword ascii /* score: '4.00'*/
      $s13 = "r!HyRoDD%" fullword ascii /* score: '4.00'*/
      $s14 = "Saratov1\"0 " fullword ascii /* score: '4.00'*/
      $s15 = "iigc88&" fullword ascii /* score: '4.00'*/
      $s16 = "d. 84 of. 2, ul.Tankistov1" fullword ascii /* score: '4.00'*/
      $s17 = "Jpin.G'j{" fullword ascii /* score: '4.00'*/
      $s18 = "BHrXtf[D" fullword ascii /* score: '4.00'*/
      $s19 = "FhDoC`a" fullword ascii /* score: '4.00'*/
      $s20 = "YESu:3{88" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

