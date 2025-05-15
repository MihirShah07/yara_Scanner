/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpjbcgd41w
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpjbcgd41w_Mantas {
   meta:
      description = "tmpjbcgd41w - file Mantas.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "7b5dec6a48ee2114c3056f4ccb6935f3e7418ef0b0bc4a58931f2c80fc94d705"
   strings:
      $s1 = "crexecomjpgm" fullword ascii /* score: '19.00'*/
      $s2 = "GetLa>A" fullword ascii /* score: '9.00'*/
      $s3 = "%&'()*4567" fullword ascii /* score: '9.00'*/ /* hex encoded string 'Eg' */
      $s4 = "gif%s\\%s*.*," fullword ascii /* score: '6.50'*/
      $s5 = "me error " fullword ascii /* score: '6.00'*/
      $s6 = "gnucld" fullword ascii /* score: '5.00'*/
      $s7 = "/'runti" fullword ascii /* score: '4.00'*/
      $s8 = "MANTASu" fullword ascii /* score: '4.00'*/
      $s9 = "cubV6ld" fullword ascii /* score: '4.00'*/
      $s10 = "gMKeyb" fullword ascii /* score: '4.00'*/
      $s11 = "desc+8F@" fullword ascii /* score: '4.00'*/
      $s12 = "terCPInfo" fullword ascii /* score: '4.00'*/
      $s13 = "SizeofResour" fullword ascii /* score: '4.00'*/
      $s14 = "}argu(s_02f" fullword ascii /* score: '4.00'*/
      $s15 = "g 5pur+virtu!" fullword ascii /* score: '4.00'*/
      $s16 = ":CDEFGHIJS" fullword ascii /* score: '4.00'*/
      $s17 = "XYZcdefghijstuvw" fullword ascii /* score: '4.00'*/
      $s18 = "CloseHaVm5vl7K" fullword ascii /* score: '4.00'*/
      $s19 = "WideChw" fullword ascii /* score: '4.00'*/
      $s20 = "ModulFNam" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

