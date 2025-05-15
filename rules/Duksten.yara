/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpxzj264ar
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpxzj264ar_Duksten {
   meta:
      description = "tmpxzj264ar - file Duksten.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "caec6e664b3cff5717dd2efea8dcd8715abdcfe7f611456be7009771f22a8f50"
   strings:
      $s1 = "ICONO1" fullword wide /* score: '2.00'*/
      $s2 = ".````````" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      all of them
}

