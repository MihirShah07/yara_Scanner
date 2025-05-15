/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_ser1s_q
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp_ser1s_q_VeryFun {
   meta:
      description = "tmp_ser1s_q - file VeryFun.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "8b04fda4bee1806587657da6c6147d3e949aa7d11be1eefb8cd6ef0dba76d387"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"*\" processorArchitec" ascii /* score: '26.00'*/
      $s2 = "kernel32.dllD" fullword ascii /* score: '16.00'*/
      $s3 = " publicKeyToken=\"6595b64144ccf1df\"/>" fullword ascii /* score: '13.00'*/
      $s4 = "GetNativeSystemInf" fullword ascii /* score: '12.00'*/
      $s5 = "TmenO:\"" fullword ascii /* score: '10.00'*/
      $s6 = "* AJo2Jqm " fullword ascii /* score: '9.00'*/
      $s7 = "opera?" fullword ascii /* score: '9.00'*/
      $s8 = "alnumsci" fullword ascii /* score: '8.00'*/
      $s9 = "YYYY?2" fullword ascii /* score: '7.00'*/
      $s10 = "&TD:\"R" fullword ascii /* score: '7.00'*/
      $s11 = ";O:\\PnJ" fullword ascii /* score: '7.00'*/
      $s12 = "cBP:\\7" fullword ascii /* score: '7.00'*/
      $s13 = "JPLO7%D~<" fullword ascii /* score: '7.00'*/
      $s14 = "+qRUN$KI2HENnHPY" fullword ascii /* score: '7.00'*/
      $s15 = "ALWFGRP" fullword ascii /* score: '6.50'*/
      $s16 = "VWHYYBY" fullword ascii /* score: '6.50'*/
      $s17 = "DOMMIVFAIT" fullword ascii /* score: '6.50'*/
      $s18 = "=- .;e60" fullword ascii /* score: '5.00'*/
      $s19 = "cntrlv" fullword ascii /* score: '5.00'*/
      $s20 = "dizqdb" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

