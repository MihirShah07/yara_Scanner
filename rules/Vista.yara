/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp6iezxh7p
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp6iezxh7p_Vista {
   meta:
      description = "tmp6iezxh7p - file Vista.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "6680317e6eaa04315b47aaadd986262cd485c8a4bd843902f4c779c858a3e31b"
   strings:
      $s1 = "vista.exe" fullword wide /* score: '22.00'*/
      $s2 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s4 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s5 = "RJLLOGO" fullword wide /* score: '11.50'*/
      $s6 = "x||||||" fullword ascii /* reversed goodware string '||||||x' */ /* score: '11.00'*/
      $s7 = "Download more harmless pranks from our website" fullword wide /* score: '10.00'*/
      $s8 = "{Co>DlLn^+f" fullword ascii /* score: '9.00'*/
      $s9 = "A gag that fakes a Windows Vista upgrade" fullword wide /* score: '9.00'*/
      $s10 = "%dKKAY%W" fullword ascii /* score: '8.00'*/
      $s11 = "zsconal" fullword ascii /* score: '8.00'*/
      $s12 = "hhbkkes" fullword ascii /* score: '8.00'*/
      $s13 = "&*Mu:\"3" fullword ascii /* score: '7.00'*/
      $s14 = "iKM.uoj;x" fullword ascii /* score: '7.00'*/
      $s15 = "K:\"T&T" fullword ascii /* score: '7.00'*/
      $s16 = "8cMDafR^z" fullword ascii /* score: '7.00'*/
      $s17 = "RZCOMMON_ABORT" fullword wide /* score: '7.00'*/
      $s18 = "RZCOMMON_ALL" fullword wide /* score: '7.00'*/
      $s19 = "RZCOMMON_CHECKBOX_CHECKED" fullword wide /* score: '7.00'*/
      $s20 = "RZCOMMON_CHECKBOX_GRAYED" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

