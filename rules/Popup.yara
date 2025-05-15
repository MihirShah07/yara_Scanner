/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp71en7pjq
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp71en7pjq_Popup {
   meta:
      description = "tmp71en7pjq - file Popup.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "f8f7b5f20ca57c61df6dc8ff49f2f5f90276a378ec17397249fdc099a6e1dcd8"
   strings:
      $s1 = "popup.exe" fullword wide /* score: '22.00'*/
      $s2 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "support@rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s4 = "TFRMCONFIG" fullword wide /* score: '9.50'*/
      $s5 = "* 8|)Z" fullword ascii /* score: '9.00'*/
      $s6 = "Fake popup ad that is customizable" fullword wide /* score: '9.00'*/
      $s7 = "RZBTNEDT_LOOKUP" fullword wide /* score: '7.00'*/
      $s8 = "RZCOMMON_ABORT" fullword wide /* score: '7.00'*/
      $s9 = "RZCOMMON_ALL" fullword wide /* score: '7.00'*/
      $s10 = "RZCOMMON_CHECKBOX_CHECKED" fullword wide /* score: '7.00'*/
      $s11 = "RZCOMMON_CHECKBOX_GRAYED" fullword wide /* score: '7.00'*/
      $s12 = "RZCOMMON_CHECKBOX_UNCHECKED" fullword wide /* score: '7.00'*/
      $s13 = "RZCOMMON_CLOSE" fullword wide /* score: '7.00'*/
      $s14 = "RZCOMMON_HELP" fullword wide /* score: '7.00'*/
      $s15 = "RZCOMMON_IGNORE" fullword wide /* score: '7.00'*/
      $s16 = "RZCOMMON_NO" fullword wide /* score: '7.00'*/
      $s17 = "RZCOMMON_OK" fullword wide /* score: '7.00'*/
      $s18 = "RZCOMMON_RADIOBUTTON_CHECKED" fullword wide /* score: '7.00'*/
      $s19 = "RZCOMMON_RADIOBUTTON_UNCHECKED" fullword wide /* score: '7.00'*/
      $s20 = "RZCOMMON_RETRY" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

