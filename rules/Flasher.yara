/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpluk3hwdi
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpluk3hwdi_Flasher {
   meta:
      description = "tmpluk3hwdi - file Flasher.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "30676ad5dc94c3fec3d77d87439b2bf0a1aaa7f01900b68002a06f11caee9ce6"
   strings:
      $s1 = "flasher.exe" fullword wide /* score: '22.00'*/
      $s2 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "support@rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s4 = "If you do not specify a command line image, the RJL logo will flash." fullword wide /* score: '17.00'*/
      $s5 = "flasher.exe [seconds to delay] [path to image file]" fullword wide /* score: '14.00'*/
      $s6 = "flasher" fullword wide /* score: '8.00'*/
      $s7 = "RZCOMMON_ABORT" fullword wide /* score: '7.00'*/
      $s8 = "RZCOMMON_ALL" fullword wide /* score: '7.00'*/
      $s9 = "RZCOMMON_CHECKBOX_CHECKED" fullword wide /* score: '7.00'*/
      $s10 = "RZCOMMON_CHECKBOX_GRAYED" fullword wide /* score: '7.00'*/
      $s11 = "RZCOMMON_CHECKBOX_UNCHECKED" fullword wide /* score: '7.00'*/
      $s12 = "RZCOMMON_CLOSE" fullword wide /* score: '7.00'*/
      $s13 = "RZCOMMON_HELP" fullword wide /* score: '7.00'*/
      $s14 = "RZCOMMON_IGNORE" fullword wide /* score: '7.00'*/
      $s15 = "RZCOMMON_NO" fullword wide /* score: '7.00'*/
      $s16 = "RZCOMMON_OK" fullword wide /* score: '7.00'*/
      $s17 = "RZCOMMON_RADIOBUTTON_CHECKED" fullword wide /* score: '7.00'*/
      $s18 = "RZCOMMON_RADIOBUTTON_UNCHECKED" fullword wide /* score: '7.00'*/
      $s19 = "RZCOMMON_RETRY" fullword wide /* score: '7.00'*/
      $s20 = "RZCOMMON_YES" fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

