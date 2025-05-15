/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp1kuoqhas
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp1kuoqhas_LoveYou {
   meta:
      description = "tmp1kuoqhas - file LoveYou.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1edc8771e2a1a70023fc9ddeb5a6bc950380224b75e8306eb70da8eb80cb5b71"
   strings:
      $s1 = "loveyou.exe" fullword wide /* score: '22.00'*/
      $s2 = "@*\\AC:\\COOLME\\TESTY.VBP" fullword wide /* score: '17.00'*/
      $s3 = "C:\\Program\\Visual Basic\\VB5.OLB" fullword ascii /* score: '13.00'*/
      $s4 = "\\wir.com" fullword wide /* score: '12.00'*/
      $s5 = "PLEASE FUCK MY ASS HARD!" fullword wide /* score: '9.00'*/
      $s6 = "loveyou" fullword wide /* score: '8.00'*/
      $s7 = "I'M STILL WAITING... PUSH THE BUTTON OR ALL DATA ON YOUR HARD DRIVE AND BIOS WILL BE DESTROYED !!!" fullword wide /* score: '8.00'*/
      $s8 = "cmdPlease_MouseMove" fullword ascii /* score: '7.00'*/
      $s9 = "cmdPlease" fullword ascii /* score: '7.00'*/
      $s10 = "PC Fucker: Serious error" fullword wide /* score: '7.00'*/
      $s11 = "BIOS ERROR: NO BIOS FOUND!" fullword wide /* score: '7.00'*/
      $s12 = "Form_Load" fullword ascii /* score: '4.00'*/
      $s13 = "modRegistry" fullword ascii /* score: '4.00'*/
      $s14 = "FindWindowsPath" fullword ascii /* score: '4.00'*/
      $s15 = "tmrMyAss" fullword ascii /* score: '4.00'*/
      $s16 = "EAL BAD. AND YOU'RE NOT GONNA LIKE IT!" fullword ascii /* score: '4.00'*/
      $s17 = "tmrMyAss_Timer" fullword ascii /* score: '4.00'*/
      $s18 = "lblJustPush" fullword ascii /* score: '4.00'*/
      $s19 = "FuckMeHard" fullword ascii /* score: '4.00'*/
      $s20 = "tmrYourAss_Timer" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and
      8 of them
}

