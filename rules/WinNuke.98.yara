/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_kchqzay
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule WinNuke_98 {
   meta:
      description = "tmp_kchqzay - file WinNuke.98.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2f1f93ede80502d153e301baf9b7f68e7c7a9344cfa90cfae396aac17e81ce5a"
   strings:
      $s1 = "C:\\AUTOEXEC.BAT" fullword wide /* score: '28.00'*/
      $s2 = "WinNuke98.exe" fullword wide /* score: '22.00'*/
      $s3 = "http://www.hackerworld.com/nuke.html" fullword ascii /* score: '17.00'*/
      $s4 = "@*\\AC:\\Program Files\\DevStudio\\VB\\WinNuke 98 Attacking.vbp" fullword wide /* score: '17.00'*/
      $s5 = "DEL *.DLL" fullword wide /* score: '17.00'*/
      $s6 = "DEL *.EXE" fullword wide /* score: '16.00'*/
      $s7 = "DEL *.SYS" fullword wide /* score: '16.00'*/
      $s8 = "DEL *.COM" fullword wide /* score: '15.00'*/
      $s9 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii /* score: '13.00'*/
      $s10 = "Command1_Click" fullword ascii /* score: '12.00'*/
      $s11 = "Choose Port :" fullword ascii /* score: '7.00'*/
      $s12 = "WinNuke Attacking Port Successfully" fullword ascii /* score: '7.00'*/
      $s13 = "IP Address :" fullword ascii /* score: '7.00'*/
      $s14 = "WinNuke98" fullword wide /* score: '5.00'*/
      $s15 = "Frame2" fullword ascii /* score: '5.00'*/
      $s16 = "Project1" fullword ascii /* score: '5.00'*/
      $s17 = " Please Click OK Return to WinNuke" fullword ascii /* score: '4.00'*/
      $s18 = "Nuke Attack" fullword ascii /* score: '4.00'*/
      $s19 = "optRestart" fullword ascii /* score: '4.00'*/
      $s20 = "Form_Unload" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

