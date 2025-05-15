/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp2c79qdmd
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp2c79qdmd_Gas {
   meta:
      description = "tmp2c79qdmd - file Gas.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "da3f40b66cc657ea33dbf547eb05d8d4fb5fb5cf753689d0222039a3292c937a"
   strings:
      $s1 = "Virus.exe" fullword wide /* score: '22.00'*/
      $s2 = "*\\AC:\\@smp@\\Virri.vbp" fullword wide /* score: '17.00'*/
      $s3 = "C:\\VB5\\VB5.OLB" fullword ascii /* score: '13.00'*/
      $s4 = "Something :)" fullword wide /* score: '8.00'*/
      $s5 = "Form_KeyDown" fullword ascii /* score: '7.00'*/
      $s6 = "Ready?" fullword wide /* score: '7.00'*/
      $s7 = "We're Cookin With Gas Now." fullword wide /* score: '6.00'*/
      $s8 = "HScroll1" fullword ascii /* score: '5.00'*/
      $s9 = "Module1" fullword ascii /* score: '5.00'*/
      $s10 = "VScroll1" fullword ascii /* score: '5.00'*/
      $s11 = "Form_Load" fullword ascii /* score: '4.00'*/
      $s12 = "Form_Paint" fullword ascii /* score: '4.00'*/
      $s13 = "Form_Unload" fullword ascii /* score: '4.00'*/
      $s14 = "FastTaskSwitching" fullword ascii /* score: '4.00'*/
      $s15 = "UnloadMode" fullword ascii /* score: '4.00'*/
      $s16 = "Timer1_Timer" fullword ascii /* score: '4.00'*/
      $s17 = "DisableTaskBar" fullword ascii /* score: '4.00'*/
      $s18 = "Timer2_Timer" fullword ascii /* score: '4.00'*/
      $s19 = "EnableTaskBar" fullword ascii /* score: '4.00'*/
      $s20 = "Timer3_Timer" fullword ascii /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      8 of them
}

