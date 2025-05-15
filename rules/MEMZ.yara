/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp2sm8fun2
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp2sm8fun2_MEMZ {
   meta:
      description = "tmp2sm8fun2 - file MEMZ.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "a3d5715a81f2fbeb5f76c88c9c21eeee87142909716472f911ff6950c790c24d"
   strings:
      $s1 = "http://answers.microsoft.com/en-us/protect/forum/protect_other-protect_scanning/memz-malwarevirus-trojan-completely-destroying/2" ascii /* score: '22.00'*/
      $s2 = "http://answers.microsoft.com/en-us/protect/forum/protect_other-protect_scanning/memz-malwarevirus-trojan-completely-destroying/2" ascii /* score: '22.00'*/
      $s3 = "http://google.co.ck/search?q=virus.exe" fullword ascii /* score: '22.00'*/
      $s4 = "http://play.clubpenguin.com" fullword ascii /* score: '21.00'*/
      $s5 = "http://softonic.com" fullword ascii /* score: '21.00'*/
      $s6 = "http://pcoptimizerpro.com" fullword ascii /* score: '21.00'*/
      $s7 = "597a673b6b45" ascii /* score: '17.00'*/ /* hex encoded string 'Yzg;kE' */
      $s8 = "http://motherboard.vice.com/read/watch-this-malware-turn-a-computer-into-a-digital-hellscape" fullword ascii /* score: '16.00'*/
      $s9 = "http://google.co.ck/search?q=what+happens+if+you+delete+system32" fullword ascii /* score: '15.00'*/
      $s10 = "STILL EXECUTE IT?" fullword ascii /* score: '14.00'*/
      $s11 = "The software you just executed is considered malware." fullword ascii /* score: '14.00'*/
      $s12 = "DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE?" fullword ascii /* score: '14.00'*/
      $s13 = "If you are seeing this message without knowing what you just executed, simply press No and nothing will happen." fullword ascii /* score: '14.00'*/
      $s14 = "http://google.co.ck/search?q=bonzi+buddy+download+free" fullword ascii /* score: '13.00'*/
      $s15 = "http://google.co.ck/search?q=facebook+hacking+tool+free+download+no+virus+working+2016" fullword ascii /* score: '13.00'*/
      $s16 = "http://google.co.ck/search?q=virus+builder+legit+free+download" fullword ascii /* score: '13.00'*/
      $s17 = "http://google.co.ck/search?q=batch+virus+download" fullword ascii /* score: '13.00'*/
      $s18 = "http://google.co.ck/search?q=how+to+download+memz" fullword ascii /* score: '13.00'*/
      $s19 = "http://google.co.ck/search?q=minecraft+hax+download+no+virus" fullword ascii /* score: '13.00'*/
      $s20 = "http://google.co.ck/search?q=how+to+get+money" fullword ascii /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      8 of them
}

