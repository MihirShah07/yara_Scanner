/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpuxsyosk7
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule CodeRed_a {
   meta:
      description = "tmpuxsyosk7 - file CodeRed.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "59fe169797953f2046b283235fe80158ebf02ba586eabfea306402fba8473dae"
   strings:
      $s1 = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=english\"><title>HELLO!</title></head><bady><hr size=" ascii /* score: '27.00'*/
      $s2 = "HOST:www.worm.com" fullword ascii /* score: '23.00'*/
      $s3 = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=english\"><title>HELLO!</title></head><bady><hr size=" ascii /* score: '22.00'*/
      $s4 = "GET /default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN" ascii /* score: '19.00'*/
      $s5 = "GET /default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN" ascii /* score: '16.00'*/
      $s6 = "c:\\notworm" fullword ascii /* score: '13.00'*/
      $s7 = "ont color=\"red\"><p align=\"center\">Welcome to http://www.worm.com !<br><br>Hacked By Chinese!</font></hr></bady></html>      " ascii /* score: '12.00'*/
      $s8 = "Content-length: 3569 " fullword ascii /* score: '9.00'*/
      $s9 = "  HTTP/1.0" fullword ascii /* score: '7.00'*/
      $s10 = "bd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u00=a  HTT" ascii /* score: '4.00'*/
      $s11 = " Accept: */*" fullword ascii /* score: '4.00'*/
      $s12 = "UWSVPj<" fullword ascii /* score: '4.00'*/
      $s13 = "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%uc" ascii /* score: '4.00'*/
      $s14 = ":LMTHu" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4547 and filesize < 10KB and
      8 of them
}

