/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpnm_12orr
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpnm_12orr_Adwind {
   meta:
      description = "tmpnm_12orr - file Adwind.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "bbc572cced7c94d63a7208f4aba4ed20d1350bef153b099035a86c95c8d96d4a"
   strings:
      $s1 = "Obfuscation by Allatori Obfuscator http://www.allatori.com" fullword ascii /* score: '17.00'*/
      $s2 = "xfzzzf" fullword ascii /* score: '5.00'*/
      $s3 = "GeUb)z6K" fullword ascii /* score: '4.00'*/
      $s4 = "iiiiIiIIIi.classPK" fullword ascii /* score: '3.00'*/
      $s5 = "IiIiIIiiIi.classPK" fullword ascii /* score: '3.00'*/
      $s6 = "IIIIiIiIIi.classuSko" fullword ascii /* score: '3.00'*/
      $s7 = "IiIiIIiiIi.class" fullword ascii /* score: '3.00'*/
      $s8 = "IIIIiIiIIi.classPK" fullword ascii /* score: '3.00'*/
      $s9 = "iiiiIiIIIi.class}T" fullword ascii /* score: '3.00'*/
      $s10 = "xnSyH5" fullword ascii /* score: '2.00'*/
      $s11 = "$zxi{s(" fullword ascii /* score: '1.00'*/
      $s12 = "o_yQa-" fullword ascii /* score: '1.00'*/
      $s13 = "*xt;_D" fullword ascii /* score: '1.00'*/
      $s14 = "2F0)`JF" fullword ascii /* score: '1.00'*/
      $s15 = "K(H(JX" fullword ascii /* score: '1.00'*/
      $s16 = "10/10/10/PK" fullword ascii /* score: '1.00'*/
      $s17 = "2065.18" fullword ascii /* score: '1.00'*/
      $s18 = "10/10/10/" fullword ascii /* score: '1.00'*/
      $s19 = "<e/jApX" fullword ascii /* score: '1.00'*/
      $s20 = "*}+._$" fullword ascii /* score: '1.00'*/
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      8 of them
}

