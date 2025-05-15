/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpmnw18dxa
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpmnw18dxa_Curfun {
   meta:
      description = "tmpmnw18dxa - file Curfun.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "ef878461a149024f3065121ff4e165731ecabef1b94b0b3ed2eda010ad39202b"
   strings:
      $s1 = "cursorfun.exe" fullword wide /* score: '22.00'*/
      $s2 = "www.rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s3 = "support@rjlsoftware.com" fullword wide /* score: '21.00'*/
      $s4 = "TFRMCOPYRIGHT" fullword wide /* score: '6.50'*/
      $s5 = "h`uTSL`*u9" fullword ascii /* score: '4.00'*/
      $s6 = "RNWQxTj" fullword ascii /* score: '4.00'*/
      $s7 = "OARH=#\"" fullword ascii /* score: '4.00'*/
      $s8 = "3\"hFLFXGf#-#.^9u" fullword ascii /* score: '4.00'*/
      $s9 = "EudCm4'" fullword ascii /* score: '4.00'*/
      $s10 = "xPhZd)60" fullword ascii /* score: '4.00'*/
      $s11 = "}RXyVp\"" fullword ascii /* score: '4.00'*/
      $s12 = "UCqJnP." fullword ascii /* score: '4.00'*/
      $s13 = "vqNau$f" fullword ascii /* score: '4.00'*/
      $s14 = "btllt%[" fullword ascii /* score: '4.00'*/
      $s15 = "sVzqB?" fullword ascii /* score: '4.00'*/
      $s16 = "JhRb!-" fullword ascii /* score: '4.00'*/
      $s17 = "4hNWXIu}bD" fullword ascii /* score: '4.00'*/
      $s18 = "mouQ tI" fullword ascii /* score: '4.00'*/
      $s19 = "RJL Software" fullword wide /* score: '4.00'*/
      $s20 = "Randomly changes cursor" fullword wide /* score: '4.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

