/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmphz1y5m5x
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule GandCrab {
   meta:
      description = "tmphz1y5m5x - file GandCrab.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "bfb9db791b8250ffa8ebc48295c5dbbca757a5ed3bbb01de12a871b5cd9afd5a"
   strings:
      $s1 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s2 = ".2=,9,\">00" fullword ascii /* score: '9.00'*/ /* hex encoded string ')' */
      $s3 = ">67!&(>(?,=" fullword ascii /* score: '9.00'*/ /* hex encoded string 'g' */
      $s4 = "$);7',%1<:" fullword ascii /* score: '9.00'*/ /* hex encoded string 'q' */
      $s5 = " constructor or from DllMain." fullword ascii /* score: '9.00'*/
      $s6 = "#'% =5$9-," fullword ascii /* score: '9.00'*/ /* hex encoded string 'Y' */
      $s7 = ">#, 2&;;2(" fullword ascii /* score: '9.00'*/ /* hex encoded string '"' */
      $s8 = "*=$,,)%%53" fullword ascii /* score: '9.00'*/ /* hex encoded string 'S' */
      $s9 = "7?/05.*0+" fullword ascii /* score: '9.00'*/ /* hex encoded string 'pP' */
      $s10 = "6;:)1/\"%" fullword ascii /* score: '9.00'*/ /* hex encoded string 'a' */
      $s11 = ",')2052>><" fullword ascii /* score: '9.00'*/ /* hex encoded string ' R' */
      $s12 = "($/7<.+$8)77" fullword ascii /* score: '9.00'*/ /* hex encoded string 'xw' */
      $s13 = "3;65:'!;8." fullword ascii /* score: '9.00'*/ /* hex encoded string '6X' */
      $s14 = "7'?-(5,+5%2" fullword ascii /* score: '9.00'*/ /* hex encoded string 'uR' */
      $s15 = "? -+ %" fullword ascii /* score: '9.00'*/
      $s16 = "!266!&9&>" fullword ascii /* score: '9.00'*/ /* hex encoded string '&i' */
      $s17 = "<3$76<4:%" fullword ascii /* score: '9.00'*/ /* hex encoded string '7d' */
      $s18 = "telokagikavetitogone" fullword ascii /* score: '8.00'*/
      $s19 = "ruyejegomu" fullword ascii /* score: '8.00'*/
      $s20 = "!2!!!#9" fullword ascii /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

