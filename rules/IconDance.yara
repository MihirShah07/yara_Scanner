/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpzt3vwdue
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule IconDance {
   meta:
      description = "tmpzt3vwdue - file IconDance.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "a4b6e53453d1874a6f78f0d7aa14dfafba778062f4b85b42b4c1001e1fc17095"
   strings:
      $s1 = " en lecture seule'Erreur lors de la lecture de %s%s%s: %s" fullword wide /* score: '13.50'*/
      $s2 = "  - Zone d'empilement non trouv" fullword wide /* score: '12.00'*/
      $s3 = "e+ - La zone d'empilement n'a pas de contr" fullword wide /* score: '12.00'*/
      $s4 = "EComponentError4" fullword ascii /* score: '11.00'*/
      $s5 = " de liste hors limites (%d)!Compte de liste hors limites (%d)6Op" fullword wide /* score: '10.00'*/
      $s6 = "%s (%s, ligne %d)" fullword wide /* score: '9.50'*/
      $s7 = "Erreur Win32.  Code : %d." fullword wide /* score: '9.00'*/
      $s8 = "thode variante non support" fullword wide /* score: '9.00'*/
      $s9 = "EInOutErrortl@" fullword ascii /* score: '7.00'*/
      $s10 = "ERangeError4n@" fullword ascii /* score: '7.00'*/
      $s11 = ":+:7:D:V:\\:h:|:" fullword ascii /* score: '7.00'*/
      $s12 = ":,:L:T:X:\\:`:d:h:l:p:t:x:" fullword ascii /* score: '7.00'*/
      $s13 = "Alt+,Le Presse-papiers ne supporte pas les ic" fullword wide /* score: '7.00'*/
      $s14 = "Index de bits hors limites1Le menu '%s' est d" fullword wide /* score: '7.00'*/
      $s15 = " par une autre fiche%Le composant empil" fullword wide /* score: '7.00'*/
      $s16 = "!Un composant nomm" fullword wide /* score: '7.00'*/
      $s17 = " %s existe d" fullword wide /* score: '7.00'*/
      $s18 = "e %s existe d" fullword wide /* score: '7.00'*/
      $s19 = "ne\"Format Presse-papiers non support" fullword wide /* score: '7.00'*/
      $s20 = "Impossible d'affecter %s " fullword wide /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

