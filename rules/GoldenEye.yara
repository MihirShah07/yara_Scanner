/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpwc7hn7zt
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule GoldenEye {
   meta:
      description = "tmpwc7hn7zt - file GoldenEye.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "389a7d395492c2da6f8abf5a8a7c49c3482f7844f77fe681808c71e961bcae97"
   strings:
      $s1 = "estrictions on destinations, end users and end use.  For additional information, see \\cf1\\ul www.microsoft.com/exporting <http" ascii /* score: '28.00'*/
      $s2 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes the " ascii /* score: '23.00'*/
      $s3 = "/www.microsoft.com/exporting>\\cf0\\ulnone .\\b\\par" fullword ascii /* score: '17.00'*/
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii /* score: '15.00'*/
      $s5 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii /* score: '13.00'*/
      $s6 = "\\pard\\keepn\\fi-360\\li720\\sb120\\sa120\\tx720\\lang1036\\'b7\\tab tout  ce qui est reli\\'e9 au logiciel, aux services ou au" ascii /* score: '13.00'*/
      $s7 = "\\pard\\sb240\\lang1036 Remarque : Ce logiciel \\'e9tant distribu\\'e9 au Qu\\'e9bec, Canada, certaines des clauses dans ce cont" ascii /* score: '11.00'*/
      $s8 = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab reverse engineer, decompile or disassemble the binary versions of the software, ex" ascii /* score: '11.00'*/
      $s9 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab les r\\'e9clamations au titre de violation de contrat ou de garantie, ou au" ascii /* score: '10.00'*/
      $s10 = "ou must comply with all domestic and international export laws and regulations that apply to the software.  These laws include r" ascii /* score: '10.00'*/
      $s11 = " Type Descriptor'" fullword ascii /* score: '10.00'*/
      $s12 = "\\pard\\sb120\\sa120 EXON\\'c9RATION DE GARANTIE.\\b0  Le logiciel vis\\'e9 par une licence est offert \\'ab tel quel \\'bb. Tou" ascii /* score: '10.00'*/
      $s13 = "n usage particulier et d'absence de contrefa\\'e7on sont exclues.\\par" fullword ascii /* score: '9.00'*/
      $s14 = "us par les lois de votre pays.  Le pr\\'e9sent contrat ne modifie pas les droits que vous conf\\'e8rent les lois de votre pays s" ascii /* score: '9.00'*/
      $s15 = "sation de ce logiciel est \\'e0 votre seule risque et p\\'e9ril. Sysinternals n'accorde aucune autre garantie expresse. Vous pou" ascii /* score: '9.00'*/
      $s16 = "z b\\'e9n\\'e9ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut" ascii /* score: '8.00'*/
      $s17 = "ces and support services that you use, are the entire agreement for the software and support services.\\par" fullword ascii /* score: '7.00'*/
      $s18 = " compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers ; et\\par" fullword ascii /* score: '7.00'*/
      $s19 = "port services for it.\\b\\par" fullword ascii /* score: '7.00'*/
      $s20 = "00 $ US. Vous ne pouvez pr\\'e9tendre \\'e0 aucune indemnisation pour les autres dommages, y compris les dommages sp\\'e9ciaux, " ascii /* score: '7.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

