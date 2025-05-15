/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_bjayhql
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp_bjayhql_Funsoul {
   meta:
      description = "tmp_bjayhql - file Funsoul.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "69ee59cee5a1d39739d935701cfa917f75787b29e0b9bda9ada9e2642ade434c"
   strings:
      $x1 = "c:\\Login.scr" fullword wide /* score: '31.00'*/
      $x2 = "C:\\Login.scr" fullword wide /* score: '31.00'*/
      $s3 = "C:\\Autoexec.bat" fullword wide /* score: '28.00'*/
      $s4 = "http://www.outpost-of-freedom.com/McVeigh/default.htm" fullword wide /* score: '22.00'*/
      $s5 = "c:\\Protect.sys" fullword wide /* score: '21.00'*/
      $s6 = "c:\\hide.bat" fullword wide /* score: '20.00'*/
      $s7 = "C:\\Help.bat" fullword wide /* score: '20.00'*/
      $s8 = "C:\\hide.bat" fullword wide /* score: '20.00'*/
      $s9 = "c:\\Funny.scr" fullword wide /* score: '20.00'*/
      $s10 = "C:\\Funny.scr" fullword wide /* score: '20.00'*/
      $s11 = "c:\\help.bat" fullword wide /* score: '20.00'*/
      $s12 = "C:\\help.bat" fullword wide /* score: '20.00'*/
      $s13 = "Funny.scr" fullword wide /* score: '18.00'*/
      $s14 = "@*\\AC:\\WINDOWS\\DESKTOP\\NEW911~1\\NEW911~1.VBP" fullword wide /* score: '17.00'*/
      $s15 = "http://207.211.212.35/pmaia/Visual_b.htm" fullword wide /* score: '15.00'*/
      $s16 = "Under the bludgeonings of chance my head is bloody, but unbowed." fullword ascii /* score: '14.00'*/
      $s17 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii /* score: '13.00'*/
      $s18 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" fullword wide /* score: '10.00'*/
      $s19 = "In the fell clutch of circumstance I have not winced nor cried aloud." fullword ascii /* score: '9.00'*/
      $s20 = "Vshield32dll" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      1 of ($x*) and 4 of them
}

