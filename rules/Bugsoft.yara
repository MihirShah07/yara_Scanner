/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmppw1tb1sw
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmppw1tb1sw_Bugsoft {
   meta:
      description = "tmppw1tb1sw - file Bugsoft.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "96425ae53a5517b9f47e30f6b41fdc883831039e1faba02fe28b2d5f3efcdc29"
   strings:
      $s1 = "copy/y love.exe c:\\windows\\command\\scandisk.exe" fullword wide /* score: '30.00'*/
      $s2 = "copy/y love.exe c:\\windows\\command\\scanreg.exe" fullword wide /* score: '30.00'*/
      $s3 = "copy/y c:\\windows\\command\\game.exe c:\\windows\\command\\fdisk.exe" fullword wide /* score: '29.00'*/
      $s4 = "copy/y c:\\windows\\command\\game.exe c:\\windows\\command\\ebd\\fdisk.exe" fullword wide /* score: '29.00'*/
      $s5 = "if not exist c:\\windows\\startm~1\\programs\\startup\\love.exe copy/y c:\\windows\\command\\game.exe c:\\windows\\stratm~1\\pro" wide /* score: '29.00'*/
      $s6 = "if not exist a:\\love.exe copy c:\\windows\\command\\game.exe a:\\love.exe" fullword wide /* score: '29.00'*/
      $s7 = "if exist a:\\fdisk.exe copy/y c:\\windows\\command\\game.exe a:\\fdisk.exe" fullword wide /* score: '29.00'*/
      $s8 = "c:\\windows\\wscript mail.vbs" fullword wide /* score: '26.00'*/
      $s9 = "copy/y c:\\windows\\command\\game.exe c:\\windows\\command\\format.com" fullword wide /* score: '25.00'*/
      $s10 = "copy/y love.exe c:\\windows\\command\\edit.com" fullword wide /* score: '25.00'*/
      $s11 = "copy/y love.exe c:\\windows\\command\\sys.com" fullword wide /* score: '25.00'*/
      $s12 = "if exist a:\\format.com copy/y c:\\windows\\command\\game.exe a:\\format.com" fullword wide /* score: '25.00'*/
      $s13 = "if exist a:\\command.com copy/y c:\\windows\\command\\game.exe a:\\command.com" fullword wide /* score: '25.00'*/
      $s14 = "if exist a:\\command.com copy/y c:\\windows\\game.exe a:\\command.com" fullword wide /* score: '25.00'*/
      $s15 = "c:\\windows\\love.exe" fullword wide /* score: '24.00'*/
      $s16 = "copy/y love.exe c:\\windows\\scandiskw.exe" fullword wide /* score: '22.00'*/
      $s17 = "love.exe" fullword wide /* score: '22.00'*/
      $s18 = "copy/y c:\\windows\\love.exe love.exe" fullword wide /* score: '21.00'*/
      $s19 = "copy/y c:\\windows\\love.exe c:\\windows\\game.exe" fullword wide /* score: '21.00'*/
      $s20 = "copy/y c:\\windows\\startm~1\\progra~1\\startup\\love.exe c:\\windows\\game.exe" fullword wide /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

