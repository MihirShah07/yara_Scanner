/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpcnl9wozr
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpcnl9wozr_Alerta {
   meta:
      description = "tmpcnl9wozr - file Alerta.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "2d2a22db20a44474afbd7b0e6488690bad584dcae9789a5db776cc1a00b98728"
   strings:
      $s1 = "shellh32.dll" fullword wide /* score: '28.00'*/
      $s2 = "c:\\msdos.sys" fullword wide /* score: '24.00'*/
      $s3 = "alerta.exe" fullword wide /* score: '22.00'*/
      $s4 = "ALERTA.exe" fullword wide /* score: '22.00'*/
      $s5 = "22222222222222222222222222222222222222222222222222" ascii /* score: '17.00'*/ /* hex encoded string '"""""""""""""""""""""""""' */
      $s6 = "A*\\AC:\\HUD!\\PATIFA~1\\ALERTA\\ALERTA.VBP" fullword wide /* score: '17.00'*/
      $s7 = "C:\\Arquivos de programas\\VB5\\VB5.OLB" fullword ascii /* score: '16.00'*/
      $s8 = "Command3" fullword ascii /* score: '13.00'*/
      $s9 = "ALERTA!!!" fullword ascii /* score: '13.00'*/
      $s10 = "Command4" fullword ascii /* score: '13.00'*/
      $s11 = "Command2_Click" fullword ascii /* score: '12.00'*/
      $s12 = "Command3_Click" fullword ascii /* score: '12.00'*/
      $s13 = "Command4_MouseMove" fullword ascii /* score: '12.00'*/
      $s14 = "FOI DETECTADO UM HOMOSSEXUAL TENTANDO USAR O COMPUTADOR!!! VOC" fullword ascii /* score: '12.00'*/
      $s15 = "O!!!!!!" fullword ascii /* score: '10.00'*/
      $s16 = "HTqw.Cpe 08" fullword ascii /* score: '10.00'*/
      $s17 = "spfc.bmp" fullword wide /* score: '10.00'*/
      $s18 = "Shellh32" fullword wide /* score: '10.00'*/
      $s19 = "Bootkeys" fullword wide /* score: '9.00'*/
      $s20 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide /* score: '9.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

