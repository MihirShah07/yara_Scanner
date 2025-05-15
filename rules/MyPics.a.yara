/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpy28dji8p
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule MyPics_a {
   meta:
      description = "tmpy28dji8p - file MyPics.a.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "0ae040287546a70f8a2d5fc2da45a83e253da044bf10246ae77830af971b3359"
   strings:
      $s1 = "c:\\MyPics.exe" fullword wide /* score: '24.00'*/
      $s2 = "c:\\cbios.com" fullword wide /* score: '23.00'*/
      $s3 = "MyPics.exe" fullword wide /* score: '22.00'*/
      $s4 = "C:\\Pics4You.exe" fullword wide /* score: '21.00'*/
      $s5 = "c:\\Pics4You.exe" fullword wide /* score: '21.00'*/
      $s6 = "@*\\AC:\\MYPICS.VBP" fullword wide /* score: '17.00'*/
      $s7 = "http://www.geocities.com/SiliconValley/Vista/8279/index.html" fullword wide /* score: '17.00'*/
      $s8 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii /* score: '13.00'*/
      $s9 = "format d: /autotest /q /u" fullword wide /* score: '12.00'*/
      $s10 = "format c: /autotest /q /u" fullword wide /* score: '12.00'*/
      $s11 = "SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\Windows\\Run" fullword wide /* score: '10.00'*/
      $s12 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" fullword wide /* score: '10.00'*/
      $s13 = "GetNameSpace" fullword wide /* score: '9.00'*/
      $s14 = ": :0:8:@:D:H:L:P:T:X:\\:d:h:l:p:t:x:" fullword ascii /* score: '7.00'*/
      $s15 = "PrivateProfileString" fullword wide /* score: '7.00'*/
      $s16 = "AddressLists" fullword wide /* score: '7.00'*/
      $s17 = "AddressEntries" fullword wide /* score: '7.00'*/
      $s18 = "HELLO " fullword wide /* score: '6.00'*/
      $s19 = "ctty nul" fullword wide /* score: '6.00'*/
      $s20 = "Module1" fullword ascii /* score: '5.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

