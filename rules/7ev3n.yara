/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmprpvp58pp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmprpvp58pp_7ev3n {
   meta:
      description = "tmprpvp58pp - file 7ev3n.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "7d373ccb96d1dbb1856ef31afa87c2112a0c1795a796ab01cb154700288afec5"
   strings:
      $x1 = "C:\\windows\\system32\\cmd.exe /c " fullword ascii /* score: '45.00'*/
      $x2 = "REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"Shell\" /t REG_SZ /d \"explorer.e" ascii /* score: '39.00'*/
      $x3 = "REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"Shell\" /t REG_SZ /d \"explorer.e" ascii /* score: '39.00'*/
      $x4 = "\\Windows\\System32\\SCHTASKS.exe /create /SC ONLOGON /TN uac /TR \"" fullword ascii /* score: '33.00'*/
      $x5 = "cmd.exe /c " fullword ascii /* score: '33.00'*/
      $x6 = "REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"Shell\" /t REG_SZ /d \"" fullword ascii /* score: '32.00'*/
      $s7 = "hello your files has been encrypted. for decrypt contact: JulyCezar1001@mail.com " fullword wide /* score: '26.00'*/
      $s8 = "\\AppData\\Local\\system.exe" fullword ascii /* score: '25.00'*/
      $s9 = "system.exe" fullword ascii /* score: '25.00'*/
      $s10 = "C:\\users\\" fullword wide /* score: '24.00'*/
      $s11 = "Dkernel32.dll" fullword wide /* score: '23.00'*/
      $s12 = "REG ADD \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\" /v \"Scancode Map\" /t REG_BINARY /d \"00000" ascii /* score: '22.00'*/
      $s13 = "REG ADD \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\" /v \"Scancode Map\" /t REG_BINARY /d \"00000" ascii /* score: '22.00'*/
      $s14 = "\\AppData\\Local\\uac.exe" fullword ascii /* score: '22.00'*/
      $s15 = "schtasks.exe /delete /TN uac /F" fullword ascii /* score: '21.00'*/
      $s16 = "REG DELETE \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\" /v \"Scancode Map\" /f /reg:64" fullword ascii /* score: '19.00'*/
      $s17 = "J:\\Win32Project9\\Release\\Win32Project9.pdb" fullword ascii /* score: '19.00'*/
      $s18 = "REG ADD \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d 506 /f /reg:64" fullword ascii /* score: '18.00'*/
      $s19 = "warning, do not try to get rid of this programm, any action taken will result in decryption key being destroyed, you will lose y" ascii /* score: '18.00'*/
      $s20 = "\\AppData\\Local\\del.bat" fullword ascii /* score: '18.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

