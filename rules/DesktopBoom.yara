/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpvy9hyzeq
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule DesktopBoom {
   meta:
      description = "tmpvy9hyzeq - file DesktopBoom.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "c20e78ce9028299d566684d35b1230d055e5ea0e9b94d0aff58f650e0468778a"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:v3=\"urn:schemas-microsoft-com:asm.v3\"><asse" ascii /* score: '48.00'*/
      $x2 = "Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language" ascii /* score: '39.00'*/
      $s3 = "AutoHotkey.exe" fullword wide /* score: '25.00'*/
      $s4 = "Could not launch WindowSpy.ahk or AU3_Spy.exe" fullword wide /* score: '24.00'*/
      $s5 = "https://autohotkey.com" fullword wide /* score: '24.00'*/
      $s6 = "ges><v3:requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /></v3:requestedPrivileges></v3:security></v3:trustInfo><" ascii /* score: '23.00'*/
      $s7 = "DesktopBoom.exe" fullword wide /* score: '22.00'*/
      $s8 = "AU3_Spy.exe" fullword wide /* score: '21.00'*/
      $s9 = "Could not open URL https://autohotkey.com in default browser." fullword wide /* score: '20.00'*/
      $s10 = "\\AutoHotkey.exe" fullword wide /* score: '19.00'*/
      $s11 = "RunAs: Missing advapi32.dll." fullword wide /* score: '19.00'*/
      $s12 = "command option was not enabled in the original script." fullword wide /* score: '18.00'*/
      $s13 = "WCreateProcessWithLogonW." fullword wide /* score: '18.00'*/
      $s14 = "Script lines most recently executed (oldest first).  Press [F5] to refresh.  The seconds elapsed between a line and the one afte" wide /* score: '17.00'*/
      $s15 = "HUUUUUUUU" fullword ascii /* reversed goodware string 'UUUUUUUUH' */ /* score: '16.50'*/
      $s16 = "The oldest are listed first.  VK=Virtual Key, SC=Scan Code, Elapsed=Seconds since the previous event.  Types: h=Hook Hotkey, s=S" wide /* score: '16.00'*/
      $s17 = "comspec" fullword wide /* PEStudio Blacklist: strings */ /* score: '16.00'*/
      $s18 = "Compile error %d at offset %d: %hs" fullword wide /* score: '15.50'*/
      $s19 = "if not GetKeyState(\"%s\")" fullword wide /* score: '15.00'*/
      $s20 = "WindowSpy.ahk" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

