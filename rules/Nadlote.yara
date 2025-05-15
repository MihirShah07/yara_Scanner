/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp_7xu3vcx
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp_7xu3vcx_Nadlote {
   meta:
      description = "tmp_7xu3vcx - file Nadlote.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "ab020413dce53c9d57cf22d75eaf1339d72252d5316617a935149e02fee42fd3"
   strings:
      $x1 = "c:\\RECYCLER\\downloads.exe" fullword wide /* score: '37.00'*/
      $x2 = "c:\\RECYCLER\\Downloads.exe" fullword wide /* score: '37.00'*/
      $x3 = "cmd /c net share Love2=\"c:\\Documents and Settings\" /unlimited " fullword wide /* score: '34.00'*/
      $x4 = "d:\\RECYCLER\\Downloads.exe" fullword wide /* score: '34.00'*/
      $x5 = "d:\\RECYCLER\\downloads.exe" fullword wide /* score: '34.00'*/
      $s6 = "c:\\Downloads.exe" fullword wide /* score: '30.00'*/
      $s7 = "e:\\Downloads.exe" fullword wide /* score: '27.00'*/
      $s8 = ":\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\csrss.exe" fullword wide /* score: '26.00'*/
      $s9 = "C*\\AF:\\Documents and Settings\\VB6\\open v4.0\\open.vbp" fullword wide /* score: '25.00'*/
      $s10 = " net share Love2=\"c:\\Documents and Settings\" /unlimited" fullword wide /* score: '25.00'*/
      $s11 = "cmd  /c REG ADD HKLM\\Software\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN /V smss /t REG_SZ /d \"" fullword wide /* score: '23.00'*/
      $s12 = "cmd  /c REG ADD HKCU\\Software\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN /V smss /t REG_SZ /d \"" fullword wide /* score: '23.00'*/
      $s13 = "cmd  /c REG ADD HKCU\\Software\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN /V Csrss /t REG_SZ /d \"" fullword wide /* score: '23.00'*/
      $s14 = "open2.exe" fullword wide /* score: '22.00'*/
      $s15 = "c:\\RECYCLER" fullword wide /* score: '20.00'*/
      $s16 = "cmd /c net share Love1 /DELETE" fullword wide /* score: '20.00'*/
      $s17 = "Unable to get process snapshot" fullword wide /* score: '20.00'*/
      $s18 = "OPEN=PLAY_xXx.EXE" fullword wide /* score: '19.00'*/
      $s19 = "c:\\autorun.INF" fullword wide /* score: '19.00'*/
      $s20 = "play_xxx.exe" fullword wide /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

