/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpsy_zv6lv
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Blackkomet {
   meta:
      description = "tmpsy_zv6lv - file Blackkomet.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "0e8336ed51fe4551ced7d9aa5ce2dde945df8a0cc4e7c60199c24dd1cf7ccd48"
   strings:
      $s1 = "lstports.dll" fullword ascii /* score: '26.00'*/
      $s2 = "BTRESULTDownload File|Mass Download : File Downloaded , Executing new one in temp dir...|" fullword ascii /* score: '24.00'*/
      $s3 = " Command successfully executed!|" fullword ascii /* score: '24.00'*/
      $s4 = "BTRESULTUpdate from URL|Update : File Downloaded , Executing new one in temp dir...|" fullword ascii /* score: '24.00'*/
      $s5 = "GETMPASSWORDS" fullword ascii /* score: '22.50'*/
      $s6 = "UnActiveOfflineKeylogger" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s7 = "ActiveOnlineKeylogger" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s8 = "ActiveOfflineKeylogger" fullword ascii /* PEStudio Blacklist: strings */ /* score: '22.00'*/
      $s9 = "OpenProcessToken error" fullword ascii /* score: '21.00'*/
      $s10 = "TMPMUTEX" fullword ascii /* score: '20.50'*/
      $s11 = "RemoteErrorError when getting hosts content file" fullword ascii /* score: '20.00'*/
      $s12 = "ping 127.0.0.1 -n 4 > NUL" fullword ascii /* score: '20.00'*/
      $s13 = "RemoteErrorError on getting logs" fullword ascii /* score: '20.00'*/
      $s14 = "__tmp.exe" fullword ascii /* score: '19.00'*/
      $s15 = "DownloadFail" fullword ascii /* PEStudio Blacklist: strings */ /* score: '18.00'*/
      $s16 = "tmpthumb.tmp" fullword ascii /* score: '17.00'*/
      $s17 = "InstallHKEY" fullword ascii /* base64 encoded string '"{-jYG(F' */ /* score: '17.00'*/
      $s18 = "UnActiveOnlineKeylogger" fullword ascii /* score: '17.00'*/
      $s19 = "tmpprint.txt" fullword ascii /* score: '17.00'*/
      $s20 = "UntKeylogger" fullword ascii /* score: '17.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

