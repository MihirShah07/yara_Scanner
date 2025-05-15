/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpjiodytln
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule FreeYoutubeDownloader {
   meta:
      description = "tmpjiodytln - file FreeYoutubeDownloader.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "cae57a60c4d269cd1ca43ef143aedb8bfc4c09a7e4a689544883d05ce89406e7"
   strings:
      $x1 = "www.youtubedownloadernew.com" fullword ascii /* score: '36.00'*/
      $x2 = "support@youtubedownloadernew.com" fullword ascii /* score: '36.00'*/
      $s3 = "@$&%04\\Free YouTube Downloader.exe" fullword ascii /* score: '30.00'*/
      $s4 = "A password is required to begin the installation of Free Youtube Downloader. Type the password and then click \"Next\"." fullword ascii /* score: '27.00'*/
      $s5 = "Free Youtube Downloader.lnk" fullword ascii /* score: '26.00'*/
      $s6 = "Setup is now ready to begin installing Free Youtube Downloader on your computer." fullword ascii /* score: '25.00'*/
      $s7 = "Free Youtube Downloader 4.1.1.1" fullword ascii /* score: '24.00'*/
      $s8 = "Free Youtube Downloader 4.1.1.1 Uninstall" fullword ascii /* score: '24.00'*/
      $s9 = "Free Youtube Downloader 4.1.1.1 Installation" fullword ascii /* score: '24.00'*/
      $s10 = "Welcome to installer Free Youtube Downloader" fullword ascii /* score: '22.00'*/
      $s11 = "Setup has finished installing Free Youtube Downloader on your computer." fullword ascii /* score: '22.00'*/
      $s12 = "Welcome to the Free Youtube Downloader Setup Wizard" fullword ascii /* score: '22.00'*/
      $s13 = "Completing the Free Youtube Downloader Setup Wizard" fullword ascii /* score: '22.00'*/
      $s14 = "Free Youtube Downloader has been installed on your computer." fullword ascii /* score: '22.00'*/
      $s15 = "For installing Free Youtube Downloader on disk %s insufficiently free place. Try to choose other disk." fullword ascii /* score: '22.00'*/
      $s16 = "Remove Free Youtube Downloader from your computer." fullword ascii /* score: '22.00'*/
      $s17 = "Execute the commands..." fullword ascii /* score: '21.00'*/
      $s18 = "Uninstall Free Youtube Downloader" fullword ascii /* score: '19.00'*/
      $s19 = "Install Free Youtube Downloader is breaking." fullword ascii /* score: '19.00'*/
      $s20 = "Are you sure you want to quit Free Youtube Downloader?" fullword ascii /* score: '19.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

