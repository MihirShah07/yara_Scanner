/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpp6h4vsnk
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpp6h4vsnk_Spark {
   meta:
      description = "tmpp6h4vsnk - file Spark.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "55bfcb784904477ef62ef7e4994dee42f03d69bfec3591989513cccbba3fc8fe"
   strings:
      $x1 = "C:\\Users\\Chris\\source\\newrepos\\Spark\\Release\\DLL.pdb" fullword ascii /* score: '38.00'*/
      $x2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msconfig.exe" fullword wide /* score: '38.00'*/
      $x3 = "C:\\Users\\Chris\\source\\newrepos\\Spark\\Release\\Driver-x86.pdb" fullword ascii /* score: '36.00'*/
      $x4 = "c:\\Users\\Chris\\source\\newrepos\\Spark\\x64\\Release\\Driver-x64.pdb" fullword ascii /* score: '36.00'*/
      $x5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mmc.exe" fullword wide /* score: '35.00'*/
      $x6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\regedit.exe" fullword wide /* score: '35.00'*/
      $x7 = "C:\\Users\\Chris\\source\\newrepos\\Spark\\Spark\\obj\\Release\\Spark.pdb" fullword ascii /* score: '33.00'*/
      $x8 = "C:\\Users\\Chris\\source\\newrepos\\Spark\\IFEO\\obj\\Release\\IFEO.pdb" fullword ascii /* score: '33.00'*/
      $s9 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, S" ascii /* score: '27.00'*/
      $s10 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s11 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskschd.msc" fullword wide /* score: '27.00'*/
      $s12 = "Driver.sys" fullword wide /* score: '25.00'*/
      $s13 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADP" fullword ascii /* score: '24.00'*/
      $s14 = "\\System32\\bcdedit.exe" fullword wide /* score: '24.00'*/
      $s15 = "costura.costura.dll.compressed" fullword wide /* score: '22.00'*/
      $s16 = "costura.microsoft.win32.taskscheduler.dll.compressed" fullword wide /* score: '22.00'*/
      $s17 = "C:\\Windows\\File Cache\\DLL.dll" fullword ascii /* score: '22.00'*/
      $s18 = "IFEO.exe" fullword wide /* score: '22.00'*/
      $s19 = "Spark.exe" fullword wide /* score: '22.00'*/
      $s20 = "?StartProcPayload@Export@SparkDLL@@QAEXH@Z" fullword ascii /* score: '21.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

