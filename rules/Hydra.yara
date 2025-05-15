/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpekofg01g
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpekofg01g_Hydra {
   meta:
      description = "tmpekofg01g - file Hydra.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "0b6c0af51cde971b3e5f8aa204f8205418ab8c180b79a5ac1c11a6e0676f0f7c"
   strings:
      $s1 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ahSystem.Drawing.Bitmap, S" ascii /* score: '27.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "ystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADPBj" fullword ascii /* score: '24.00'*/
      $s4 = "Hydra.exe" fullword wide /* score: '22.00'*/
      $s5 = "D:\\Visual Studio Projects\\Hydra\\Hydra\\obj\\Release\\Hydra.pdb" fullword ascii /* score: '19.00'*/
      $s6 = "[Hydra ViRuS BioCoded by WiPet]" fullword wide /* score: '16.00'*/
      $s7 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii /* score: '15.00'*/
      $s8 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii /* score: '11.00'*/
      $s9 = ".NET Framework 4.7.20" fullword ascii /* score: '10.00'*/
      $s10 = ".NETFramework,Version=v4.7.2" fullword ascii /* score: '10.00'*/
      $s11 = "Cut off a head, two more will take its place." fullword wide /* score: '9.00'*/
      $s12 = "Hydra.MsgBoxForm.resources" fullword ascii /* score: '7.00'*/
      $s13 = "Hydra.Properties" fullword ascii /* score: '7.00'*/
      $s14 = "Hydra.Properties.Resources.resources" fullword ascii /* score: '7.00'*/
      $s15 = "MsgBoxForm_KeyPress" fullword ascii /* score: '7.00'*/
      $s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii /* score: '7.00'*/
      $s17 = "pbIcon.Image" fullword wide /* score: '7.00'*/
      $s18 = "Hydra.Properties.Resources" fullword wide /* score: '7.00'*/
      $s19 = "16.0.0.0" fullword ascii /* score: '6.00'*/
      $s20 = " Microsoft Corporation 2019" fullword wide /* score: '6.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

