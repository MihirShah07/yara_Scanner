/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpmu_qkybl
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _uckyLocker {
   meta:
      description = "tmpmu_qkybl - file $uckyLocker.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "86e0eac8c5ce70c4b839ef18af5231b5f92e292b81e440193cdbdc7ed108049f"
   strings:
      $x1 = "C:\\Users\\Tyler\\Desktop\\hidden-tear-master\\hidden-tear\\hidden-tear\\obj\\Debug\\VapeHacksLoader.pdb" fullword ascii /* score: '42.00'*/
      $x2 = "VapeHacksLoader.exe" fullword wide /* score: '31.00'*/
      $s3 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD:" fullword ascii /* score: '27.00'*/
      $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s5 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s6 = "C:\\Users\\" fullword wide /* score: '24.00'*/
      $s7 = "Loader-Private" fullword wide /* score: '16.00'*/
      $s8 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s9 = "\\Desktop\\READ_IT.txt" fullword wide /* score: '15.00'*/
      $s10 = "VapeHacksLoader" fullword ascii /* score: '13.00'*/
      $s11 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s12 = "      <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s13 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s14 = "      <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s15 = "      <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s16 = "SendPassword" fullword ascii /* score: '12.00'*/
      $s17 = "      <!-- Windows 8 -->" fullword ascii /* score: '12.00'*/
      $s18 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii /* score: '11.00'*/
      $s19 = "             requestedExecutionLevel node with one of the following." fullword ascii /* score: '11.00'*/
      $s20 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

