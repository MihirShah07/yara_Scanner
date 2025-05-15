/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpaome7xyc
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpaome7xyc_Trololo {
   meta:
      description = "tmpaome7xyc - file Trololo.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "3d0efd55bde5fb7a73817940bac2a901d934b496738b7c5cab7ea0f6228e28fe"
   strings:
      $x1 = "taskkill.exe /f /im explorer.exe" fullword wide /* score: '34.00'*/
      $x2 = "taskkill.exe /f /im taskmgr.exe" fullword wide /* score: '34.00'*/
      $x3 = "C:\\Users\\Alexander\\Documents\\Visual Studio 2008\\Projects\\Virus\\Virus\\obj\\Release\\Virus.pdb" fullword ascii /* score: '33.00'*/
      $s4 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s5 = "Virus.exe" fullword wide /* score: '22.00'*/
      $s6 = "WScript.Shell" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.00'*/
      $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii /* score: '19.00'*/
      $s8 = "REG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 0 /f" fullword wide /* score: '18.00'*/
      $s9 = "4454573736" ascii /* score: '17.00'*/ /* hex encoded string 'DTW76' */
      $s10 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" fullword wide /* score: '16.00'*/
      $s11 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s12 = "            compatibility then delete the requestedExecutionLevel node." fullword ascii /* score: '14.00'*/
      $s13 = "!!!!!5 5 :" fullword ascii /* score: '14.00'*/ /* hex encoded string 'U' */
      $s14 = "# # 2&2&-+-+" fullword ascii /* score: '13.00'*/ /* hex encoded string '"' */
      $s15 = "lns:asmv2=\"urn:schemas-microsoft-com:asm.v2\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" fullword ascii /* score: '13.00'*/
      $s16 = "Enter stop password:" fullword wide /* score: '12.00'*/
      $s17 = "Password Is Wrong. U mad bro?" fullword wide /* score: '12.00'*/
      $s18 = "MyTemplate" fullword ascii /* score: '11.00'*/
      $s19 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
      $s20 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

