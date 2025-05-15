/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpo3vekoyr
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule WinlockerVB6Blacksod {
   meta:
      description = "tmpo3vekoyr - file WinlockerVB6Blacksod.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "68b0e1932f3b4439865be848c2d592d5174dbdbaab8f66104a0e5b28c928ee0c"
   strings:
      $x1 = "C:\\Users\\victor\\Desktop\\BRANCH\\win\\Release\\stubs\\x86\\ExternalUi.pdb" fullword ascii /* score: '33.00'*/
      $x2 = "Launching msiexec.exe with command line:" fullword wide /* score: '32.00'*/
      $x3 = "[SystemFolder]msiexec.exe" fullword wide /* score: '32.00'*/
      $x4 = "  <msiOptions> - options for msiexec.exe on running the MSI package" fullword wide /* score: '32.00'*/
      $s5 = "  <!-- Set the current process as DPI aware (for Windows Vista or newer) -->" fullword ascii /* score: '28.00'*/
      $s6 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '27.00'*/
      $s7 = "FComCtl32.dll" fullword wide /* score: '26.00'*/
      $s8 = "Decoder.dll" fullword wide /* score: '25.00'*/
      $s9 = "Setup package was encrypted using AES 256 algorithm. To continue the setup process, you should provide the password needed to de" wide /* score: '25.00'*/
      $s10 = "decoder.dll" fullword wide /* score: '25.00'*/
      $s11 = "%s cannot be installed on %s<%s cannot be installed on the following Windows versions: %sP%s cannot be installed on systems with" wide /* score: '24.50'*/
      $s12 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii /* score: '24.00'*/
      $s13 = "c:\\users\\victor\\desktop\\branch\\externalui\\controls\\generic\\VisualStyleBorder.h" fullword wide /* score: '24.00'*/
      $s14 = "c:\\users\\victor\\desktop\\branch\\externalui\\nativeui\\NativeAccelerator.h" fullword wide /* score: '24.00'*/
      $s15 = "c:\\users\\victor\\desktop\\branch\\externalui\\controls\\generic/VisualStyleBorder.h" fullword wide /* score: '24.00'*/
      $s16 = "Return code of msiexec.exe:" fullword wide /* score: '24.00'*/
      $s17 = "[SystemFolder]msi.dll" fullword wide /* score: '23.00'*/
      $s18 = "Dbghelp.dll" fullword ascii /* score: '23.00'*/
      $s19 = "IUxTheme.dll" fullword wide /* score: '23.00'*/
      $s20 = "User name and password for proxy server were received from command line and used." fullword wide /* score: '23.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

