/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpjayt3f_9
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ClassicShell {
   meta:
      description = "tmpjayt3f_9 - file ClassicShell.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "a848bf24651421fbcd15c7e44f80bb87cbacd2599eb86508829537693359e032"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii /* score: '49.00'*/
      $s2 = "        * if %MSI% is not found, the setup runs \"msiexec /i <MSI file> <some msiexec options>\"" fullword wide /* score: '28.00'*/
      $s3 = "Failed to run msiexec.exe." fullword wide /* score: '27.00'*/
      $s4 = "mon-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyId" ascii /* score: '25.00'*/
      $s5 = "    /l* log.txt - runs the installer and logs the process in the log.txt file" fullword wide /* score: '25.00'*/
      $s6 = "    <some msiexec options> - the options are passed to msiexec" fullword wide /* score: '23.00'*/
      $s7 = "ClassicShellSetup.exe" fullword wide /* score: '23.00'*/
      $s8 = "yIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"IvoSoft.ClassicShellSetup\" type=\"win32\"></assemblyIdentity" ascii /* score: '21.00'*/
      $s9 = "ption>Classic Shell Setup</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows." ascii /* score: '21.00'*/
      $s10 = "utionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustI" ascii /* score: '19.00'*/
      $s11 = "<33333333" fullword ascii /* reversed goodware string '33333333<' */ /* score: '19.00'*/ /* hex encoded string '3333' */
      $s12 = "<3333333333" fullword ascii /* reversed goodware string '3333333333<' */ /* score: '19.00'*/ /* hex encoded string '33333' */
      $s13 = "dependentAssembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedEx" ascii /* score: '18.00'*/
      $s14 = "    <no command line> - runs the installer normally" fullword wide /* score: '18.00'*/
      $s15 = "2323333333" ascii /* score: '17.00'*/ /* hex encoded string '##333' */
      $s16 = "3333333333333F" ascii /* score: '17.00'*/ /* hex encoded string '333333?' */
      $s17 = "    /qn ADDLOCAL=ClassicStartMenu APPLICATIONFOLDER=C:\\ClassicShell - installs only Classic Start Menu in quiet mode in the fol" wide /* score: '17.00'*/
      $s18 = "Classic Shell Setup will install Classic Shell on  your computer. Possible command lines:" fullword wide /* score: '16.00'*/
      $s19 = "        * run msiexec with no parameters to see the full list of msiexec options" fullword wide /* score: '16.00'*/
      $s20 = "This beta version is password-protected. Please enter the password:" fullword wide /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      1 of ($x*) and 4 of them
}

