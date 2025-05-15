/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmperu4ndbg
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Windows_KB2670838_msu {
   meta:
      description = "tmperu4ndbg - file Windows-KB2670838.msu.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "f91f02fd27ada64f36f6df59a611fef106ff7734833dea825d0612e73bdfb621"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADm" fullword ascii /* score: '27.00'*/
      $s2 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii /* score: '27.00'*/
      $s3 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii /* score: '25.00'*/
      $s4 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii /* score: '23.00'*/
      $s5 = "Windows-KB2670838.msu.exe" fullword wide /* score: '19.00'*/
      $s6 = "D:\\Visual Studio Projects\\WindowsUpdate\\WindowsUpdate\\obj\\Release\\Windows-KB2670838.msu.pdb" fullword ascii /* score: '19.00'*/
      $s7 = "d5-ba3d-11da-ad31-d33d75182f1b\" xmlns:tiff=\"http://ns.adobe.com/tiff/1.0/\"/></rdf:RDF></x:xmpmeta>" fullword ascii /* score: '17.00'*/
      $s8 = "365857777777" ascii /* score: '17.00'*/ /* hex encoded string '6XWwww' */
      $s9 = "<http://ns.adobe.com/xap/1.0/" fullword ascii /* score: '17.00'*/
      $s10 = "\"uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"/><rdf:Description rdf:about=\"uuid:f" ascii /* score: '16.00'*/
      $s11 = "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description rdf:ab" ascii /* score: '16.00'*/
      $s12 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii /* score: '15.00'*/
      $s13 = "processInformationLength" fullword ascii /* score: '15.00'*/
      $s14 = "get_logon" fullword ascii /* score: '14.00'*/
      $s15 = "      <!-- Windows 10 -->" fullword ascii /* score: '12.00'*/
      $s16 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii /* score: '12.00'*/
      $s17 = "      <!-- Windows Vista -->" fullword ascii /* score: '12.00'*/
      $s18 = "      <!-- Windows 7 -->" fullword ascii /* score: '12.00'*/
      $s19 = "      <!-- Windows 8.1 -->" fullword ascii /* score: '12.00'*/
      $s20 = "LogonText" fullword wide /* score: '12.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

