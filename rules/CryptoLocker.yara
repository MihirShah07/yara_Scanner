/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpu1f6joxp
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule CryptoLocker {
   meta:
      description = "tmpu1f6joxp - file CryptoLocker.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9"
   strings:
      $s1 = "Failed to decrypt a previously encrypted file \"%s\". Perhaps the file may be damaged or used by another process." fullword wide /* score: '28.00'*/
      $s2 = "ster}}}\\cf1\\ulnone\\b0\\f0\\fs20  at Ukash.com, login and then go to the Manage Ukash area to use the Combine tool.\\par" fullword ascii /* score: '27.00'*/
      $s3 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '27.00'*/
      $s4 = "Encryption was produced using a \\b unique\\b0  public key \\cf2\\ul\\b{\\field{\\*\\fldinst{HYPERLINK \"http://en.wikipedia.org" ascii /* score: '26.00'*/
      $s5 = "You can \\b combine multiple values\\b0  of your Ukash into a single amount and have your new Ukash Code and value emailed to yo" ascii /* score: '26.00'*/
      $s6 = "Failed to decrypt the file \"%s\". Perhaps the file may be damaged or used by another process." fullword wide /* score: '23.00'*/
      $s7 = "{\\field{\\*\\fldinst{HYPERLINK \"https://www.ukash.com/en-GB/where-to-get/\"}}{\\fldrslt{\\ul Get Ukash}}}\\cf1\\kerning0\\ulno" ascii /* score: '22.00'*/
      $s8 = "{\\field{\\*\\fldinst{HYPERLINK \"https://www.ukash.com/en-GB/where-to-get/\"}}{\\fldrslt{\\ul Get Ukash}}}\\cf1\\kerning0\\ulno" ascii /* score: '22.00'*/
      $s9 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii /* score: '21.00'*/
      $s10 = "Encryption was produced using a \\b unique\\b0  public key \\cf2\\ul\\b{\\field{\\*\\fldinst{HYPERLINK \"http://en.wikipedia.org" ascii /* score: '21.00'*/
      $s11 = "@Msftedit.dll" fullword wide /* score: '20.00'*/
      $s12 = "@urlmon.dll" fullword wide /* score: '20.00'*/
      $s13 = "\\cf3\\b{\\field{\\*\\fldinst{HYPERLINK \"https://www.moneypak.com/\"}}{\\fldrslt{\\ul Home Page}}}\\ulnone\\f0\\fs20\\par" fullword ascii /* score: '18.00'*/
      $s14 = "\\cf3\\b{\\field{\\*\\fldinst{HYPERLINK \"https://www.ukash.com/en-GB/\"}}{\\fldrslt{\\ul Home Page}}}\\ulnone\\f0\\fs20\\par" fullword ascii /* score: '18.00'*/
      $s15 = "The private key destruction is suspended for the time of payment processing." fullword wide /* score: '18.00'*/
      $s16 = "if you want. You will need to {\\field{\\*\\fldinst{HYPERLINK \"https://www.ukash.com/en-GB/registration/\"}}{\\fldrslt{\\cf3\\u" ascii /* score: '17.00'*/
      $s17 = "Make sure that all important files have been decrypted! If part of the files had not been decrypted - move them to the desktop a" wide /* score: '17.00'*/
      $s18 = "\\viewkind4\\uc1\\pard\\nowidctlpar\\cf1\\lang9\\f0\\fs20 Your important files \\b encryption\\b0  produced on this computer: ph" ascii /* score: '16.00'*/
      $s19 = "{\\field{\\*\\fldinst{HYPERLINK \"http://bitcoin.org/en/getting-started\"}}{\\fldrslt{\\ul Getting started with Bitcoin}}}\\cf1" ascii /* score: '15.00'*/
      $s20 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii /* score: '15.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

