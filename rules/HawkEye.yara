/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmp8c4j8__g
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmp8c4j8__g_HawkEye {
   meta:
      description = "tmp8c4j8__g - file HawkEye.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "1dacdc296fd6ef6ba817b184cce9901901c47c01d849adfa4222bfabfed61838"
   strings:
      $x1 = "5/UNYMlFEShtrF70aFBuzZ7vAGKcoCupCpBeHGt0ddl5IxDzxZ9fQgjvWJU1J4WfeDyDE+wU3zBpK0NEtNJkcPs5dLKOVMYmoKRwxihQMcbXZfNC8tCqg6cDn5ql0j7N" wide /* score: '47.00'*/
      $x2 = "Loader.exe" fullword ascii /* score: '31.00'*/
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii /* score: '27.00'*/
      $s4 = "Y3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP" wide /* score: '16.00'*/
      $s5 = "Uglq1TA2pTi/QKOegfPX+3zjOYKbL/+HNI5DRMTe6ctUe5QypsIjPe5MlQtC+sNOCC6hZijZJLJ2W6JJbYvRJXL49mSGaJgW1KRczF1ltpJscEhQ/e252l4VRlenjZ2E" wide /* score: '11.00'*/
      $s6 = "tmp1E2A.jpg" fullword ascii /* score: '10.00'*/
      $s7 = "oldHeaders" fullword ascii /* score: '9.00'*/
      $s8 = "dosHeader" fullword ascii /* score: '9.00'*/
      $s9 = "GetModuleCount" fullword ascii /* score: '9.00'*/
      $s10 = "fnDllEntry" fullword ascii /* score: '9.00'*/
      $s11 = "BuildImportTable" fullword ascii /* score: '7.00'*/
      $s12 = "IMAGE_EXPORT_DIRECTORY" fullword ascii /* score: '7.00'*/
      $s13 = "generateSubkeys" fullword ascii /* score: '7.00'*/
      $s14 = "IMAGE_IMPORT_BY_NAME" fullword ascii /* score: '7.00'*/
      $s15 = "AddRoundKey" fullword ascii /* score: '7.00'*/
      $s16 = "Win32Imports" fullword ascii /* score: '7.00'*/
      $s17 = "jQECBAgQIECAGzZs2KtNmi9evGPGlzVq1LN9+u/FkTly5NO9YcKfJUqUM2bMgx06dOjLjQECBAgQIECAGzZs2KtNmi9evGPGlzVq1LN9+u/FkTly5NO9YcKfJUqUM2bM" wide /* score: '7.00'*/
      $s18 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s19 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* score: '6.50'*/
      $s20 = "MEMORYMODULE" fullword ascii /* score: '6.50'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

