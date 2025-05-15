/*
   YARA Rule Set
   Author: HTB-AC-1135606
   Date: 2025-05-14
   Identifier: tmpgd6ab73w
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _tmp_tmpgd6ab73w_NetWire {
   meta:
      description = "tmpgd6ab73w - file NetWire.exe"
      author = "HTB-AC-1135606"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-05-14"
      hash1 = "086d35f26bd2fd886e99744960b394d94e74133c40145a3e2bc6b3877b91ec5d"
   strings:
      $s1 = "Execute not supported: %s1Operation not allowed on a unidirectional dataset" fullword wide /* score: '29.00'*/
      $s2 = "URL.DLL" fullword ascii /* score: '20.00'*/
      $s3 = "Field '%s' has no dataset\"Circular datalinks are not allowed/Lookup information for field '%s' is incomplete" fullword wide /* score: '18.00'*/
      $s4 = "TLOGINDIALOG" fullword wide /* score: '17.50'*/
      $s5 = "TLoginDialog" fullword ascii /* score: '15.00'*/
      $s6 = "Database Login" fullword ascii /* score: '15.00'*/
      $s7 = "TPASSWORDDIALOG" fullword wide /* score: '14.50'*/
      $s8 = "sUnitInjection" fullword ascii /* score: '14.00'*/
      $s9 = "UnitInjection" fullword ascii /* score: '14.00'*/
      $s10 = "Remote Login&Cannot change the size of a JPEG image" fullword wide /* score: '14.00'*/
      $s11 = "/Custom variant type (%s%.4x) already used by %s*Custom variant type (%s%.4x) is not usable2Too many custom variant types have b" wide /* score: '14.00'*/
      $s12 = "%s,Custom variant type (%s%.4x) is out of range" fullword wide /* score: '13.50'*/
      $s13 = "TPasswordDialog" fullword ascii /* score: '12.00'*/
      $s14 = "PasswordCharx" fullword ascii /* score: '12.00'*/
      $s15 = "TCommonDialog(" fullword ascii /* score: '12.00'*/
      $s16 = "Bitmap.Data" fullword ascii /* score: '11.00'*/
      $s17 = "Filologiya" fullword ascii /* score: '11.00'*/
      $s18 = "3333s33" fullword ascii /* reversed goodware string '33s3333' */ /* score: '11.00'*/
      $s19 = "33333s3" fullword ascii /* reversed goodware string '3s33333' */ /* score: '11.00'*/
      $s20 = "DataSource cannot be changed0Cannot perform this operation on an open dataset\"Dataset not in edit or insert mode1Cannot perform" wide /* score: '11.00'*/
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

