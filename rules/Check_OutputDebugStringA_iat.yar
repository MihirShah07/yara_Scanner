rule Check_OutputDebugStringA_iat
{

	meta:
		Author = "cyrus"
		Description = "Detect in IAT OutputDebugstringA"

	condition:
		pe.imports("kernel32.dll","OutputDebugStringA")
}
