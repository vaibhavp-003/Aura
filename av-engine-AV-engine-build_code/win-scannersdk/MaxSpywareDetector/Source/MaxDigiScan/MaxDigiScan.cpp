// MaxDigiScan.cpp : Defines the exported functions for the DLL application.
//

#include "pch.h"
#include "MaxDigitalSigCheck.h"
CMaxDigitalSigCheck g_objMaxDigitalSigCheck;

extern "C" __declspec(dllexport) bool ScanFileDigiSig(TCHAR *pszPattern)
{
	return g_objMaxDigitalSigCheck.CheckDigitalSign(pszPattern);
}
extern "C" __declspec(dllexport) bool LoadDigiSig()
{
	return g_objMaxDigitalSigCheck.LoadWinTrust();
}
extern "C" __declspec(dllexport) bool UnLoadDigiSig()
{
	return g_objMaxDigitalSigCheck.UnLoadWinTrust();
}