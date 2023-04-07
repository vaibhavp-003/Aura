#include "conf.h"
#include "windows.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

int _main(int argc, char *argv[],DWORD,DWORD,bool);

void WriteLog(char *szString)
{
}

int Check4FileSize(char * pszFile2Check)
{
	int	iRetValue = -1;

	FILE* fp = fopen(pszFile2Check, "rb");
	if (fp == NULL)
	{
		return iRetValue;
	}
	fseek(fp, 0x00, SEEK_END);
	iRetValue = ftell(fp);

	fclose(fp);
	fp = NULL;

	return iRetValue;
}

extern "C" __declspec(dllexport) bool UnPackUPXFile64(char *pFileName, char *pUnpackFileName)
{
	
	bool bRetStatus = false;
	if (pFileName == NULL || pUnpackFileName == NULL)
	{
		return bRetStatus;
	}

	do_one_file(pFileName, pUnpackFileName);

	OutputDebugStringA(pFileName);
	OutputDebugStringA(pUnpackFileName);

	int iOriginalFileSize = Check4FileSize(pFileName);
	int iUnpackFileSize = Check4FileSize(pUnpackFileName);

	TCHAR szLog[MAX_PATH] = { 0x00 };
	_swprintf(szLog, L"iOriginalFileSize : %d", iOriginalFileSize);


	TCHAR szLog1[MAX_PATH] = { 0x00 };
	_swprintf(szLog1, L"iUnpackFileSize :%d", iUnpackFileSize);

	OutputDebugString(szLog);
	OutputDebugString(szLog1);
	if (iUnpackFileSize >= iOriginalFileSize)
	{
		OutputDebugString(L"UNPACK SUCCESSFULL");
		return true;
	}
	return false;

}

