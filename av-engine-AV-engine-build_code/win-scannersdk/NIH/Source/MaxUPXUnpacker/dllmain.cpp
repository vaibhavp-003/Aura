// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "MaxExceptionFilter.h"
#include "MaxPEFile.h"
#include "conf.h"

////extern CMaxPEFile fi->m_pInputFile.;
//DWORD fi->m_dwCodeOffset;
//DWORD fi->m_dwSigOffset;
//bool fi->m_bLZMA;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CMaxExceptionFilter::InitializeExceptionFilter();
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
	FILE * fp = 0;
	fopen_s(&fp, "C:\\UPXLog.txt", "a");
	if(fp)
	{
		fputs(szString, fp);
		fputs("\r\n", fp);
		fclose(fp);
	}
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
extern "C" __declspec(dllexport) bool UnPackUPXFile(char *pFileName, char *pUnpackFileName, DWORD dwCodeOffset, DWORD dwSigOffset, bool bLZMA)
{
	__try
	{
		bool bRetStatus = false;
		if(pFileName == NULL || pUnpackFileName == NULL )
		{
			return bRetStatus;
		}

		do_one_file(pFileName,pUnpackFileName,dwCodeOffset,dwSigOffset,bLZMA);

		int iOriginalFileSize = Check4FileSize(pFileName);
		int iUnpackFileSize = Check4FileSize(pUnpackFileName);

		if (iUnpackFileSize >= iOriginalFileSize)
		{
			return true;
		}

		/*fi->m_dwCodeOffset = dwCodeOffset;
		fi->m_dwSigOffset = dwSigOffset;
		fi->m_bLZMA = bLZMA;*/

		/*char *argv[5];

		argv[0] = NULL;

		argv[1] = new char[3];
		if(argv[1] == NULL)
		{
			return bRetStatus;
		}
		memset(argv[1], 0, 3);
		strcpy_s(argv[1], 3, "-d");

		DWORD	dwFilenameLen = strlen(pFileName);
		if(dwFilenameLen == 0)
		{
			return bRetStatus;
		}	
		argv[2] = new char [dwFilenameLen + 1];
		if(argv[2] == NULL)
		{
			return bRetStatus;
		}
		memset(argv[2], 0, dwFilenameLen + 1);
		strcpy_s(argv[2], dwFilenameLen + 1, pFileName);

		argv[3] = new char[3];
		if(argv[3] == NULL)
		{
			return bRetStatus;
		}
		memset(argv[3], 0, 3);
		strcpy_s(argv[3], 3, "-o");
		
		DWORD	dwUnpackFilenameLen = strlen(pUnpackFileName);
		if(dwUnpackFilenameLen == 0)
		{
			return bRetStatus;
		}

		argv[4] = new char [dwUnpackFilenameLen + 1];
		if(argv[4] == NULL)
		{
			return bRetStatus;
		}
		memset(argv[4], 0, dwUnpackFilenameLen + 1);
		strcpy_s(argv[4], dwUnpackFilenameLen + 1, pUnpackFileName);

		/*argv[5]= new char [sizeof(DWORD)];
		memset(argv[5],0,sizeof(DWORD));
		memcpy(argv[5],(char *)(&dwCodeOffset),sizeof(DWORD));

		argv[6]= new char [sizeof(DWORD)];
		memset(argv[6],0,sizeof(DWORD));
		memcpy(argv[6],(char *)&dwSigOffset,sizeof(DWORD));

		argv[7]= new char [sizeof(bool)];
		memset(argv[7],0,sizeof(bool));
		memcpy(argv[7],(char *)&bLZMA,sizeof(bool));*/


		/*WriteLog(argv[0]);
		WriteLog(argv[1]);
		WriteLog(argv[2]);
		WriteLog(argv[3]);
		WriteLog(argv[4]);
		WriteLog("\r\n\r\n\r\n");

		_main(5, argv,dwCodeOffset,dwSigOffset,bLZMA);
		
		delete []argv[1];
		delete []argv[2];
		delete []argv[3];
		delete []argv[4];*/

		//fi->m_pInputFile.CloseFile();
		return false;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), L"Exception caught in UPXUnpacker Dll"), L"", false)
	{
		//fi->m_pInputFile.CloseFile();
		WriteLog(pFileName);
	}
	return false;
}

