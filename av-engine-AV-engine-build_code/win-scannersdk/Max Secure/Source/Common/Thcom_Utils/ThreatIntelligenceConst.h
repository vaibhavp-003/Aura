#pragma once
#include "atlstr.h"

#define _MAX_THREAT_INTELLIGENCE_DB		_T("ThreatIntelligence.db");
#define _MAX_THREAT_INTELLIGENCE_DB1	_T("\\ThreatIntelligence.db");
#define _MAx_SCAN_DETAILS_DB			_T("SecScanDtls");
#define _MAX_POLICIES_DB				_T("ThinClntDtls");

const CString _MAX_TI_SCN_MUTEX	=	_T("$_TI_SCN_ON_$");

typedef struct _UNSAFE_FILE_INFO
{
	TCHAR	szFilePath[1024];
	TCHAR	szHuerFilePath[1024];
	TCHAR	szMD5[33];
	TCHAR	szSHA256[66];
	TCHAR	szPESig[20];
	TCHAR	szFileSize[10];
	TCHAR	szProbability[10];
	TCHAR	szScanTime[50];	
	ULONG64	ulSignature;
}UNSAFE_FILE_INFO,*LPUNSAFE_FILE_INFO;


typedef struct _UNSAFE_FILE_FULL_INFO
{
	TCHAR	szFilePath[1024];
	TCHAR	szHuerFilePath[1024];
	TCHAR	szMD5[33];
	TCHAR	szSHA256[66];
	TCHAR	szPESig[20];
	TCHAR	szFileSize[10];
	TCHAR	szProbability[10];
	TCHAR	szScanTime[50];	
	int		iDetectionStatus;
	TCHAR	szSpyName[MAX_PATH];
	int		iSpyID;
	int		iScannerName;
	int		iAction;
	int		iActionStatus;
	int		iFileType;
	int		iInfoUpload;
	int		iISFileUploaded;
	int		iThreatID;
	int		iScanDone;
	DWORD	dwScannerID;
}UNSAFE_FILE_FULL_INFO,*LPUNSAFE_FILE_FULL_INFO;


