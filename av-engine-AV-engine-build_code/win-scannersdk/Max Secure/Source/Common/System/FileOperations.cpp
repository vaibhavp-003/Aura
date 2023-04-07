/*======================================================================================
FILE             : FileOperations.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
-------------------Created as an unpublished copyright work.  All rights reserved.
-------------------This document and the information it contains is confidential and
-------------------proprietary to Aura.  Hence, it may not be
-------------------used, copied, reproduced, transmitted, or stored in any form or by any
-------------------means, electronic, recording, photocopying, mechanical or otherwise,
-------------------without the prior written permission of Aura.
CREATION DATE   : 8/1/2009 7:55:44 PM
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#include "pch.h"
#include "FileOperations.h"
#include "CPUInfo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/*--------------------------------------------------------------------------------------
Function       : CFileOperations::CFileOperations
In Parameters  :
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CFileOperations::CFileOperations()
{

}

/*--------------------------------------------------------------------------------------
Function       : CFileOperations::~CFileOperations
In Parameters  :
Out Parameters :
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
CFileOperations::~CFileOperations()
{

}

/*--------------------------------------------------------------------------------------
Function       : CFileOperations::CryptData
In Parameters  : DWORD * Data, DWORD dwDataSize, char * key, unsigned long keylen,
Out Parameters : void
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
void CFileOperations::CryptData(DWORD * Data, DWORD dwDataSize, char * key, unsigned long keylen)
{
	//we will consider size of sbox 256 bytes
	//(extra byte are only to prevent any mishep just in case)
	DWORD Sbox[257], Sbox2[257];
	unsigned long i, j, t, x;

	//this unsecured key is to be used only when there is no input key from user
	static const DWORD OurUnSecuredKey[] = {0xFFAAFFAA, 0xAAFCAAFC, 0xA37EA37E, 
											0xB34EB34E, 0xFFFFFFFF, 0x3BE73BE7,
											0xCBA9CBA9, 0x23C123C1, 0x2E6C2E6C,
											0x13CB13CB, 0x64E764E7, 0x34D234D2};

	static const int OurKeyLen = sizeof(OurUnSecuredKey)/sizeof(OurUnSecuredKey[0]);
	DWORD temp, k;
	temp = i = j = k = t =  x = 0;

	//always initialize the arrays with zero
	memset(Sbox, 0, sizeof(Sbox));
	memset(Sbox2, 0, sizeof(Sbox2));

	//initialize sbox i
	for(i = 0; i < 256U; i++)
	{
		Sbox[i] = (DWORD)0xFFFFFFFF - (DWORD)i;
	}
	j = 0;
	//whether user has sent any inpur key
	if(keylen)
	{
		//initialize the sbox2 with user key
		for(i = 0; i < 256U; i++)
		{
			if(j == keylen)
			{
				j = 0;
			}
			Sbox2[i] = key[j++];
		}
	}
	else
	{
		//initialize the sbox2 with our key
		for(i = 0; i < 256U; i++)
		{
			if(j == OurKeyLen)
			{
				j = 0;
			}
			Sbox2[i] = OurUnSecuredKey[j++];
		}
	}

	j = 0; //Initialize j
	//scramble sbox1 with sbox2
	for(i = 0; i < 256; i++)
	{
		j = (j + (unsigned long)Sbox[i] + (unsigned long)Sbox2[i])% 256U;
		temp =  Sbox[i];
		Sbox[i] = Sbox[j];
		Sbox[j] =  temp;
	}

	i = j = 0;
	for(x = 0; x < dwDataSize; x++)
	{
		//increment i
		i = (i + 1U)% 256U;
		//increment j
		j = (j + (unsigned long)Sbox[i])% 256U;

		//Scramble SBox #1 further so encryption routine will
		//will repeat itself at great interval
		temp = Sbox[i];
		Sbox[i] = Sbox[j];
		Sbox[j] = temp;

		//Get ready to create pseudo random  byte for encryption key
		t = ((unsigned long)Sbox[i] + (unsigned long)Sbox[j])%  256U;

		//get the random byte
		k = Sbox[t];

		//xor with the data and done
		Data[x] = (Data[x] ^ (DWORD)k);
	}
}

/*--------------------------------------------------------------------------------------
Function       : CFileOperations::CryptFile
In Parameters  : const TCHAR *csFileName, const TCHAR *csCryptFileName,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CFileOperations::CryptFile(const TCHAR *csFileName, const TCHAR *csCryptFileName)
{
	bool bReadError = false;
	BYTE * ReadBuffer = NULL;
	HANDLE hFile = 0, hCryptFile = 0;
	DWORD dwFileSize = 0, dwBytesRead = 0, dwBytesToRead = 0, dwTotalBytesRead = 0;
	DWORD dwReadBufferSize = 1024 * 512, dwRemainingData = 0;

	hFile = CreateFile(csFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	hCryptFile = CreateFile(csCryptFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
							0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return false;
	}

	dwFileSize = GetFileSize(hFile, 0);
	ReadBuffer = new BYTE[dwReadBufferSize];

	dwRemainingData = dwFileSize % 4;
	dwFileSize = dwFileSize - dwRemainingData;

	while(!bReadError && dwTotalBytesRead < dwFileSize)
	{
		if(dwFileSize - dwTotalBytesRead >= dwReadBufferSize)
		{
			dwBytesToRead = dwReadBufferSize;
		}
		else
		{
			dwBytesToRead = dwFileSize - dwTotalBytesRead;
		}

		ReadFile(hFile, ReadBuffer, dwBytesToRead, &dwBytesRead, 0);
		if(dwBytesToRead != dwBytesRead)
		{
			bReadError = true;
		}

		dwTotalBytesRead += dwBytesRead;

		CryptData((DWORD*)ReadBuffer, dwBytesRead / 4);
		WriteFile(hCryptFile, ReadBuffer, dwBytesRead, &dwBytesRead, 0);
	}

	if(dwRemainingData <= 3)
	{
		BYTE Buffer[3] = {0};
		ReadFile(hFile, Buffer, dwRemainingData, &dwBytesRead, 0);
		for(DWORD dwIndex = 0; dwIndex < dwBytesRead; dwIndex++)
		{
			Buffer[dwIndex] ^= (BYTE)141;
		}

		WriteFile(hCryptFile, Buffer, dwBytesRead, &dwBytesRead, 0);
	}

	CloseHandle(hFile);
	CloseHandle(hCryptFile);
	delete [] ReadBuffer;
	ReadBuffer = NULL;
	return true;
}

/*--------------------------------------------------------------------------------------
Function       : CFileOperations::ProcessDatabase
In Parameters  : LPCWSTR lstrFileName, CObject &objDatabaseMap, bool bSave,
Out Parameters : bool
Description    :
Author & Date  : Darshan Singh Virdi & 1 Aug, 2009.
--------------------------------------------------------------------------------------*/
bool CFileOperations::ProcessDatabase(LPCWSTR lstrFileName, CObject &objDatabaseMap, bool bSave)
{
	WCHAR strFullFile[MAX_PATH] = {0};
	if(wcsrchr(lstrFileName, '\\')== NULL)
	{
		GetModuleFileName(NULL, strFullFile, MAX_PATH);
		WCHAR *cExtPtr = wcsrchr(strFullFile, '\\');
		*cExtPtr = '\0';
		wcscat_s(strFullFile, _T("\\Data\\"));
		wcscat_s(strFullFile, lstrFileName);
	}
	else
	{
		wcscpy_s(strFullFile, lstrFileName);

	}

	WCHAR wsTempFileName[MAX_PATH] = {0};
	wcscpy_s(wsTempFileName, MAX_PATH, strFullFile);
	wcscat_s(wsTempFileName, MAX_PATH, L".tmp");

	if(!bSave)
	{
		if(!CryptFile(strFullFile, wsTempFileName))
		{
			return false;
		}
	}

	CFile theFile;
	if(!theFile.Open(wsTempFileName, (bSave ? CFile::modeWrite|CFile::modeCreate : CFile::modeRead|CFile::shareDenyNone)))
	{
		return false;
	}
	CArchive archive(&theFile, (bSave ? CArchive::store : CArchive::load));
	objDatabaseMap.Serialize(archive);
	archive.Close();
	theFile.Close();

	if(bSave)
	{
		if(!CryptFile(wsTempFileName, strFullFile))
		{
			return false;
		}
	}
	::DeleteFile(wsTempFileName);
	return true;
}

BOOL CFileOperations::ParseInfo(CString csFilePath)
{
	BOOL bRet = FALSE;
	HANDLE hFileHandle = CreateFile(csFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(INVALID_HANDLE_VALUE == hFileHandle)
	{
		return bRet;
	}

	const int BUFF_SIZE = 0x200;
	BYTE byBuff[BUFF_SIZE] = {0};	
	DWORD dwBytesRead = 0;
	
	::SetFilePointer(hFileHandle, GetFileSize(hFileHandle, NULL) - BUFF_SIZE, 0, FILE_BEGIN);
	if(!ReadFile(hFileHandle, byBuff, BUFF_SIZE, &dwBytesRead, NULL))
	{
		return bRet;
	}
	if(dwBytesRead == 0)
	{
		return bRet;
	}

	const BYTE START_TAG[] = {0x21, 0x53, 0x23};
	const BYTE END_TAG[] = {0x21, 0x45, 0x23};
	bool bFoundStartTag = false;
	DWORD dwValNameLen = 0, dwValDataLen = 0;
	BYTE byTemp[MAX_PATH] = {0};
	TCHAR szValName[MAX_PATH] = {0}, szValData[MAX_PATH] = {0}; 
	
	CRegistry objReg;
	CCPUInfo objSystem;
	if(TRUE == objSystem.isOS64bit())
	{
		objReg.SetWow64Key(true);
	}
	CString csServerVer;
	HKEY hKey = NULL;
	CString csKeyName = _T("");
	return bRet;
	csKeyName += TRACKER_KEY;
	objReg.CreateKey(csKeyName, hKey, HKEY_LOCAL_MACHINE);	
			
	for(DWORD dwOffset = 0; dwOffset < BUFF_SIZE; dwOffset++)
	{
		if(!bFoundStartTag && memcmp(&byBuff[dwOffset], START_TAG, sizeof(START_TAG)) != 0)
		{
			continue;
		}
		if(!bFoundStartTag)
		{
			bFoundStartTag = true;
			dwOffset += sizeof(START_TAG) + 1;
		}
		if(memcmp(&byBuff[dwOffset], END_TAG, sizeof(END_TAG)) == 0)
		{
			bRet = TRUE;
			break;
		}

		dwValNameLen = 0;
		while(byBuff[dwOffset + dwValNameLen] != '=')
		{
			dwValNameLen++;
		}
		memcpy(byTemp, &byBuff[dwOffset], dwValNameLen);
		byTemp[dwValNameLen]= '\0';
		_stprintf_s(szValName, MAX_PATH, L"%S", byTemp);

		dwValDataLen = 0;
		while(byBuff[dwOffset + dwValNameLen + dwValDataLen + 1] != 0x0A)
		{
			dwValDataLen++;
		}
		memcpy(byTemp, &byBuff[dwOffset + dwValNameLen + 1], dwValDataLen);
		byTemp[dwValDataLen]= '\0';
		_stprintf_s(szValData, MAX_PATH, L"%S", byTemp);
		
		if(_memicmp(szValName, L"DLY", 3) == 0)
		{
			int iVal = _tstoi(szValData);
			objReg.Set(csKeyName, TRACKER_DELAY_START, iVal, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"BI", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_QUERY, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"UL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_UNISTALL_URL, szValData, HKEY_LOCAL_MACHINE);
		}		
		else if(_memicmp(szValName, L"SL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_SUPPORT_URL, szValData, HKEY_LOCAL_MACHINE);
		}		
		else if(_memicmp(szValName, L"PL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_HOMEPAGE_URL, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"WL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_WELCOME_PAGE, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"GL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_BUYNOW_URL, szValData, HKEY_LOCAL_MACHINE);
		}
		else if(_memicmp(szValName, L"FL", 2) == 0)
		{
			objReg.Set(csKeyName, TRACKER_SETUP_NAME, szValData, HKEY_LOCAL_MACHINE);
		}	
		
		dwOffset += dwValNameLen + dwValDataLen + 1;
	}

	time_t tim = time(NULL);
	objReg.Set(csKeyName, TRACKER_INSTALL_DATE, tim, HKEY_LOCAL_MACHINE);

	GUID guid;
	CoCreateGuid(&guid); 
	
	const CComBSTR guidBstr(guid);  // Converts from binary GUID to BSTR
	CString guidStr(guidBstr); // Converts from BSTR to appropriate string, ANSI
	
	guidStr.Remove('{');
	guidStr.Remove('}');
	objReg.Set(csKeyName, TRACKER_MACHINE_GUID, guidStr, HKEY_LOCAL_MACHINE);
	
	CString csBuyNowLink = _T("");
	objReg.Get(csKeyName, TRACKER_BUYNOW_URL, csBuyNowLink, HKEY_LOCAL_MACHINE);
	csBuyNowLink.Replace(_T("%GID%"), guidStr);
	objReg.Set(csKeyName, TRACKER_BUYNOW_URL, csBuyNowLink, HKEY_LOCAL_MACHINE);
	
	GetOSVersion(szValData);
	objReg.Set(csKeyName, TRACKER_OS, szValData, HKEY_LOCAL_MACHINE);

	CString csTemp;
	DWORD dwBuffLen = MAX_PATH;
	TCHAR szCurrentUser[MAX_PATH] = {0};
	GetUserName(szCurrentUser, &dwBuffLen);
	objReg.Set(csKeyName, TRACKER_USER, szCurrentUser, HKEY_LOCAL_MACHINE);
	return bRet;	
}

void CFileOperations::GetOSVersion(LPTSTR szOSVer)
{
	SYSTEM_INFO si;
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	
	OSVERSIONINFOEX osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	BOOL bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*) &osvi);

	_tcscpy_s(szOSVer, MAX_PATH, UNTRACTED);

	if(bOsVersionInfoEx == NULL ) 
	{
		return;
	}

	// Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.	
	typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
	PGNSI pGNSI = (PGNSI) GetProcAddress(
		GetModuleHandle(TEXT("kernel32.dll")), 
		"GetNativeSystemInfo");
	if(NULL != pGNSI)
		pGNSI(&si);
	else GetSystemInfo(&si);	

	if ( VER_PLATFORM_WIN32_NT == osvi.dwPlatformId && 
		osvi.dwMajorVersion > 4 )
	{
		if ( osvi.dwMajorVersion == 6  && osvi.wProductType == VER_NT_WORKSTATION )
		{
			if( osvi.dwMinorVersion == 0 )
			{
				if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN_VISTA_64BIT);
				}
				else 
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN_VISTA_32BIT);
				}
			}				
			if ( osvi.dwMinorVersion == 1 )
			{				
				if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN7_64BIT);
				}
				else
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN7_32BIT);
				}
			}
			if(osvi.dwMinorVersion == 2 )
			{
				if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN8_64BIT);
				}
				else
				{
					_tcscpy_s(szOSVer, MAX_PATH, WIN8_32BIT);
				}
			}
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION &&
				si.wProcessorArchitecture== PROCESSOR_ARCHITECTURE_AMD64)
			{
				_tcscpy_s(szOSVer, MAX_PATH, WINXP_64BIT);
			}			
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
		{
			_tcscpy_s(szOSVer, MAX_PATH, WINXP_32BIT);
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
		{
			_tcscpy_s(szOSVer, MAX_PATH, WIN_2000);
		}		
	}
	return; 
}