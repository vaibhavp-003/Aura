
/*=============================================================================
FILE		           : CommonFileIntegrityCheck.cpp
ABSTRACT		       : 
DOCUMENTS	       : 
AUTHOR		       : Sandip Sanap
COMPANY		       : Aura 
COPYRIGHT NOTICE    :
					(C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura.	
CREATION DATE      : 14-Nov-2009
NOTES		      : This class containts commaon functions needed for file integirty check.
VERSION HISTORY    : 

=============================================================================*/
#include "pch.h"
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "CommonFileIntegrityCheck.h"

//#define _UNICODE 1
//#define UNICODE 1

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

bool GetMD5Signature32(const char *filepath, char *cMD5Signature);

/*--------------------------------------------------------------------------------------
Function       : CCommonFileIntegrityCheck
In Parameters  : TCHAR * szDBPath, 
Out Parameters : 
Description    : Constructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CCommonFileIntegrityCheck::CCommonFileIntegrityCheck(LPCTSTR szDBPath):m_objNameMD5Db(false, true)
{
	_tcscpy_s(m_szDBPath, szDBPath);
	//AddLogEntry(_T("CCommonFileIntegrityCheck :DB Path : %s"), (CString)m_szDBPath);
	m_objNameMD5Db.Load(m_szDBPath);
}

/*--------------------------------------------------------------------------------------
Function       : ~CCommonFileIntegrityCheck
In Parameters  : void, 
Out Parameters : 
Description    : Destructor
Author         : Sandip Sanap
--------------------------------------------------------------------------------------*/
CCommonFileIntegrityCheck::~CCommonFileIntegrityCheck(void)
{
	if(m_bSave)
	{
		m_objNameMD5Db.Balance();
		m_objNameMD5Db.Save(m_szDBPath);
	}
}

/*-------------------------------------------------------------------------------------
Function		: AddFile
In Parameters	: const TCHAR * szFilePath, const TCHAR * szMD5
Out Parameters	: bool
Purpose			: Add binary file name and md5 signature in database
Author			: Sandip
--------------------------------------------------------------------------------------*/
bool CCommonFileIntegrityCheck::AddFile(const TCHAR * szFilePath, const TCHAR * szMD5)
{
	m_objNameMD5Db.AppendItem(szFilePath, szMD5);
	m_bSave = true;
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: DeleteDBFile
In Parameters	: const TCHAR * szFilePath
Out Parameters	: bool
Purpose			: Deletefile from the database
Author			: Sandip
--------------------------------------------------------------------------------------*/
bool CCommonFileIntegrityCheck::DeleteDBFile(const TCHAR * szFilePath)
{
	m_objNameMD5Db.DeleteItem(szFilePath); 
	m_bSave = true;
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: CheckMD5
In Parameters	: const TCHAR * szFilePath, const TCHAR * szMD5
Out Parameters	: bool
Purpose			: This function will check that given file name with md5 presents in DB or not
Author			: Sandip
--------------------------------------------------------------------------------------*/
bool CCommonFileIntegrityCheck::CheckMD5(const TCHAR * szFilePath, const TCHAR * szMD5)
{
	TCHAR szTempMD5[MAX_PATH] ={0 };
	m_objNameMD5Db.SearchItem(szFilePath, (LPTSTR &)szTempMD5);
	if(!_tcsicmp(szTempMD5, szMD5))
	{
		return true;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
Function		: GetSignature
In Parameters	: TCHAR * szFilePath, TCHAR * szMd5
Out Parameters	: TCHAR *
Purpose			: retrive the signature of the given file
Author			: Sandip
--------------------------------------------------------------------------------------*/
TCHAR * CCommonFileIntegrityCheck::GetSignature(TCHAR * szFilePath, TCHAR * szMd5)
{
	if(_tcslen(szFilePath) > 0)
	{
		CStringA csFilePath(szFilePath);
		char cMD5Signature[33] = {0};
		if(GetMD5Signature32((LPCSTR)csFilePath, cMD5Signature))
		{
			CString csSignature(cMD5Signature);
			_tcscpy_s(szMd5, MAX_PATH, (LPCTSTR)csSignature);
		}
	}
	return _T("");
}

/*-------------------------------------------------------------------------------------
Function		: ReadINIAndCreateDB
In Parameters	: const TCHAR * szINIPath
Out Parameters	: bool
Purpose			: read given ini file and create the File Inntegrity Check Database
Author			: Sandip
--------------------------------------------------------------------------------------*/
bool CCommonFileIntegrityCheck::ReadINIAndCreateDB(const TCHAR * szINIPath)
{
	TCHAR  szCount[MAX_PATH] ={0 };
	int iCnt;
	GetPrivateProfileString(_T("FileInfo"), _T("cnt"), NULL, szCount, MAX_PATH, szINIPath);
	iCnt = _wtoi(szCount);
	for(int i=0; i<iCnt; i++)
	{
		TCHAR szPath[MAX_PATH]={0};
		TCHAR  szFilePath[MAX_PATH] ={0 };
		TCHAR *pdest;
		wsprintf(szCount, L"%d", i);
		GetPrivateProfileString(_T("FileInfo"), szCount, NULL, szFilePath, MAX_PATH, szINIPath);
		_tcscpy_s(szPath, szFilePath);
	
		CString csTemp(szFilePath);
		VerifyEmbeddedSignature(csTemp);

		pdest = _tcsrchr(szPath, _T('\\')) +1;
		if(pdest)
		{
			TCHAR szMD5[MAX_PATH]={0};
			GetSignature(szFilePath, szMD5);
			if(_tcslen(szMD5) > 0 &&_tcslen(szFilePath) > 0)
			{
				AddFile(pdest, szMD5);
			}
			else
			{
				AfxMessageBox(szFilePath);
			}
		}
	}
	return true;
}

/*-------------------------------------------------------------------------------------
Function		: CheckBinaryFileMD5
In Parameters	: TCHAR * szAppPath
Out Parameters	: bool
Purpose			: This function will check the MD5 of binary presents on client machine
matches with our Database MD5 or not
Author			: Sandip
--------------------------------------------------------------------------------------*/
bool CCommonFileIntegrityCheck::CheckBinaryFileMD5(LPCTSTR szAppPath)
{
	bool bReturn = true;
	try
	{
		LPVOID posUserName = m_objNameMD5Db.GetFirst();
		if(posUserName == NULL)
		{
			AddLogEntry(L"m_objNameMD5Db is empty");
			bReturn = false;
		}
		while(posUserName)
		{
			LPTSTR strFileName = NULL;
			LPTSTR strDBMD5 = NULL;
			m_objNameMD5Db.GetKey(posUserName, strFileName);
			m_objNameMD5Db.GetData(posUserName, strDBMD5);
			TCHAR szFileMD5[MAX_PATH]={0};
			TCHAR szFullFilePath[MAX_PATH]={0};
			_tcscat_s(szFullFilePath, szAppPath);
			_tcscat_s(szFullFilePath, strFileName);
			GetSignature(szFullFilePath, szFileMD5);

			if(!_tcsicmp(strFileName, L"vipre.dll"))
			{
			}
			else if(_tcsicmp(szFileMD5, strDBMD5))
			{
				bReturn =  false;
				AddLogEntry(_T("Mismatch Found: %s"), strFileName);
				AddLogEntry(_T("      File MD5: %s"), szFileMD5);
				AddLogEntry(_T("      DB   MD5: %s"), strDBMD5);
			}
			posUserName = m_objNameMD5Db.GetNext(posUserName);
		}
	}
	catch(...)
	{
		bReturn =  false;
		AddLogEntry(L"Error in CCommonFileIntegrityCheck::CheckBinaryFileMD5");
	}
	return bReturn;
}

BOOL CCommonFileIntegrityCheck::VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

	memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = 0;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwProvFlags = WTD_SAFER_FLAG;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

	lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus) 
    {
        case ERROR_SUCCESS:
			//OutputDebugString (_T("The File Digitally Signned  " + (CString)pwszSourceFile ));
            break;
        
        case TRUST_E_NOSIGNATURE:
            
			dwLastError = GetLastError();
            if (TRUST_E_NOSIGNATURE == dwLastError ||
                    TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
                    TRUST_E_PROVIDER_UNKNOWN == dwLastError) 
            {
                AfxMessageBox (L"The File has been not Digitally Signed \n" + (CString) pwszSourceFile);
            } 
            else 
            {
                // The signature was not valid or there was an error 
                // opening the file.
                wprintf_s(L"An unknown error occurred trying to "
                    L"verify the signature of the \"%s\" file.\n",
                    pwszSourceFile);
				AfxMessageBox (L"An unknown error occurred trying to verify the signature of the File \n" + (CString) pwszSourceFile);
            }

            break;

        case TRUST_E_EXPLICIT_DISTRUST:
            // The hash that represents the subject or the publisher 
            // is not allowed by the admin or user.
            wprintf_s(L"The signature is present, but specifically "
                L"disallowed.\n");
			AfxMessageBox (L"The signature is present For File %s but specifically disallowed \n " + (CString) pwszSourceFile);
            break;

        case TRUST_E_SUBJECT_NOT_TRUSTED:
            // The user clicked "No" when asked to install and run.
            wprintf_s(L"The signature is present, but not "
                L"trusted.\n");
			AfxMessageBox (L"The signature is present For File %s but not trusted \n" + (CString) pwszSourceFile);
            break;

        case CRYPT_E_SECURITY_SETTINGS:
            /*
            The hash that represents the subject or the publisher 
            was not explicitly trusted by the admin and the 
            admin policy has disabled user trust. No signature, 
            publisher or time stamp errors.
            */
            wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
                L"representing the subject or the publisher wasn't "
                L"explicitly trusted by the admin and admin policy "
                L"has disabled user trust. No signature, publisher "
                L"or timestamp errors.\n");
            break;

        default:
            // The UI was disabled in dwUIChoice or the admin policy 
            // has disabled user trust. lStatus contains the 
            // publisher or time stamp chain error.
            wprintf_s(L"Error is: 0x%x.\n",
                lStatus);
            break;
    }

    return true;
}
