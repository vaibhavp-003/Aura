#include "pch.h"
#include "MaxDigitalSigCheck.h"
#include "MaxExceptionFilter.h"
//#include <Softpub.h>
//#include <wincrypt.h>
//#include <wintrust.h>

// Link with the Wintrust.lib file.
//#pragma comment (lib, "wintrust")



CMaxDigitalSigCheck::CMaxDigitalSigCheck(void)
{
	m_bDigitalScanLoaded = false;
}

CMaxDigitalSigCheck::~CMaxDigitalSigCheck(void)
{
	UnLoadWinTrust();
}

bool CMaxDigitalSigCheck::CheckDigitalSign(LPCTSTR pszDBPath)
{
	bool bReturn = false;
	//bReturn =  VerifySignature(pszDBPath);
	
	__try
	{
		if(m_bDigitalScanLoaded)
		{
			/*bReturn =  IsFileDigitallySigned(pszDBPath);
			if(bReturn == false)
			{
				bReturn =  IsCatDigitallySigned(pszDBPath);
			}*/
			bReturn =  IsCatDigitallySigned(pszDBPath);
		}
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in CMaxDigitalSigCheck::CheckDigitalSign")))
	{
		return false;
	}
	return bReturn;
}
bool CMaxDigitalSigCheck::IsCatDigitallySigned(LPCTSTR FilePath)
{	
	//PVOID Context;
	HCATADMIN hContext = NULL;
	HCATINFO hCatalogContext = NULL;
	HANDLE hFileHandle;
	DWORD dwHashSize = 0;
	PBYTE pbyBuffer = NULL;
	//PVOID CatalogContext;
	CATALOG_INFO InfoStruct;
	WINTRUST_DATA WintrustStructure;
	WINTRUST_CATALOG_INFO WintrustCatalogStructure;
	
	PWCHAR pszMemberTag = NULL;
	BOOLEAN bReturnFlag = FALSE;
	ULONG ulReturnVal = 0;
	//CString csLog;

	GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	//Zero our structures.
	
	memset(&InfoStruct, 0, sizeof(CATALOG_INFO));
	InfoStruct.cbStruct = sizeof(CATALOG_INFO);

	memset(&WintrustCatalogStructure, 0, sizeof(WINTRUST_CATALOG_INFO));
	memset(&WintrustStructure, 0, sizeof(WINTRUST_DATA));

	if(m_bSha256)
	{
		if (!m_lpfnCryptCATAdminAcquireContext2(&hContext, NULL, BCRYPT_SHA256_ALGORITHM, NULL, 0))
		{
			return FALSE;
		}
	}
	else
	{
		if (!m_lpfnCryptCATAdminAcquireContext(&hContext, NULL, 0))
		{
			return FALSE;
		}
	}
	//Open file.
	hFileHandle = CreateFileW(FilePath, GENERIC_READ, 7, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFileHandle)
	{
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		hContext = NULL;
		return FALSE;
	}
	
	//Get the size we need for our hash.
	//CryptCATAdminCalcHashFromFileHan(FileHandle, &HashSize, NULL, 0);
	if(m_bSha256)
	{
		m_lpfnCryptCATAdminCalcHashFromFileHandle2(hContext, hFileHandle, &dwHashSize, NULL, 0);
	}
	else
	{
		m_lpfnCryptCATAdminCalcHashFromFileHandle(hFileHandle, &dwHashSize, NULL, 0);
	}
	if (dwHashSize == 0)
	{
		//0-sized has means error!
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		hContext = NULL;
		CloseHandle(hFileHandle); 
		hFileHandle = NULL;
		return FALSE;
	}
	//Allocate memory.
	pbyBuffer = (PBYTE)calloc(dwHashSize, 1);
	if(m_bSha256)
	{
		if (!m_lpfnCryptCATAdminCalcHashFromFileHandle2(hContext, hFileHandle, &dwHashSize, pbyBuffer, 0))
		{
			m_lpfnCryptCATAdminReleaseContext(hContext, 0);
			hContext = NULL;
			free(pbyBuffer); 
			pbyBuffer = NULL;
			CloseHandle(hFileHandle);
			hFileHandle = NULL;
			return FALSE;
		}
	}
	else
	{
		if(!m_lpfnCryptCATAdminCalcHashFromFileHandle(hFileHandle, &dwHashSize, pbyBuffer, 0))
		{
			m_lpfnCryptCATAdminReleaseContext(hContext, 0);
			hContext = NULL;
			free(pbyBuffer); 
			pbyBuffer = NULL;
			CloseHandle(hFileHandle);
			hFileHandle = NULL;
			return FALSE;
		}
	}

	//Convert the hash to a string.
	pszMemberTag = (PWCHAR)calloc((dwHashSize * 2) + 1, sizeof(WCHAR));
	for (unsigned int i = 0; i < dwHashSize; i++)
	{
		swprintf(&pszMemberTag[i * 2], L"%02X", pbyBuffer[i]);
	}

	//Get catalog for our context.
	hCatalogContext = m_lpfnCryptCATAdminEnumCatalogFromHash(hContext, pbyBuffer, dwHashSize, 0, NULL);
	if (hCatalogContext)
	{
		//If we couldn't get information
		if (!m_lpfnCryptCATCatalogInfoFromContext(hCatalogContext, &InfoStruct, 0))
		{
			//Release the context and set the context to null so it gets picked up below.
			m_lpfnCryptCATAdminReleaseCatalogContext(hContext, hCatalogContext, 0); 
			hCatalogContext = NULL;
		}
	}

	//If we have a valid context, we got our info.
	//Otherwise, we attempt to verify the internal signature.
	//If we get here, we have catalog info! Verify it.
	bool bRetValue = false;
	if(hCatalogContext)
	{
		WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
		//WintrustCatalogStructure.dwCatalogVersion = 0;
		WintrustCatalogStructure.pcwszCatalogFilePath = InfoStruct.wszCatalogFile;
		WintrustCatalogStructure.pcwszMemberFilePath = FilePath;
		WintrustCatalogStructure.pcwszMemberTag = pszMemberTag;
		WintrustCatalogStructure.hMemberFile = NULL;

		WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
		WintrustStructure.dwUnionChoice = WTD_CHOICE_CATALOG;
		WintrustStructure.pCatalog = &WintrustCatalogStructure;
		WintrustStructure.dwUIChoice = WTD_UI_NONE;
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;		
		WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustStructure.dwProvFlags = 0;
		WintrustStructure.hWVTStateData = NULL;
		WintrustStructure.pwszURLReference = NULL;
		WintrustStructure.pPolicyCallbackData = 0;
		WintrustStructure.pSIPClientData = 0;
		WintrustStructure.dwUIContext = WTD_UICONTEXT_EXECUTE;

		ulReturnVal = m_lpfnWinVerifyTrust(NULL, &ActionGuid, &WintrustStructure);
		//Check return.	
		bReturnFlag = SUCCEEDED(ulReturnVal);
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE;
		m_lpfnWinVerifyTrust(0, &ActionGuid, &WintrustStructure);
		bool bRetValue = false;
		switch (ulReturnVal) 
		{
		case ERROR_SUCCESS:
			bRetValue = true;
			break;

		case TRUST_E_NOSIGNATURE:
			break;

		case TRUST_E_EXPLICIT_DISTRUST:
			break;

		case TRUST_E_SUBJECT_NOT_TRUSTED:
			break;

		case CRYPT_E_SECURITY_SETTINGS:
			break;

		default:
			break;
		}
	}

	if(hContext != NULL)
	{
		if(hCatalogContext != NULL)
		{	
			m_lpfnCryptCATAdminReleaseCatalogContext(hContext, hCatalogContext, 0);
			 hCatalogContext = NULL;
		}
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		hContext = NULL;
	}

	if(pszMemberTag != NULL)
	{
		free(pszMemberTag);
		pszMemberTag = NULL;
	}
	if(pbyBuffer != NULL)
	{
		free(pbyBuffer);
		pbyBuffer = NULL;
	}
	if(hFileHandle != NULL)
	{
		CloseHandle(hFileHandle);
		hFileHandle =  NULL;
	}
	return bRetValue;
} 


bool CMaxDigitalSigCheck::IsFileDigitallySigned(LPCTSTR FilePath)
{
	
	//PVOID Context;
	WINTRUST_DATA WintrustStructure;
	WINTRUST_FILE_INFO WintrustFileStructure;

	BOOLEAN bReturnFlag = FALSE;
	ULONG ulReturnVal = 0;
	//CString csLog;

	GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	
	memset(&WintrustFileStructure, 0, sizeof(WINTRUST_FILE_INFO));
	memset(&WintrustStructure, 0, sizeof(WINTRUST_DATA));

	//Zero our structures.
	WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);
	WintrustFileStructure.pcwszFilePath = FilePath;
	WintrustFileStructure.hFile = NULL;
	WintrustFileStructure.pgKnownSubject = NULL;
	WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
	WintrustStructure.dwUnionChoice = WTD_CHOICE_FILE;
	WintrustStructure.pFile = &WintrustFileStructure;
	WintrustStructure.dwUIChoice = WTD_UI_NONE;
	WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
	//WintrustStructure.dwStateAction = WTD_STATEACTION_IGNORE;
	WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
	WintrustStructure.dwProvFlags = 0;
	WintrustStructure.hWVTStateData = NULL;
	WintrustStructure.pwszURLReference = NULL;
	//Fill in catalog info structure.
	ulReturnVal = m_lpfnWinVerifyTrust(NULL, &ActionGuid, &WintrustStructure);
	//Check return.	
	bReturnFlag = SUCCEEDED(ulReturnVal);
	//if (bReturnFlag)
	//{
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE;
		m_lpfnWinVerifyTrust(0, &ActionGuid, &WintrustStructure);
	//}	
	bool bRetValue = false;
	switch (ulReturnVal) 
	{
	case ERROR_SUCCESS:
		bRetValue = true;

		break;

	case TRUST_E_NOSIGNATURE:
		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		break;

	default:
		break;
	}
	return bRetValue;
} 
bool CMaxDigitalSigCheck::IsFileDigitallySignedEX(LPCTSTR FilePath)
{
	
	//PVOID Context;
	HCATADMIN hContext = NULL;
	HCATINFO hCatalogContext = NULL;
	HANDLE hFileHandle;
	DWORD dwHashSize = 0;
	PBYTE pbyBuffer = NULL;
	//PVOID CatalogContext;
	CATALOG_INFO InfoStruct;
	WINTRUST_DATA WintrustStructure;
	WINTRUST_CATALOG_INFO WintrustCatalogStructure;
	WINTRUST_FILE_INFO WintrustFileStructure;

	PWCHAR pszMemberTag = NULL;
	BOOLEAN bReturnFlag = FALSE;
	ULONG ulReturnVal = 0;
	//CString csLog;

	GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	//Zero our structures.
	
	memset(&InfoStruct, 0, sizeof(CATALOG_INFO));
	InfoStruct.cbStruct = sizeof(CATALOG_INFO);

	memset(&WintrustCatalogStructure, 0, sizeof(WINTRUST_CATALOG_INFO));
	//WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);

	memset(&WintrustFileStructure, 0, sizeof(WINTRUST_FILE_INFO));
	WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);

	memset(&WintrustStructure, 0, sizeof(WINTRUST_DATA));

	if(m_bSha256)
	{
		if (!m_lpfnCryptCATAdminAcquireContext2(&hContext, NULL, BCRYPT_SHA256_ALGORITHM, NULL, 0))
		{
			return FALSE;
		}
	}
	else
	{
		if (!m_lpfnCryptCATAdminAcquireContext(&hContext, NULL, 0))
		{
			return FALSE;
		}
	}
	//Open file.
	hFileHandle = CreateFileW(FilePath, GENERIC_READ, 7, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFileHandle)
	{
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		return FALSE;
	}
	
	//Get the size we need for our hash.
	//CryptCATAdminCalcHashFromFileHan(FileHandle, &HashSize, NULL, 0);
	if(m_bSha256)
	{
		m_lpfnCryptCATAdminCalcHashFromFileHandle2(hContext, hFileHandle, &dwHashSize, NULL, 0);
	}
	else
	{
		m_lpfnCryptCATAdminCalcHashFromFileHandle(hFileHandle, &dwHashSize, NULL, 0);
	}
	if (dwHashSize == 0)
	{
		//0-sized has means error!
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		CloseHandle(hFileHandle); return FALSE;
	}
	//Allocate memory.
	pbyBuffer = (PBYTE)calloc(dwHashSize, 1);
	if(m_bSha256)
	{
		if (!m_lpfnCryptCATAdminCalcHashFromFileHandle2(hContext, hFileHandle, &dwHashSize, pbyBuffer, 0))
	{
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		free(pbyBuffer); CloseHandle(hFileHandle);
		return FALSE;
	}
	}
	else
	{
		if(!m_lpfnCryptCATAdminCalcHashFromFileHandle(hFileHandle, &dwHashSize, pbyBuffer, 0))
	{
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		free(pbyBuffer); CloseHandle(hFileHandle);
		return FALSE;
	}
	}

	//Convert the hash to a string.
	pszMemberTag = (PWCHAR)calloc((dwHashSize * 2) + 1, sizeof(WCHAR));
	for (unsigned int i = 0; i < dwHashSize; i++)
	{
		swprintf(&pszMemberTag[i * 2], L"%02X", pbyBuffer[i]);
	}

	//Get catalog for our context.
	hCatalogContext = m_lpfnCryptCATAdminEnumCatalogFromHash(hContext, pbyBuffer, dwHashSize, 0, NULL);
	if (hCatalogContext)
	{
		//If we couldn't get information
		if (!m_lpfnCryptCATCatalogInfoFromContext(hCatalogContext, &InfoStruct, 0))
		{
			//Release the context and set the context to null so it gets picked up below.
			m_lpfnCryptCATAdminReleaseCatalogContext(hContext, hCatalogContext, 0); hCatalogContext = NULL;
		}
	}

	//If we have a valid context, we got our info.
	//Otherwise, we attempt to verify the internal signature.
	bool bFileCat = false;
	if (!hCatalogContext)
	{
		WintrustFileStructure.cbStruct = sizeof(WINTRUST_FILE_INFO);
		WintrustFileStructure.pcwszFilePath = FilePath;
		WintrustFileStructure.hFile = NULL;
		WintrustFileStructure.pgKnownSubject = NULL;
		WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
		WintrustStructure.dwUnionChoice = WTD_CHOICE_FILE;
		WintrustStructure.pFile = &WintrustFileStructure;
		WintrustStructure.dwUIChoice = WTD_UI_NONE;
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;
		//WintrustStructure.dwStateAction = WTD_STATEACTION_IGNORE;
		WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustStructure.dwProvFlags = 0;
		WintrustStructure.hWVTStateData = NULL;
		WintrustStructure.pwszURLReference = NULL;
	}
	else
	{
		//If we get here, we have catalog info! Verify it.
		WintrustCatalogStructure.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
		//WintrustCatalogStructure.dwCatalogVersion = 0;
		WintrustCatalogStructure.pcwszCatalogFilePath = InfoStruct.wszCatalogFile;
		WintrustCatalogStructure.pcwszMemberFilePath = FilePath;
		WintrustCatalogStructure.pcwszMemberTag = pszMemberTag;
		WintrustCatalogStructure.hMemberFile = NULL;
		
		WintrustStructure.cbStruct = sizeof(WINTRUST_DATA);
		WintrustStructure.dwUnionChoice = WTD_CHOICE_CATALOG;
		WintrustStructure.pCatalog = &WintrustCatalogStructure;
		WintrustStructure.dwUIChoice = WTD_UI_NONE;
		WintrustStructure.fdwRevocationChecks = WTD_REVOKE_NONE;		
		WintrustStructure.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustStructure.dwProvFlags = 0;
		WintrustStructure.hWVTStateData = NULL;
		WintrustStructure.pwszURLReference = NULL;
		WintrustStructure.pPolicyCallbackData = 0;
		WintrustStructure.pSIPClientData = 0;
		WintrustStructure.dwUIContext = WTD_UICONTEXT_EXECUTE;
		//Fill in catalog info structure.
		bFileCat = true;
	}
	//Call our verification function.
	ulReturnVal = m_lpfnWinVerifyTrust(NULL, &ActionGuid, &WintrustStructure);
	//Check return.	
	bReturnFlag = SUCCEEDED(ulReturnVal);
	bool bFlag = false;
	switch (ulReturnVal) 
	{
	case ERROR_SUCCESS:
		break;

	case TRUST_E_NOSIGNATURE:
		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		break;

	default:
		break;
	}

	//If we successfully verified, we need to free.
	if (bReturnFlag)
	{
		WintrustStructure.dwStateAction = WTD_STATEACTION_CLOSE;
		m_lpfnWinVerifyTrust(0, &ActionGuid, &WintrustStructure);
	}
	if(hContext != NULL)
	{
		if(hCatalogContext != NULL)
		{	
			m_lpfnCryptCATAdminReleaseCatalogContext(hContext, hCatalogContext, 0);
			 hCatalogContext = NULL;
		}
		m_lpfnCryptCATAdminReleaseContext(hContext, 0);
		hContext = NULL;
	}

	if(pszMemberTag != NULL)
	{
		free(pszMemberTag);
		pszMemberTag = NULL;
	}
	if(pbyBuffer != NULL)
	{
		free(pbyBuffer);
		pbyBuffer = NULL;
	}
	if(hFileHandle != NULL)
	{
		CloseHandle(hFileHandle);
		hFileHandle =  NULL;
	}
	return bFlag;
} 

bool CMaxDigitalSigCheck::LoadWinTrust()
{
	OSVERSIONINFO osvi ={sizeof(OSVERSIONINFO)};
	::GetVersionEx(&osvi);
	m_bWin7Check =true;
	m_bSha256 = false;
	m_bDigitalScanLoaded = false;
	if(osvi.dwMajorVersion>6 || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion>1))
	{
		m_bWin7Check= false;
	}
	else
	{
		m_bWin7Check =true;
	}
	m_hWinTrust = LoadLibrary(L"wintrust.dll");
	///crypt32 = LoadLibrary(L"crypt32.dll");
	bool bReturn = false;
	if(m_hWinTrust != NULL)
	{
		bReturn= true;
		if(m_bWin7Check == true)
		{
			m_lpfnCryptCATAdminAcquireContext = (LPFN_CryptCATAdminAcquireContext)GetProcAddress(m_hWinTrust,"CryptCATAdminAcquireContext");
			m_lpfnCryptCATAdminCalcHashFromFileHandle= (LPFN_CryptCATAdminCalcHashFromFileHandle)GetProcAddress(m_hWinTrust,"CryptCATAdminCalcHashFromFileHandle");
			if(m_lpfnCryptCATAdminAcquireContext == NULL || m_lpfnCryptCATAdminCalcHashFromFileHandle == NULL)
			{
				bReturn = false;
			}
		}
		else
		{
			m_bSha256 = true;
			m_lpfnCryptCATAdminAcquireContext2 = (LPFN_CryptCATAdminAcquireContext2)GetProcAddress(m_hWinTrust,"CryptCATAdminAcquireContext2");
			m_lpfnCryptCATAdminCalcHashFromFileHandle2= (LPFN_CryptCATAdminCalcHashFromFileHandle2)GetProcAddress(m_hWinTrust,"CryptCATAdminCalcHashFromFileHandle2");

			if(m_lpfnCryptCATAdminAcquireContext2 == NULL || m_lpfnCryptCATAdminCalcHashFromFileHandle2 == NULL)
			{
				m_bSha256 = false;
				m_lpfnCryptCATAdminAcquireContext = (LPFN_CryptCATAdminAcquireContext)GetProcAddress(m_hWinTrust,"CryptCATAdminAcquireContext");
				m_lpfnCryptCATAdminCalcHashFromFileHandle= (LPFN_CryptCATAdminCalcHashFromFileHandle)GetProcAddress(m_hWinTrust,"CryptCATAdminCalcHashFromFileHandle");
				if(m_lpfnCryptCATAdminAcquireContext == NULL || m_lpfnCryptCATAdminCalcHashFromFileHandle == NULL)
				{
					bReturn = false;
				}
			}
		}
		
		m_lpfnCryptCATAdminReleaseContext= (LPFN_CryptCATAdminReleaseContext)GetProcAddress(m_hWinTrust,"CryptCATAdminReleaseContext");
		m_lpfnCryptCATAdminEnumCatalogFromHash= (LPFN_CryptCATAdminEnumCatalogFromHash)GetProcAddress(m_hWinTrust,"CryptCATAdminEnumCatalogFromHash");
		m_lpfnCryptCATCatalogInfoFromContext= (LPFN_CryptCATCatalogInfoFromContext)GetProcAddress(m_hWinTrust,"CryptCATCatalogInfoFromContext");
		m_lpfnCryptCATAdminReleaseCatalogContext= (LPFN_CryptCATAdminReleaseCatalogContext)GetProcAddress(m_hWinTrust,"CryptCATAdminReleaseCatalogContext");
		m_lpfnWinVerifyTrust = (LPFN_WinVerifyTrust)GetProcAddress(m_hWinTrust,"WinVerifyTrust");
		if(m_lpfnCryptCATAdminReleaseContext == NULL || m_lpfnCryptCATAdminEnumCatalogFromHash == NULL || m_lpfnCryptCATCatalogInfoFromContext == NULL || m_lpfnCryptCATAdminReleaseCatalogContext== NULL || m_lpfnWinVerifyTrust == NULL)
		{
			bReturn = false;
		}
		if(bReturn == false)
		{
			if(m_hWinTrust != NULL)
			{
				FreeLibrary(m_hWinTrust);
				m_lpfnCryptCATAdminAcquireContext = NULL;
				m_lpfnCryptCATAdminAcquireContext2 = NULL;
				m_lpfnCryptCATAdminCalcHashFromFileHandle = NULL;
				m_lpfnCryptCATAdminCalcHashFromFileHandle2 = NULL;
				m_lpfnCryptCATAdminAcquireContext = NULL;
				m_lpfnCryptCATAdminReleaseContext = NULL;
				m_lpfnCryptCATAdminEnumCatalogFromHash = NULL;
				m_lpfnCryptCATCatalogInfoFromContext = NULL;
				m_lpfnCryptCATAdminReleaseCatalogContext = NULL;
				m_lpfnWinVerifyTrust = NULL;
			}
		}
		else
		{
			m_bDigitalScanLoaded = true;
		}
	}
	return bReturn;
}
bool CMaxDigitalSigCheck::UnLoadWinTrust()
{
	m_bDigitalScanLoaded = false;
	if(m_hWinTrust != NULL)
	{
		FreeLibrary(m_hWinTrust);
		m_lpfnCryptCATAdminAcquireContext = NULL;
		m_lpfnCryptCATAdminAcquireContext2 = NULL;
		m_lpfnCryptCATAdminCalcHashFromFileHandle = NULL;
		m_lpfnCryptCATAdminCalcHashFromFileHandle2 = NULL;
		m_lpfnCryptCATAdminAcquireContext = NULL;
		m_lpfnCryptCATAdminReleaseContext = NULL;
		m_lpfnCryptCATAdminEnumCatalogFromHash = NULL;
		m_lpfnCryptCATCatalogInfoFromContext = NULL;
		m_lpfnCryptCATAdminReleaseCatalogContext = NULL;
		m_lpfnWinVerifyTrust = NULL;
	}
	return true;
}