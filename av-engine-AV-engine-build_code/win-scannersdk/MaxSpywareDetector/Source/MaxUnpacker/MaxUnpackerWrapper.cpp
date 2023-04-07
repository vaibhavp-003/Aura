#include "pch.h"
#include "Packers.h"
#include "MaxUnpackerWrapper.h"
#include <math.h>
#include <shlwapi.h>
#include "MaxExceptionFilter.h"

CMaxUnpackerWrapper::CMaxUnpackerWrapper(CMaxPEFile *pInputFile, CMaxPEFile *pOutputFile):
m_pInputFile(pInputFile),
m_pOutputFile(pOutputFile),
m_pCurrentFile(pInputFile),
m_ePackerType(eVALIDPE),
m_iCurrentLevel(0)
{	
	_tcscpy_s(m_szTempFilePath, MAX_PATH, L"");
	CUnpackBase::m_iDataCnt = 0;	
}
	
CMaxUnpackerWrapper::~CMaxUnpackerWrapper(void)
{
}

void WriteLog(LPCTSTR szString)
{
	TCHAR szLogFile[MAX_PATH] = {0};
	if(GetModuleFileName(NULL, szLogFile, MAX_PATH))
	{
		WCHAR *cExtPtr = wcsrchr(szLogFile, '\\');
		*cExtPtr = '\0';
		_tcsncat_s(szLogFile, MAX_PATH, L"\\Log\\EmulatorLog.txt", 20);

		FILE * fp = 0;
		_tfopen_s(&fp, szLogFile, L"a");
		if(fp)
		{
			_fputts(szString, fp);
			_fputts(L"\r\n", fp);
			fclose(fp);
		}
	}
}

int CMaxUnpackerWrapper::UnpackFile()
{
	__try
	{	
		if(m_pInputFile->m_bPEFile && m_pInputFile->m_b64bit == false)
		{
			WORD wLastSection = m_pInputFile->m_stPEHeader.NumberOfSections - 1;
			DWORD dwLastSecVS = m_pInputFile->m_stSectionHeader[wLastSection].Misc.VirtualSize; 
			DWORD dwLastSecRVA = m_pInputFile->m_stSectionHeader[wLastSection].VirtualAddress; 	
			DWORD dwFirstSecVS = m_pInputFile->m_stSectionHeader[0].Misc.VirtualSize; 
			DWORD dwFirstSecRVA = m_pInputFile->m_stSectionHeader[0].VirtualAddress; 	
			
			if(dwLastSecVS + dwLastSecRVA > 1024 * 1024 * 50 || dwFirstSecVS + dwFirstSecRVA > 1024 * 1024 * 50 || m_pInputFile->m_dwFileSize > 1024 * 1024 * 50)
			{
				return NOT_PACKED;
			}
			if(m_pInputFile->m_stPEHeader.NumberOfRvaAndSizes > 0x10)
			{
				return NOT_PACKED;
			}
		}

		m_hTempFile = INVALID_HANDLE_VALUE;
			
		// Get temp folder path where to extrat the files
		if(!GetModuleFileName(NULL, m_szTempFolderPath, MAX_PATH))
		{
		}
		
		WCHAR *cExtPtr = wcsrchr(m_szTempFolderPath, '\\');
		*cExtPtr = '\0';

		TCHAR	szIniPath[1024] = {0x00};
		_stprintf(szIniPath,L"%s\\setting\\SDKSettings.ini",m_szTempFolderPath);
		UINT iValue = GetPrivateProfileInt(L"ProductSetting", L"UIProduct", 1, szIniPath);

		if (iValue == 1)
		{
			_tcsncat_s(m_szTempFolderPath, MAX_PATH, TEMP_FOLDER, 10);
		}
		else
		{
			GetTempPath(MAX_PATH,m_szTempFolderPath);
			_tcscat(m_szTempFolderPath,L"\\MaxTempData");
		}
		
		if(FALSE == PathIsDirectory(m_szTempFolderPath))
		{
			CreateDirectory(m_szTempFolderPath, 0);
		}

		// Get the file name to create temp file path
		LPCTSTR	szOnlyFileName = m_pInputFile->m_szFilePath? _tcsrchr(m_pInputFile->m_szFilePath, _T('\\')): NULL;
		if(NULL == szOnlyFileName)
		{
			return NOT_PACKED;
		}
		_tcscpy_s(m_szOnlyFileName, MAX_PATH, szOnlyFileName);		

		// Unpack input file
		return GetUnPackedFile();
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in Unpacker Dll"), m_pInputFile->m_szFilePath))
	{
		return UNPACK_EXPECTION;
	}
	return NOT_PACKED;
}

int CMaxUnpackerWrapper::GetUnPackedFile()
{
	
	//OutputDebugString(L"TEST >>> Inside CMaxUnpackerWrapper::GetUnPackedFile");
	/*
	TCHAR	szLogLine[1024] = {0x00};

	_stprintf(szLogLine,L"TEST >>> Inside GetUnPackedFile : No os Secs : %d",m_pInputFile->m_stPEHeader.NumberOfSections);
	AddLogEntry(szLogLine);
	*/
	if(!m_pInputFile->m_bPEFile)
	{
		CEmbeddedFile objEmbeddedFile(m_pInputFile, m_iCurrentLevel);
		if(objEmbeddedFile.IsPacked())
		{
			GetRandomFilePath(m_szTempFilePath);
			if(objEmbeddedFile.Unpack(m_szTempFilePath))
			{
				if(m_pOutputFile->OpenFile(m_szTempFilePath, false))
				{
					return UNPACK_SUCCESS;
				}
			}
		}
		return NOT_PACKED;
	}

	TCHAR	szUnPackedFilePath[MAX_PATH] = {0};
	TCHAR	szPrevTempFilePath[MAX_PATH] = {0};

	bool bPacked = false;
	for(m_iCurrentLevel = 0; m_iCurrentLevel < MAX_RECURSION_LEVEL; m_iCurrentLevel++)
	{
		if(m_pCurrentFile->m_wAEPSec == OUT_OF_FILE)
		{
			break;
		}
		if(!TryallUnpackers())
		{
			break;
		}
		bPacked = true;
		
		m_pOutputFile->CloseFile();
		if(0 == _taccess_s(szPrevTempFilePath, 0))
		{
			DeleteFile(szPrevTempFilePath);
		}
		_tcscpy_s(szPrevTempFilePath, MAX_PATH, m_szTempFilePath);
		_tcscpy_s(szUnPackedFilePath, MAX_PATH, m_szTempFilePath);
		if(!m_pOutputFile->OpenFile(szUnPackedFilePath, false))
		{
			break;
		}
		m_pCurrentFile = m_pOutputFile;
	}

	// Delete intermediate temp file if any
	if(_tcscmp(szUnPackedFilePath, szPrevTempFilePath) != 0)
	{
		if(0 == _taccess_s(szPrevTempFilePath, 0))
		{
			DeleteFile(szPrevTempFilePath);
		}
	}

	// Check whether file is unpacked by checking its size
	if(0 == _taccess_s(szUnPackedFilePath, 0))
	{
		// Get the final successfully unpacked file
		if(_tcscmp(szUnPackedFilePath, m_pOutputFile->m_szFilePath) != 0)
		{
			m_pOutputFile->DeleteTempFile();
			m_pOutputFile->OpenFile(szUnPackedFilePath, false);			
		}

		// Check unpacked file is more than the original file
		if(m_pOutputFile->m_dwFileSize > 0)
		{
			return UNPACK_SUCCESS;
		}
		
		m_pOutputFile->DeleteTempFile();
	}
	if(0 == _taccess_s(m_szTempFilePath, 0))
	{
		DeleteFile(m_szTempFilePath);
	}

	//AddLogEntry(L"TEST >>> UNPACK_FAILED");

	return bPacked ? UNPACK_FAILED : NOT_PACKED;
}

void CMaxUnpackerWrapper::GetRandomFilePath(LPTSTR szFileName)
{
	//_stprintf_s(szFileName, MAX_PATH, _T("%s%.6s_%06x_%05d_%d.tmp"), m_szTempFolderPath, m_szOnlyFileName, GetTickCount(), GetCurrentThreadId(), rand());		
	_stprintf_s(szFileName, MAX_PATH, _T("%s%.6s_%06x_%05d_%d.mup"), m_szTempFolderPath, m_szOnlyFileName, GetTickCount(), GetCurrentThreadId(), rand());		
}

bool CMaxUnpackerWrapper::TryallUnpackers(bool bDetectOnly)
{
	//OutputDebugString(L"Inside TryallUnpackers");
	//AddLogEntry(L"Inside TryallUnpackers Level 1");
	if(m_pCurrentFile->IsReloadedPE() && m_pCurrentFile->m_b64bit == false)
	{
		CEmbeddedFile objEmbeddedFile(m_pCurrentFile, m_iCurrentLevel);
		GetRandomFilePath(m_szTempFilePath);
		if(objEmbeddedFile.Unpack(m_szTempFilePath))
		{
			if(m_pOutputFile->OpenFile(m_szTempFilePath, false))
			{
				return UNPACK_SUCCESS;
			}
		}
		return NOT_PACKED;
	}

	//AddLogEntry(L"Inside TryallUnpackers Level 2");
	struct
	{
		CUnpackBase *pUnpacker;
		PACKERS_TYPE ePackerType;
	}pUnpackerList[] = {		
		{new CUPXPatch(m_pCurrentFile), eUPXPatch},
		{new CUPXUnpacker(m_pCurrentFile, m_iCurrentLevel), eUPX},
		{new CASPackUnpack(m_pCurrentFile), eASPACK},
		{new CPECompactUnpack(m_pCurrentFile), ePECOMPACT},
		{new CMewUnpacker(m_pCurrentFile), eMEW},
		{new CWinUpackUnpacker(m_pCurrentFile), eWinUpack},
		{new CFSGUnpacker(m_pCurrentFile, m_iCurrentLevel), eFSG},
		{new CNSPackUnpacker(m_pCurrentFile), eNSPACK},
		{new CSCPackUnpacker(m_pCurrentFile), eScPack},
		{new CMPressUnpack(m_pCurrentFile), eMPressPack},
		{new CDexCryptor(m_pCurrentFile), eDexCryptor},
		{new CRLUnpacker(m_pCurrentFile), eRLPack},
		{new CPogoUnpacker(m_pCurrentFile), ePOGOPack},
		{new CXPackUnpacker(m_pCurrentFile), eXPack},
		{new CPePackUnpacker(m_pCurrentFile), ePePack},
		{new CSMPackUnpacker(m_pCurrentFile), eSMPack},		
		{new CSPackUnpacker(m_pCurrentFile), eSPack},
		{new CExeUnpacker(m_pCurrentFile), eCExePack},
		{new CSimplePackUnpack(m_pCurrentFile), eSimplePack},	
		{new CDalKryptorDecrypt(m_pCurrentFile), eDalKryptor},
		{new CPetite2xxUnpacker(m_pCurrentFile), ePetite2xx},
		{new CNeoliteUnpacker(m_pCurrentFile), eNeolite},
		{new CAHPackUnpacker(m_pCurrentFile), eAHPack},
		{new CYodaCryptorDecrypt(m_pCurrentFile), eYodaUnpack},
		{new CStealthackUnpacker(m_pCurrentFile), eStealthPE},
		{new CMaskPEUnpacker(m_pCurrentFile), eMaskPE},
		{new CPECryptCFDecrypt(m_pCurrentFile), ePECryptCF},
		{new CVGCryptDecrypt(m_pCurrentFile), eVGCrypt},
		{new CKbyshooUnpacker(m_pCurrentFile), eKbyshoo},
		{new CRPCryptDeJunker(m_pCurrentFile), eRPCrypt},
		{new CVPackUnpacker(m_pCurrentFile), eVPack},
		{new CPCShrinkerUnpacker(m_pCurrentFile), ePCShrinker},
		{new CPolyCryptPEDecryptor(m_pCurrentFile), ePolyPECrypt},
		{new CNPackUnpacker(m_pCurrentFile), eNpack},
		{new CTelockDecryptor(m_pCurrentFile), eTelock},
		{new CPECompactOldUnpack(m_pCurrentFile), ePECOMPACTOld},
		{new CBitArtsUnpack(m_pCurrentFile), eBitArts},
		{new CAverCryptDecryptor(m_pCurrentFile), eAverCrypt},
		{new CSoftComUnpack(m_pCurrentFile), eSoftCom},
		{new CNullSoft(m_pCurrentFile), eNullSoft},
		{new CMSExpand(m_pCurrentFile), eMSExpand},
		{new CEmbeddedFile(m_pCurrentFile, m_iCurrentLevel), eEmbeddedFile}
	};

	bool	bRetSuccess = false;
	TCHAR	szLogLine[1024] = {0x00};
	
	//AddLogEntry(L"Inside TryallUnpackers Level 3");

	for(int i = 0; i < _countof(pUnpackerList); i++)
	{
		//_stprintf(szLogLine, L"TryallUnpackers I Value : %d", i);
		//AddLogEntry(szLogLine);
		if(pUnpackerList[i].pUnpacker->IsPacked())
		{
			m_ePackerType = pUnpackerList[i].ePackerType;
			
			if(bDetectOnly)
			{
				//AddLogEntry(L"TEST >>> Found Packer Detection Only");
				break;
			}

			SetFileAttributes(m_pCurrentFile->m_szFilePath, FILE_ATTRIBUTE_NORMAL);				
			GetRandomFilePath(m_szTempFilePath);

			bRetSuccess = pUnpackerList[i].pUnpacker->Unpack(m_szTempFilePath);
			pUnpackerList[i].pUnpacker->m_objTempFile.CloseFile();
			if(bRetSuccess)
			{
				//AddLogEntry(L"Inside TryallUnpackers Level 5");
				break;
			}
		
			::DeleteFile(m_szTempFilePath);	
		}
		//_stprintf(szLogLine, L"TryallUnpackers I Value Finished : %d", i);
		//AddLogEntry(szLogLine);
	}

//	AddLogEntry(L"Inside TryallUnpackers Level 6");
	for(int i = 0; i < _countof(pUnpackerList); i++)
	{
		delete pUnpackerList[i].pUnpacker;
		pUnpackerList[i].pUnpacker = nullptr;

		//_stprintf(szLogLine,L"TEST AFTER Destruction : %d",i);
		//OutputDebugString(szLogLine);
	}

	//AddLogEntry(L"TEST >>> TryallUnpackers : Bye Bye");
	//OutputDebugString(L"\nReturn");
	return bRetSuccess;	
}
