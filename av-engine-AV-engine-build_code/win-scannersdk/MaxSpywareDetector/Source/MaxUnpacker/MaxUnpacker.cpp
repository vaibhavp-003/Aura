// MaxUnpacker.cpp : Defines the initialization routines for the DLL.
//

#include "pch.h"
#include "MaxUnpacker.h"
#include "MaxUnpackerWrapper.h"
#include "UnrarDLL.h"
#include "NonPEFile.h"
#include "MaxExceptionFilter.h"
#include "UPXUnpacker.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


BEGIN_MESSAGE_MAP(CMaxUnpackerApp, CWinApp)
END_MESSAGE_MAP()


// CMaxUnpackerApp construction

CMaxUnpackerApp::CMaxUnpackerApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CMaxUnpackerApp object

CMaxUnpackerApp theApp;

static BOOL	m_bEmulatorLoaded = FALSE;


// CMaxUnpackerApp initialization

BOOL CMaxUnpackerApp::InitInstance()
{
	CWinApp::InitInstance();

	CMaxExceptionFilter::InitializeExceptionFilter();
	//CEmulate::IntializeSystem();
	SetEvent(CUnpackBase::m_hEvent);

	return TRUE;
}

extern "C" __declspec(dllexport) int UnPackFile(LPCTSTR szFileToUnPack, LPTSTR szUnpackFilePath)
{

	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	CMaxPEFile *pInputFile = new CMaxPEFile;
	if(!pInputFile)
	{
		return NOT_PACKED;
	}
	if(!pInputFile->OpenFile(szFileToUnPack, false))
	{
		delete pInputFile;
		return NOT_PACKED; 
	}
	//Comment on 02 Dec 2019
	/*if(pInputFile->m_b64bit)
	{
		delete pInputFile;
		return NOT_PACKED;
	}*/
	CMaxPEFile *pOutputFile = new CMaxPEFile;
	if(!pOutputFile)
	{
		delete pInputFile;
		return NOT_PACKED;
	}

	if (m_bEmulatorLoaded == FALSE)
	{
		CEmulate::IntializeSystem();
		m_bEmulatorLoaded = TRUE;
	}
	
	CMaxUnpackerWrapper oMaxUnpackerWrapper(pInputFile, pOutputFile); 
	int iRet = oMaxUnpackerWrapper.UnpackFile();
	if(iRet == UNPACK_SUCCESS)
	{
		_tcscpy_s(szUnpackFilePath, MAX_PATH, pOutputFile->m_szFilePath);
	}

	pInputFile->CloseFile();
	pOutputFile->CloseFile();

	delete pInputFile;
	delete pOutputFile;
	return iRet;
}
 
extern "C" __declspec(dllexport) int UnPackFileNew(CMaxPEFile *pInputFile, CMaxPEFile *pOutputFile)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	//Comment on 02 Dec 2019
	/*if(pInputFile->m_b64bit)
	{
		return NOT_PACKED;
	}*/
	if (m_bEmulatorLoaded == FALSE)
	{
		CEmulate::IntializeSystem();

		m_bEmulatorLoaded = TRUE;
	}
		
	CMaxUnpackerWrapper oMaxUnpackerWrapper(pInputFile, pOutputFile); 
	return oMaxUnpackerWrapper.UnpackFile();
}

extern "C" __declspec(dllexport) void UnloadDlls()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());	
	CEmulate::DeIntializeSystem();
	if(CUnpackBase::m_hEvent)
	{
		CloseHandle(CUnpackBase::m_hEvent);
		CUnpackBase::m_hEvent = NULL;
	}
	CUPXUnpacker::UnLoadUPXDll();
	
	if(CUnpackBase::m_PEBundle)
	{
		for(int i = 0; i < _countof(CUnpackBase::m_PEBundle); i++)
		{
			if(CUnpackBase::m_PEBundle[i].hUnpacker)
			{
				FreeLibrary(CUnpackBase::m_PEBundle[i].hUnpacker);
				CUnpackBase::m_PEBundle[i].lpfnDecodeSmall = NULL;
			}
		}			
	}	
}

extern "C" __declspec(dllexport) int ExtractFile(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	CUnrarDLL objUnrarDLL;
	return objUnrarDLL.UnRARArchive(szFileName, szExtractedPath);
}

extern "C" __declspec(dllexport) bool ExtractNonPEFile(int iFileType, TCHAR *szFileName, TCHAR *szExtractedPath)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	
	CNonPEFile m_objNonPEFile;
	return m_objNonPEFile.ExtractFile(iFileType, szFileName, szExtractedPath);
}

extern "C" __declspec(dllexport) int GetPackerType(LPCTSTR szFilePath, LPTSTR szPackerName)
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	
	const int MAX_PACKER_NAME = 21;
	TCHAR szPackerNames[][MAX_PACKER_NAME] = 
	{
		L"Not_Packed",
		L"MEW",
		L"UPACK",
		L"FSG",
		L"UPX",
		L"ePESPIN",
		L"WWPACK",
		L"ASPACK",
		L"NSPACK",
		L"PECOMPACT",
		L"ScPack",
		L"MPressPack",
		L"DexCryptor",
		L"RLPack",
		L"POGOPack",
		L"XPack",
		L"PePack",
		L"SMPack",
		L"SPack",
		L"CExePack",
		L"SimplePack",
		L"DalKryptor",
		L"Petite2xx",
		L"Neolite",
		L"AHPack",
		L"YodaUnpack",
		L"StealthPE",
		L"WinUpack",
		L"MaskPE",
		L"EmbeddedFile",
		L"PECryptCF",
		L"VGCrypt",
		L"Kbyshoo",
		L"RPCrypt",
		L"VPack",
		L"PCShrinker",
		L"PolyCryptPE",
		L"NPack",
		L"Telock",		
		L"PECOMPACTOld",		
		L"BitArts",		
		L"AverCrypt",		
		L"SoftCom",		
		L"eUPXPatch",
		L"NullSoft",
		L"MSExpand",
		L"UNKNOWN"
	};

	_tcscpy_s(szPackerName, MAX_PACKER_NAME, szPackerNames[0]);
	
	CMaxPEFile *pInputFile = new CMaxPEFile;
	if(!pInputFile)
	{
		return eVALIDPE;
	}
	if(!pInputFile->OpenFile(szFilePath, false))
	{
		delete pInputFile;
		return eVALIDPE;
	}
	if(pInputFile->m_b64bit || !pInputFile->m_bPEFile)
	{
		pInputFile->CloseFile();
		delete pInputFile;
		return eVALIDPE;
	}

	CMaxExceptionFilter::InitializeExceptionFilter();
	CEmulate::IntializeSystem();
	SetEvent(CUnpackBase::m_hEvent);

	CMaxUnpackerWrapper oMaxUnpackerWrapper(pInputFile, NULL); 
	int iPackerType = eVALIDPE;
	if(oMaxUnpackerWrapper.TryallUnpackers(true))
	{
		iPackerType = oMaxUnpackerWrapper.m_ePackerType;
		_tcscpy_s(szPackerName, MAX_PACKER_NAME, szPackerNames[iPackerType]);
	}
	pInputFile->CloseFile();
	delete pInputFile;

	CEmulate::DeIntializeSystem();
	if(CUnpackBase::m_hEvent)
	{
		CloseHandle(CUnpackBase::m_hEvent);
		CUnpackBase::m_hEvent = NULL;
	}
	return iPackerType;
}