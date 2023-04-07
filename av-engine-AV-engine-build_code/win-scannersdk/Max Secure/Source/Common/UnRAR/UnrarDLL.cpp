// CUnrarDLL.cpp : implementation file
//

#include "pch.h"
#include "UnrarDLL.h"

CUnrarDLL::CUnrarDLL()
{
 	m_hUnrarDLL = NULL;
	m_lpOpenArchiveEx	= NULL;
	m_lpCloseArchive	= NULL;
	m_lpReadRARHeader	= NULL;
	m_lpProcessRARFileW = NULL;
	m_lpReadRARHeaderEx = NULL;
	InitUnRARDll();
}

CUnrarDLL::~CUnrarDLL()
{
	UnloadDLL();
}

bool CUnrarDLL::InitUnRARDll()
{
	m_hUnrarDLL = LoadLibrary(_T("unrar.dll"));

	if (m_hUnrarDLL == NULL)
	{
		AddLogEntry(_T("Load Error: unrar.dll could not be loaded"));
		return false;
	}
	
	m_lpOpenArchiveEx = (OPENARCHIVEEX)GetProcAddress(m_hUnrarDLL, "RAROpenArchiveEx");
	m_lpCloseArchive = (CLOSEARCHIVE)GetProcAddress(m_hUnrarDLL, "RARCloseArchive");
	m_lpProcessRARFileW = (PROCESSRARFILEW)GetProcAddress(m_hUnrarDLL, "RARProcessFileW");
	m_lpReadRARHeaderEx = (READRARHEADEREX)GetProcAddress(m_hUnrarDLL, "RARReadHeaderEx");
	return true;
}

void CUnrarDLL::UnloadDLL()
{
	if(m_hUnrarDLL)
	{
		::FreeLibrary(m_hUnrarDLL);
		m_hUnrarDLL = NULL;
	}
	if(m_lpOpenArchiveEx)
		m_lpOpenArchiveEx = NULL;

	if(m_lpCloseArchive)
		m_lpCloseArchive	= NULL;

	if(m_lpReadRARHeader)
		m_lpReadRARHeader	= NULL;

	if(m_lpProcessRARFileW)
		m_lpProcessRARFileW = NULL;

	if(m_lpReadRARHeaderEx)
		m_lpReadRARHeaderEx = NULL;
}

int CUnrarDLL::UnRARArchive(TCHAR *szFileName, TCHAR *szExtractedPath)
{
	if (m_hUnrarDLL == NULL) 
		return ERAR_EOPEN; 

	TCHAR szTempFolderPath[MAX_PATH] = {0};
	// Get temp folder path where to extrat the files
	GetModuleFileName(NULL, szTempFolderPath, MAX_PATH);
	WCHAR *cExtPtr = wcsrchr(szTempFolderPath, '\\');
	if(cExtPtr) *cExtPtr = '\0';
	_stprintf_s(szExtractedPath, MAX_PATH, _T("%s\\TempFolder\\%08x-%05d-%05d"), szTempFolderPath, GetTickCount(), GetCurrentThreadId(), GetCurrentProcessId());

	RAROPENARCHIVE_DATA_EX sarchiveData;
	::SecureZeroMemory(&sarchiveData, sizeof(sarchiveData));
	sarchiveData.ArcNameW	= szFileName;
	sarchiveData.CmtBuf = NULL;
	sarchiveData.OpenMode = 1;

	HANDLE harchiveHandle = m_lpOpenArchiveEx(&sarchiveData);
	if (sarchiveData.OpenResult != 0)
	{
		AddLogEntry (_T("Open Error: Failed to open RAR file"));
		return ERAR_EOPEN;
	}

	RARHEADER_DATA_EX sheaderData;
	::SecureZeroMemory(&sheaderData, sizeof(sheaderData));
	sheaderData.CmtBuf = NULL;
	memset(&sarchiveData.Reserved,0,sizeof(sarchiveData.Reserved));

	int ireadHeaderCode = ERAR_UNKNOWN, iprocessFileCode = ERAR_UNKNOWN;

	while((ireadHeaderCode = m_lpReadRARHeaderEx(harchiveHandle, &sheaderData)) == 0)
	{
		iprocessFileCode = m_lpProcessRARFileW(harchiveHandle, RAR_EXTRACT, szExtractedPath, NULL);
		if (iprocessFileCode != 0)
		{
			break;
		}
	}
	m_lpCloseArchive(harchiveHandle);
	return iprocessFileCode;
}
