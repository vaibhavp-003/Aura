#pragma once

#include "MaxPEFile.h"
#include "Resmd5.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <iostream>
#include "S2S.h"


using namespace std;

class CMaxIconScanner
{
public:
	CMaxIconScanner(void);
	~CMaxIconScanner(void);

private:
	CMaxPEFile					*m_pMaxPEFile;
	CMaxMD5						objmd5;
	BYTE						*m_pbyBuff;
	PIMAGE_RESOURCE_DIRECTORY	m_pResDir;	//Pointer to base of Resource Directory
	IMAGE_SECTION_HEADER		*m_pSectionHeader;
	WORD						m_wNoOfSections;
	bool						FileGetInfo(CMaxPEFile *pMaxPEFile);
	bool						GetBuffer(DWORD dwOffset, DWORD dwNumberOfBytesToRead, DWORD dwMinBytesReq);

	CS2S						m_IconS2S;
		
	
public:
	TCHAR		m_szDBFilePath[512];

	bool		ScanFile(CMaxPEFile *pMaxPEFile,LPCTSTR pszDBPath,char *szVirusName);
};


