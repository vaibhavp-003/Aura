#pragma once
#include "polybase.h"
#include "SemiPolyDBScn.h"

#define VIRUS_DB_DIGI_SIG			_T("SDV13.DB")

class CMaxDigiSign //: public CPolyBase
{
public:
	//CMaxDigiSign(CMaxPEFile *pMaxPEFile);
	CMaxDigiSign();
	~CMaxDigiSign(void);

	BYTE	*m_pbyBuff;

public:
	//CSemiPolyDBScn				objdbscan;
	CTreeManager				m_FileInfectorTree;
	CSemiPolyDBScn				m_SemiPolyDB;
	LPTSTR						m_szSignature;
	LPTSTR						m_szVirName; 
	BOOL						m_bDBLoaded;
	DWORD						LoadDatabase(PCTSTR pszDBPath);
	DWORD						ScanFile(CMaxPEFile *pMaxPEFile, LPTSTR pszVirusName);
    BOOL						UnloadDatabase();

};