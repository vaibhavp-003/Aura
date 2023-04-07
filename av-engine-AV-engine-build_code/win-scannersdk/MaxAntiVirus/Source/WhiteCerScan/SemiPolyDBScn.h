#pragma once
#include "TreeManager.h"

class CSemiPolyDBScn
{
public:
	CSemiPolyDBScn(void);
	~CSemiPolyDBScn(void);

	CTreeManager	m_SemiPolyDBScan;
	int	LoadSigDBEx(LPCTSTR pszSig2Add, LPCTSTR pszVirusName, BOOL bMoreSigs);
	int ScanBuffer(unsigned char * szBuffer,unsigned int iBuffLen, LPTSTR szVirusName);
};
