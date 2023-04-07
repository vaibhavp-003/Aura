#pragma once
#include "MaxPEFile.h"
#include "SemiPolyDBScn.h"

class CMaxCertScan
{
	BYTE			*m_pbyBuffer;
	int				m_nRegExpCount;
	TCHAR			**m_csRegExpName;
	bool			m_bInitialized;

public:
	CMaxCertScan(void);
	~CMaxCertScan(void);

	bool	CheckKnownPublisher(LPCTSTR	pszFilePath);	
	void	FilterINI(LPCTSTR pszFolderPath);
	bool	CheckKnownFileName(LPCTSTR	pszFilePath);	
};
