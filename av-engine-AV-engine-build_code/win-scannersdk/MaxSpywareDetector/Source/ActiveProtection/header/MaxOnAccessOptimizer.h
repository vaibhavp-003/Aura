#pragma once

class CMaxOnAccessOptimizer
{
	BYTE	m_byHeaderBuff[0x50];

	BOOL	GetFileHeaderBuff(LPCTSTR pszFileAccess);
	BOOL	CheckKnownExt(LPCTSTR pszFileAccess);
	BOOL	CheckForFileType();
	BOOL	CheckProcessRule(LPCTSTR pszFileAccess, LPCTSTR pszProcessName);
	BOOL	CheckSkipExt(LPCTSTR pszFileAccess);

public:
	CMaxOnAccessOptimizer(void);
	~CMaxOnAccessOptimizer(void);

	BOOL	SkipFileScanning(LPCTSTR pszFileAccess, LPCTSTR	pszProcessPath);
	BOOL	SkipFileScanningExecute(LPCTSTR	pszProcessPath);
};
