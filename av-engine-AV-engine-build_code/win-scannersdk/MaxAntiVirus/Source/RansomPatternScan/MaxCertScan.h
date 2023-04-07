#pragma once

class CMaxCertScan
{
	TCHAR			*m_szAppDataPath;
	TCHAR			*m_szLocalAppDataPath;
		
public:
	CMaxCertScan(void);
	~CMaxCertScan(void);

	bool	CheckBlackFileName(LPCTSTR pszFileName);
	bool	CheckBlackFileInAppData(LPCTSTR pszFileName);
	void	SetAppDataPath(LPCTSTR pszAppDataPath, LPCTSTR pszLocalAppDataPath);
};
