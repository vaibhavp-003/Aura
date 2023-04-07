#pragma once
#include "splspyscan.h"


typedef struct _REG_RUN_ENTRY
{
	TCHAR		szValueName[MAX_PATH];
	TCHAR		szValueData[MAX_PATH];
}REG_RUN_ENTRY,*LPREG_RUN_ENTRY;

class CGlobalRootFix :
	public CSplSpyScan
{
public:

	CGlobalRootFix(CSplSpyWrapper *pSplSpyWrapper):CSplSpyScan(pSplSpyWrapper,5430840)
	{
		m_bSplSpyFound = false;
	}

	virtual ~CGlobalRootFix(void)
	{
	}
	bool ScanSplSpy ( bool bToDelete = false , CFileSignatureDb *pFileSigMan = NULL ) ;

private:
	bool			m_bToDelete;
	REG_RUN_ENTRY	m_RegRunEntries[0x10];
	DWORD			m_dwRegRunEntries;
	
	void FixUSBDrives();
	void ChangeUSBAttrib(LPCTSTR pszCmdLine);
	void DeleteVirusFile(LPCTSTR pszDrive);
	void GetRegRunEntries(void);	
	void CheckProgramFilesFolder();
};
