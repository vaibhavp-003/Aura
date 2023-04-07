#pragma once
#include <afx.h>
#include "MaxPEFile.h"
#include "Resmd5.h"
#include "TreeManager.h"
#include "YaraOrdLookUP.h"

class CMaxYara
{
	TCHAR			m_szIMPHash[MAX_PATH];
	CMaxPEFile		*m_pMaxPEFile;
public:
	CMaxYara(CMaxPEFile *pMaxPEFile);
	~CMaxYara(void);

	bool GetIMPHashforYARA();
	bool ValidatePERules(LPTSTR pszPERules);
	bool CheckFileSizeRule(CString csPERules);
	bool CheckSecSizeRule(CString csPERules,int iSecProperty);
	bool CheckStaticYaraRules(CTreeManager *pYaraTree);	
	bool ScanFile(CTreeManager *pYaraTree);

	bool GetAPIfromOrdList(char *pszDllName,int iOrdinal,char *pszAPIName);	
};
