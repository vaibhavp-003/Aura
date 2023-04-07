#pragma once

#include "Registry.h"

class CUserTrackingSystem
{
public:
	CUserTrackingSystem(void);
	virtual ~CUserTrackingSystem(void);

	static CString GetTrackingInfo();
	static CString GetEliteTrackingInfo();

	static void SetAppFolder(CString csAppFolder);
	static void SetProductKey(CString csProductKey);

	static bool IncrementCount(CString csEventName);
	static bool AddCount(CString csEventName, DWORD dwCount);

	static CString GetCurrentLanguage();
	static CString m_csTrackingKey;

private:
	static CRegistry m_oRegistry;

	static CString m_csProductKey;
	static CString m_csAppFolder;	
};
