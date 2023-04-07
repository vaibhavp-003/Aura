#pragma once
#include "S2U.h"
#include "DBPathExpander.h"

class CValueTypeManager
{
public:
	CValueTypeManager(void);
	virtual ~CValueTypeManager(void);

	bool SplitFileEntry(const CString &csFileEntry, int &iProfileType, int &iValueType, CString &csValue);

	bool SplitRegistryEntry(CString &csRegistryEntry, int &iProfileType, int &iValueType, CString &csKeyPart, CString &csValuePart, CString &csDataPart, bool bSpliltValueData = true);
	bool SlitValuePartAndDataPart(CString &csRegistryEntry, CString &csValuePart, CString &csDataPart);

private:

	int m_iProfileType;
	CDBPathExpander m_oDBPathExpander;

	CS2U m_oFileValueType;
	CS2U m_oRegistryValueType;

	void FillValueType();
	bool GetValueType(CString &csFullEntry, int &iValueType, CS2U &oValueType);

	bool VerifyProfilePath(CString &csRegistryEntry, CString &csValue);

	void HandleHKLMOrUserPath(const CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID);
	bool GetControlPath(const CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID);
	bool GetSoftwarePath(const CString &csRegistryEntry, CString &csReturnedPath, CString &csUserSID);
	bool GetSystemPath(const CString &csRegistryEntry, CString &csReturnedPath);
};
