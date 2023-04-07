#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CExeUnpacker: public CUnpackBase
{

public:
	CExeUnpacker(CMaxPEFile *pMaxPEFile);
	~CExeUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);
	DWORD FindResourceEx(LPCTSTR lpstNameID, DWORD dwRead);
	int FindRes(LPCTSTR lpstNameID, LPCTSTR lpstLaunguage, LPCTSTR lpstLangID, DWORD &dwRVA, DWORD &dwSize);
};
