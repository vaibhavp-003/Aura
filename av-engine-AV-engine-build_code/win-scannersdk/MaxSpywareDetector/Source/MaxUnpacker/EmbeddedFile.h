#pragma once
#include "unpackbase.h"

class CEmbeddedFile : public CUnpackBase
{
	DWORD m_dwStartOffset;
	DWORD m_dwSize;
	bool m_bXORCrypt;
	BYTE m_byXORKey;

	bool CheckFileInRrsSection();
	bool CheckFileInOverlay();
	bool CheckPKHeader();
	bool CheckXORCrypt();

	bool bSmartInstaller;	

public:
	CEmbeddedFile(CMaxPEFile *pMaxPEFile, int iCurrentLevel);
	~CEmbeddedFile(void);
		
	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
