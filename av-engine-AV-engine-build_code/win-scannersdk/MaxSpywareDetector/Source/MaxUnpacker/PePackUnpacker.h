#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CPePackUnpacker : public CUnpackBase
{	
	DWORD m_dwOriAEP;
	DWORD m_dwOffset;
	
public:
	CPePackUnpacker(CMaxPEFile *pMaxPEFile);
	~CPePackUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
};
