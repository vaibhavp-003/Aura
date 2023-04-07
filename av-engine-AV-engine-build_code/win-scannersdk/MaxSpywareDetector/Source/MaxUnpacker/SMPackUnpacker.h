#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CSMPackUnpacker: public CUnpackBase
{
	DWORD m_dwOffset;
	
public:
	CSMPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CSMPackUnpacker(void);
	
	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);
};
