#pragma once
#include "UnpackBase.h"



class CMaskPEUnpacker: public CUnpackBase
{	
     DWORD m_dwOffset;
public:

	CMaskPEUnpacker(CMaxPEFile *pMaxPEFile);
	~CMaskPEUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
};
