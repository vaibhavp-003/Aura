#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"


class CSimplePackUnpack: public CUnpackBase
{	
	
public:
	CSimplePackUnpack(CMaxPEFile *pMaxPEFile);
	~CSimplePackUnpack(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
