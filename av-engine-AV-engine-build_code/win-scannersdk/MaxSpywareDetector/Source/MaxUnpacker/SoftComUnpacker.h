#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

class CSoftComUnpack : public CUnpackBase
{
public :
	CSoftComUnpack(CMaxPEFile *pMaxPEFile);
	~CSoftComUnpack(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);

};