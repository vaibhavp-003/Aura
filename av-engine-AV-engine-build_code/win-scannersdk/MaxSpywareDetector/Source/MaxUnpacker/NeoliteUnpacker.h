#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"



class CNeoliteUnpacker: public CUnpackBase
{	
	
public:
	CNeoliteUnpacker(CMaxPEFile *pMaxPEFile);
	~CNeoliteUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
};
