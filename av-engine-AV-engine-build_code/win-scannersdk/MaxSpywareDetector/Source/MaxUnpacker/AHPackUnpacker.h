#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"


class CAHPackUnpacker: public CUnpackBase
{

public:
	CAHPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CAHPackUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
