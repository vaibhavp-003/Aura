#pragma once
#include "MaxPEFile.h"
#include "unpackbase.h"

class CNullSoft : public CUnpackBase
{
public:
	CNullSoft(CMaxPEFile *pMaxPEFile);
	~CNullSoft(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
};
