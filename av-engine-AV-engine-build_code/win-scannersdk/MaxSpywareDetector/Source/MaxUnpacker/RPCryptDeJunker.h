#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"
#include "Emulate.h"


class CRPCryptDeJunker: public CUnpackBase
{

public:
	CRPCryptDeJunker(CMaxPEFile *pMaxPEFile);
	~CRPCryptDeJunker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
