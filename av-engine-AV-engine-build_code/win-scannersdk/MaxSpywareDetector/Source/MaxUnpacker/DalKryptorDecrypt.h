#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"


class CDalKryptorDecrypt: public CUnpackBase
{

public:
	CDalKryptorDecrypt(CMaxPEFile *pMaxPEFile);
	~CDalKryptorDecrypt(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
