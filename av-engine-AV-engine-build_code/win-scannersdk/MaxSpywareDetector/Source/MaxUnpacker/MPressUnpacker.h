#pragma once
#include "UnpackBase.h"

class CMPressUnpack: public CUnpackBase
{	
	bool ResolveImportAddresses(DWORD*);
	bool ResolveCalls(DWORD,bool bSubtract=true);	
	DWORD LZMATUncompress(DWORD,DWORD);

public:
	CMPressUnpack(CMaxPEFile *pMaxPEFile);
	~CMPressUnpack(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);
};
