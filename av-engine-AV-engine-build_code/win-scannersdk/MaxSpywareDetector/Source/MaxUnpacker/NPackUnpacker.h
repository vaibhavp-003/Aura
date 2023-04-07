#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"


class CNPackUnpacker: public CUnpackBase
{	
	typedef struct _DecompressInfo
	{
		DWORD dwAEP;
		DWORD dwResolveImports;
		DWORD dwOldAEP;
		DWORD dwResourcesSize;
		DWORD dwFlag;
		DWORD dwResourcesDecompressCompare;
		DWORD dwDecryptValue;
	}DecompressInfo;
	
public:
	CNPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CNPackUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
