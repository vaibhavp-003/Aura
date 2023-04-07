#pragma once
#include "MaxPEFile.h"
#include "PEC2CodecSDK.h"
#include "UnpackBase.h"

typedef struct _LOADER_POGOPACK
{
	DWORD CompressedRVA;
	DWORD UncompressedRVA;
}LOADER_DECODER_INFO_PogoPack;

class CPogoUnpacker: public CUnpackBase
{
	bool ResolveE8E9Calls(BYTE *bySrcbuff, DWORD dwStart, DWORD dwSize);
	
public:
	CPogoUnpacker(CMaxPEFile *pMaxPEFile);
	~CPogoUnpacker(void);
	
	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);
};
