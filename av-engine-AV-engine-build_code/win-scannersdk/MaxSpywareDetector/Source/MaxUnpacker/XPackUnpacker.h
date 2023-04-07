#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

typedef enum XPack_Type
{
	LZMA_XPack = 1,
	LZSS_XPack,
	LZSS_XComp,
	LZMA_XPackMod
};

class CXPackUnpacker : public CUnpackBase
{	
	DWORD m_dwOriAEP;
	DWORD m_dwOffset;
    XPack_Type m_eCompressionType;
    DWORD m_dw2Sections;
	
	bool ResolveImportAddresses(DWORD);
	bool ResolveCalls(BYTE*,DWORD,BYTE*,DWORD);

public:
	CXPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CXPackUnpacker(void);

	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
};

extern unsigned int align(unsigned int x, unsigned int alignment);