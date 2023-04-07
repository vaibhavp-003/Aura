#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

enum
{
	NORMAL_NS=0x00,
	JMP_NS,
	MODIFIED_NOP,
};

typedef struct LZMAINFO
{
	DWORD dwSrcSize;
	DWORD dwDestSize;
	DWORD dwDestRVA;
}LZMAInfo;

typedef struct ResolveCallsInfo
{
	DWORD dwAddressOffset;
	DWORD dwtemp1;
	DWORD dwCallsCounter;
	DWORD dwtemp2;
	BYTE dwCallValue[0x04];
}ResolveCallsInfo;

class CNSPackUnpacker: public CUnpackBase
{	
	DWORD           m_dwOffset;
	LZMAInfo        *m_pStructLZMAInfo;
	ResolveCallsInfo *m_pStructResolveCallsInfo;
	int m_NSPackType;
	
public:
	CNSPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CNSPackUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);
	bool ResolveE8E9Calls(BYTE*,DWORD dwSize,ResolveCallsInfo * pStructResolveCalls);
	bool ResolveImportTable(BYTE**,BYTE*,BYTE*,DWORD,DWORD,BYTE*,DWORD &size);
};

