#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"
#include "Emulate.h"

enum Upacktypes
{
	NORMAL = 0,
	NORMALMOD,
	NORMALMOD2,
	JMP,
	PUSHAD,
	DECRYPT_NORMAL,
	DECRYPT_NORMAL2
};

typedef struct _BLOCKINFO
{
	DWORD dwSrcRead;
	DWORD dwA;
	DWORD dwResolveCallsLoop;
	DWORD dwB;
	DWORD dwWriteOffset;
	DWORD dwSrcEnd;
	DWORD dwC[0x04];
	DWORD dwAEP;
	DWORD dwResolveImports;
	DWORD dwCD[0x02];
	DWORD dwWriteEnd;
	DWORD dwResolveCallsOffs;
}BLOCKINFO;

typedef struct _BLOCKNORMALMODINFO
{
	DWORD dwSrcRead;
	DWORD dwA[0x02];
	DWORD dwWriteOffset;
	DWORD dwB1[0x02];
    DWORD dwSrcEnd;
	DWORD dwC1[0xA];
	DWORD dwResolveCallsLoop;
	DWORD dwResolveCallsOffsetSubtract;
    DWORD dwB[0x07];
	DWORD dwWriteEnd;
	DWORD dwResolveImports;
}BLOCKNORMALMODINFO;


typedef struct _BLOCKNORMALMOD2INFO
{
	DWORD dwSrcRead;
	DWORD dwA[0x7];
	DWORD dwWriteOffset;
	DWORD dwSrcEndLZMACalculatelc;
	DWORD dwB[0x6];
	DWORD dwResolveCallsOffsetSubtract;
	DWORD dwC[0x2];
    DWORD dwStartofLZMA;
	DWORD dwWriteEnd;
	DWORD dwResolveCallsLoop;
    DWORD dwD;
	DWORD dwResolveImports;
}BLOCKNORMALMOD2INFO;

typedef struct _BLOCKINFOPUSHAD
{
	DWORD dwSubtractOffset;
	DWORD dwA;
	DWORD CounterToMove;
	DWORD CounterAddIfOffsetNotZero;
	DWORD dwWriteOffset;
	DWORD dwSrcEnd;
	DWORD dwB[0x4];
	DWORD dwResolveCallsOffsetSubtract;
	DWORD dwCi[0x02];
	DWORD dwLZMAOffset;
	DWORD dwWriteEnd;
	DWORD dwD;
	DWORD dwResolveImports;
	DWORD dwE[0x4];
	DWORD dwResolveCallsLoop;
	DWORD dwAfterResolveImportsOffset;
	DWORD dwSrcRead;
}BLOCKINFOPUSHAD;

typedef struct _BLOCKINFOJMP
{
 DWORD dwSrcRead;
 DWORD dwWriteOffSet;
 DWORD dwToCalculateAEP;
 DWORD dwA[0x6];
 DWORD dwResolveCallsOffsetSubtract;
 DWORD dwB[0x2];
 DWORD dwToCalculateLZMAlcAndSrcEnd;
 DWORD dwWriteEnd;//0x2C here 0x30
 DWORD dwResolveCallsLoop;
 DWORD dwCq;
 DWORD dwResolveImports;
}BLOCKINFOJMP;

class CWinUpackUnpacker: public CUnpackBase
{
	DWORD	m_dwOffset;
	int		m_UpackType;
	
	bool ResolveE8E9Calls(BYTE*,DWORD dwUncompressedLengthSize,DWORD dwCounterSize,DWORD,DWORD,BYTE byCompare);
	bool ResolveImports(BYTE*,BYTE**,DWORD *ImportSize,DWORD dwImportOffset);
	
public:
	CWinUpackUnpacker(CMaxPEFile *pMaxPEFile);
	~CWinUpackUnpacker(void);
	
	bool IsPacked();
	bool Unpack(LPCTSTR szTempFileName);	
};
