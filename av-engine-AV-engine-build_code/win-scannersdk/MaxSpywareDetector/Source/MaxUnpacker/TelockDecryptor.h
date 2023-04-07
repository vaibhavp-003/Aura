#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"
#include "Emulate.h"


class CTelockDecryptor: public CUnpackBase
{	
	DWORD m_dwOffset;
	typedef struct _DecompressInfo
	{
		DWORD dwResolveImports;
		DWORD dwIncaseImageBaseChange;
		DWORD dwRVADecompressRes;
		DWORD dwA;
		DWORD dwNewImageBase;
		DWORD dwOldImageBase;
        DWORD dwOffsetInsideResolveImp;
		DWORD dwDestResolveImpSize;
		DWORD dwOffsetAddResolve;
		DWORD dwCRCKey;
		DWORD dwKey2;
		DWORD dwNoOfPECBlocks;
		DWORD dwAEP;
	}DecompressInfo;

	typedef struct _SingleBlockInfo
	{
		DWORD dwRVA;
		DWORD dwSize;
		DWORD dwCRCCheckValue;
	}SingleBlockInfo;

public:
	CTelockDecryptor(CMaxPEFile *pMaxPEFile);
	~CTelockDecryptor(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
	DWORD CallEmulatorDissambler(DWORD,BYTE*,CEmulate objEmulate,DWORD* = NULL,DWORD* = NULL,DWORD *dwRegIndex=0,BYTE* = NULL,int iType=0,bool *bContinue=NULL);
	DWORD ImplementCRCFunction(BYTE *,DWORD dwLoopSize);
	bool BuildJunkCodeandDecrypt(BYTE *bybuff,DWORD dwDecryptOffsetKey,DWORD dwDecryptOffset,BYTE *bykey2,DWORD dwKeySize);
	bool UnPackTelockCryporPolyEmulator(BYTE *,BYTE*,DWORD,DWORD,DWORD*);
};
