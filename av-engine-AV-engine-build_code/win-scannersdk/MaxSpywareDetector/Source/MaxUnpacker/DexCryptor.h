#pragma once
#include "MaxPEFile.h"
#include "Emulate.h"
#include "UnpackBase.h"

typedef enum DexCrypt_Type
{
	POPAD = 0,
	SUB,
	NOP1,
	VCrypt
};

class CDexCryptor: public CUnpackBase
{	
	DWORD			m_dwOrigAEP;
    DexCrypt_Type	m_eCrypt_Type;
	DWORD           m_dwOffset;
	DWORD           m_dwIncrementSize;
		
	bool DecryptParts(DWORD dwSrcStart, DWORD dwSrcEnd, BYTE byXORkey,int iType);
	bool _IsPacked();	
	
public:
	CDexCryptor(CMaxPEFile *pMaxPEFile);
	~CDexCryptor(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
