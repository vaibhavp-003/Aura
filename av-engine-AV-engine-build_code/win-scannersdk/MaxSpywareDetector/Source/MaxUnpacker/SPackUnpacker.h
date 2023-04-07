#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"

typedef struct _Param
{	DWORD RVAStart;
	DWORD Size;
}DecryptParam;

class CSPackUnpacker: public CUnpackBase
{	
	DWORD			m_dwOrigAEP;
	DWORD           m_dwOffset;
	DWORD           m_dwIncrementSize;
		
public:
	CSPackUnpacker(CMaxPEFile *pMaxPEFile);
	~CSPackUnpacker(void);

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
};
