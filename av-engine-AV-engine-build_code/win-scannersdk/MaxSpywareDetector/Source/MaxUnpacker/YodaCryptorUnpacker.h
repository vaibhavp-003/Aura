#pragma once
#include "MaxPEFile.h"
#include "UnpackBase.h"


class CYodaCryptorDecrypt: public CUnpackBase
{	
	enum
	{
		e8dBd=1,
		e81E9
	};


	typedef struct _stSectionCheckList
	{
		DWORD dwValue;
		_stSectionCheckList * next;
	}stSectionCheckList;

	DWORD m_dwOffsetMove;


	int m_eYodaType;
public:
	CYodaCryptorDecrypt(CMaxPEFile *pMaxPEFile);
	~CYodaCryptorDecrypt(void);
	stSectionCheckList *pSectionCheckList;

	bool IsPacked();	
	bool Unpack(LPCTSTR szTempFileName);	
	bool UnPackYodaCryporPolyEmulator(BYTE *,BYTE*,DWORD,DWORD);
	//bool CheckImports(BYTE*);
};
