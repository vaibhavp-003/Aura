/*======================================================================================
FILE				: PolyXpaj.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Neeraj Singh + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Xpaj Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int XPAJ_GEN_BUFF_SIZE	= 0x250;
const int XPAJ_GEN_STUB_SIZE	= 0xD700;
const int XPAJ_GEN_VIRT_SIZE    = 0x2B000;

typedef struct _REL_STRUCT
{
	DWORD	dwBaseAdrs[0x50];
	DWORD	dwRelAdressArray[0x50][0x02];	
	DWORD	dwBaseEntries;
	DWORD	dwRelEntries;
}REL_STRUCT,*LPREL_STRUCT;

class CPolyXpaj : public CPolyBase
{
	DWORD	m_dwEBX;
	DWORD   m_dwECX;
	DWORD   m_dwEAX;
	DWORD   m_dwDecSize;
	DWORD	m_dwFirstKey;
	DWORD	m_dwSecondKey;
	DWORD   m_dwFourthKey;
	DWORD   m_dwRelocSize;
	DWORD   m_dwRelocStart;
	DWORD   m_dwDecStartRVA;
	DWORD   m_dwCalledAddRVA;
	DWORD   m_dwVirusStartRVA;
	DWORD   m_dwVirusCodeSize;
	DWORD   m_dwInfectionType;
	bool    m_bRelocPresent;
	bool    m_bImageSizeModified;

	int		DetectXpajGen();
	bool	GetEAX();
	bool	DecryptTableGen();
	bool    DecryptTableXpajA(DWORD dwFlag);
	bool    DecryptData(CEmulate &objEmulate);
	bool    GetXpajType(CEmulate &objEmulate);
	bool    CheckVirusTypeGen(CEmulate &objEmulate, DWORD dwCnt);
	bool    CleanXpajGen(CEmulate &objEmulate, DWORD dwCnt);
	bool    CleanXpajA(CEmulate &objEmulate, DWORD dwCnt);
	bool    CheckVirusTypeGenA(CEmulate &objEmulate, DWORD dwCnt);
	bool	CheckXpajGenInstructions(BYTE *pbyBuff);
	DWORD	CalculateRetAdd(DWORD dwPushVal, DWORD dwRetAdd, DWORD dwCallRawData, DWORD dwEAXConst);
	void	ReslovePatchedDataCallJMP(BYTE *byBuffer, DWORD dwCounter, DWORD dwBuffReadRVA, DWORD dwReplacementRVA);
	
	REL_STRUCT	m_structRelTable;
	void	ReapirRelocationTable();
	void	AddRelocTableEntry(DWORD dwAddress);

	//GENA
	DWORD	m_dwKeyA;
	DWORD	m_dwFirstKeyA;
	DWORD	m_dwSecondKeyA;
	DWORD	m_dwCounter1A;
	DWORD	m_dwCounter2A;
	DWORD	m_dwCopyStartA;
	DWORD   m_dwArrStart;
	DWORD   m_dwFirstAllocAddress;
	DWORD   m_dwSecondAllocAddress;
	BYTE	m_bDelete;

	int		_CleanVirus();
	bool	DecryptGenA1(LPBYTE byBuff);
	void	UpdateStack(LPBYTE byStackArr, DWORD dwRetVal, DWORD dwStackStart);
	void    UpdateRegisters(CEmulate &objEmulate, DWORD dwStackStart);
	bool	GetKeysXpajGenA(CEmulate &objEmulate, DWORD dwBuffIndex, LPBYTE byBuffer);
	bool    DecryptBuffXpajGenA(LPBYTE byBuffer, DWORD dwDecCnt, DWORD dwTemp, LPBYTE m_pbyBuff);	

public:
	CPolyXpaj(CMaxPEFile *pMaxPEFile);
	~CPolyXpaj(void);

	int		DetectVirus();
	int		CleanVirus();
};
