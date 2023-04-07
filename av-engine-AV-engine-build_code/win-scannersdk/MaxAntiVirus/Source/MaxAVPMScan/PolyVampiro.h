/*======================================================================================
FILE				: PolyVampiro.h
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam + Virus Analysis Team
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for malware Vampiro Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
					  Emulation is used for detection for this family 
					  as virus is very complecated and virus code is very scattered.
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyBase.h"

const int MAX_VAMPIRO_BUFF_SIZE = 0x5400;			

typedef struct
{
	DWORD Eip;
	DWORD JmpOffset;
	DWORD CmpOffset;
	int CounterReg;
	DWORD CounterValue;
}JumpData;

typedef struct 
{
	char szInstrName[MAX_INSTRUCTION_LEN];
	DWORD dwOperand;
	BYTE m_byInstrLen;
	BYTE bySrcReg;
	BYTE byDestReg;
	DWORD SrcRegValue;
	DWORD DestRegValue;
}KeyOPerations;

class CPolyVampiro :
	public CPolyBase
{	
	DWORD	m_dwType;
	DWORD	m_dwKey;
	DWORD	m_dwCounter;
	DWORD	m_dwPatcedAddr;
	DWORD	m_dwCalledAdd;
	DWORD	m_dwOffset;
	char	szRegName[3][5];
	BYTE	m_byKeyRegNo;
	BYTE	m_byCheck;

	DWORD 	m_dwKeyChngType[5];
	DWORD 	m_dwKeyChngKey[5];
	int		m_iVariant;

	int PrimaryDetection();
	int DetectVampiroDec(CEmulate &objEmulate);
	int GetDecryptionParameter(CEmulate &objEmulate, bool &bIsKeyReg);	
	int GetKeyChangeParameter(KeyOPerations *KeyOPs);

	void DoDecryption(DWORD dwIndex);
	void DoDecryptionRev(int);
	void DecryptKey();

	bool CalculateCallAdderess();

public:
	CPolyVampiro(CMaxPEFile *pMaxPEFile);
	~CPolyVampiro(void);

	int DetectVirus();
	int CleanVirus();
};
