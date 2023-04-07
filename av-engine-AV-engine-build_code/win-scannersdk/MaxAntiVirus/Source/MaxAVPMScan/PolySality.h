/*======================================================================================
FILE				: PolySality.h
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
NOTES				: This is detection module for malware Sality Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#pragma once
#include "polybase.h"

const int AEP_PATCHED_BUFFER_SIZE	= 0x2000;
const int SALITY_BUFFER_SIZE		= 0x3000;

const int VIRUS_SALITY_Y	= 0x02;
const int VIRUS_SALITY_V	= 0x03;
const int VIRUS_SALITY_Z	= 0x04;
const int VIRUS_SALITY_AA	= 0x05;
const int VIRUS_SALITY_OG	= 0x06;
const int VIRUS_SALITY_BH	= 0x12;
const int VIRUS_SALITY_AF	= 0x14;
const int VIRUS_SALITY_AE	= 0x13;
const int VIRUS_SALITY_T	= 0x15;
const int VIRUS_SALITY_U	= 0x16;
const int VIRUS_SALITY_EX	= 0x17;

const int MAX_REG_LEN		= 0x10;
const int MAX_INST_SIZE		= 0x30;
const int DEC_TYPE_ADD		= 0x01;
const int DEC_TYPE_SUB		= 0x02;
const int DEC_TYPE_XOR		= 0x03;

//<START> 25 may 2011 ==> Adnan Declaration for Sality.T
typedef struct
{
	static const int T_AEP_PATCHED_COUNT	= 0x11;		// Number of bytes patched at AEP
	static const int T_DEC_START_OFFSET		= 0x2A;		// From virus start to no of bytes forward Decryption start
	static const int T_ORIGINAL_BYTE_OFFSET	= 0x5F0;	// In decrypted buffer no bytes forward original bytes start.
	static const int T_DEC_COUNTER			= 0x900;	// NO of bytes to be decrypted.
	WORD			 wDeckey;							// It contains one constant needed for decryption.
}SALITY_T_STRUCT;
//<END>

//Sality Structures
typedef struct
{
	DWORD dwKey;
	DWORD dwType;
	DWORD dwCounter;	
	DWORD dwOrgBytesOffset;
	DWORD dwReplaceBytes;
}SALITY_OG_STRUCT,*PSALITY_OG_STRUCT;

typedef struct
{
	DWORD dwKey;
	DWORD dwType;				
}SALITY_OG_AA_STRUCT,*PSALITY_OG_AA_STRUCT;

typedef struct
{
	DWORD dwKey;
	DWORD dw16ByteKeyOffset;				
}SALITY_BH_STRUCT,*PSALITY_BH_STRUCT;

typedef struct
{
	BOOL	bSectionName;
	DWORD 	dwTruncateOffset;
	DWORD   dwTruncateRVA;
	DWORD 	dwKey;
	DWORD 	dwType;	
	DWORD   dwPatchedOffset;
	DWORD   dwNoPachedBytes;
	bool    bDeleteFile;
	
}SALITY_AE_STRUCT,*PSALITY_AE_STRUCT;

typedef struct
{
	DWORD dwDecOffset;
	DWORD dwKey[0x02];
	DWORD dwType;	
  	BYTE  byVirusFound;
}SALITY_AF_STRUCT,*PSALITY_AF_STRUCT;

typedef struct
{
	static const int AEP_PATCHED_COUNT		= 0x6A;	// Number of bytes patched at AEP
	static const int DEC_COUNTER			= 0x500;	// NO of bytes to be decrypted.
	WORD			 wDeckey;							// It contains one constant needed for decryption.
	DWORD			 dwOrgBytesOffSet;
	DWORD			 dwLoopCounter;	
}SALITY_U_STRUCT;


typedef struct 
{
	BYTE					m_bMultipleCalls;
	BOOL					m_bIsJUMP;
	char					m_szReqReg[5];
	DWORD					m_dwAEPPatchCnt;
	BOOL					m_bIsPUSHADAEP;
	char					m_szFirstVirusInst[MAX_INST_SIZE];
	DWORD					m_dwVirusBodySize;
	DWORD					m_dwLastSecJumpRVA;
	DWORD					m_dwLastSecJumpOffset;
	DWORD					m_dwVirusRVA;
	DWORD					m_dwVirusOffSet;
	BOOL					m_bSalityAADEC;
	SALITY_OG_STRUCT		m_SalityOGParam;
	SALITY_OG_AA_STRUCT		m_SalityAAParam;
	SALITY_BH_STRUCT		m_SalityBHParam;
	SALITY_AE_STRUCT		m_SalityAEParam;
	SALITY_AF_STRUCT		m_SalityAFParam;
	SALITY_T_STRUCT			m_SalityTParam;
	SALITY_U_STRUCT			m_SalityUParam;
	DWORD					m_dwAddressofPatchedBytes;
}SALITY_PARAMS,*PSALITY_PARAMS;

typedef struct 
{
	DWORD	dwStartOffset;
	DWORD	dwSize;
	BYTE		byDecKey;
	DWORD	dwType;
}SalityExParams;

typedef enum SALITY_GEN_TYPE
{
	NO_VIRUS_FOUND = 0,
	SALITY_AA,
	SALITY_V,
	SALITY_Y,
	SALITY_AA_DEC_ZERO,
};

class CPolySality :	public CPolyBase
{
	DWORD			m_dwSalityType;
	DWORD			m_dwOriByteReplacementOff;
	DWORD			m_dwbufferReadRVA;
	DWORD           m_dwIndex;
	int				m_dwSalityExAEP;
	int				m_iIndex;
	
	SALITY_PARAMS	m_SalityParam;
	SALITY_GEN_TYPE	eSalityGenType;
	SalityExParams	m_objStructSalityExParams[10];
	Instruction_Set_Struct m_objInstructionSet[MAX_INSTRUCTIONS];
	
	// Detection routines
	DWORD	GetEmulatedRegister(DWORD dwStartAddress , 
								DWORD dwEndAddress ,
								char *szRequiredRegister, 
								DWORD dwDisasmStartAddr,
								int iStep);

	bool	GetSalityAEKeyModeEx(DWORD dwStart);
	bool	GetSalityAFKeyMode(DWORD dwStart);
	bool	GetInitialRegisterValue(char *pszReg, DWORD *piStart, DWORD *pKey);
	bool	GetSalityStartAddress();
	bool	GetFirstInst();
	bool	GetSalityOGPrimarDecParam(); 
	bool	GetSalityDecryptKeyModeEx();
	bool	GetDecryptKeyModeInstruction(DWORD dwStart);
	bool	GetSalityBHKeyEx();	    

	int		DetectSalityBHTrojan();
	int		DetectSalityAEorAF();	
	int		DetectSalityOG(); 
	int		DetectSalityBH();
	int		DetectSalityAA(bool bDeadCode);
	int		DetectSalityT();
	int		DetectSalityU();
	int		DetectSalityEx();
	int		DetectSalityStub();
	int		DetectSalityDriver();
	int		DeleteDeadCodeSamples();
	     
	// Cleaning routines
	int		CleanSalityAA();
	int		CleanSalityZ();
	int		CleanSalityBH();
	int		CleanSalityOG();
	int		CleanSalityAF();
	int		CleanSalityAE();
	int		CleanSalityT();
	int		CleanSalityU();
	int		CleanSalityEx();

	int		DetectSalityVirusType();
	int		RemoveSalityVirusCode();
	DWORD	TraceCALLInstruction(DWORD dwRVAStart,DWORD *dwCallOffset);
	DWORD	GetInstructionSet(BYTE *pBuff, DWORD dwSize, BYTE bEndOpt, DWORD *pCallLocation);
	DWORD	GetRequiredRegister(char *pRegister, DWORD *pLocation );
	DWORD	GetGivenRegisterValue(DWORD dwStart, char *pszReg, DWORD *pdwValue, DWORD *pdwNextStart);
	BOOL	GetEspValue(DWORD dwInitial, DWORD *dwValue, DWORD *pdwCount);
	DWORD	GetPushADInst(BYTE *pBuff,DWORD dwStart, DWORD dwRange);

	DWORD	CheckForValidDecryption();
	BOOL	Detect4ValidDec();

	BOOL 	CheckSalityYSig();
	BOOL 	CheckSalityAASig();
	BOOL 	CheckSalityVSig();
	BOOL    CheckSalityAESig();
	BOOL    CheckSalityAFSig();
	BOOL    CheckSalityStubSig(DWORD dwReadOffset);
	BOOL    CheckSalityOGSig();

	BOOL	SalityGenDecryption();

	BOOL 	GetSalityVCounterAndOffset();
	BOOL 	GetSalityYCounterAndOffset();
	BOOL 	GetSalityAACounterAndOffset();
	BOOL 	GetSalityAADECCounterAndOffset();

	BOOL	SalityAA_DEC();

	int		CleanSalityGen();
	int		RepairSalityGen(DWORD dwCounter, DWORD dwOffset);
	void	CheckPushAndRet();
	void	GetOriByteReplacementOff();

public:
	CPolySality(CMaxPEFile *pMaxPEFile);
	~CPolySality(void);

	int		DetectVirus(void);
	int		CleanVirus(void);
};
