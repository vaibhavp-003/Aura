/*======================================================================================
FILE				: NonRepairable.cpp
ABSTRACT			: Part of AuAVPMScan.dll module.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 25 Jun 2010
NOTES				: This is detection module for Non-repairable malwares.
					  The repair action is : DELETE
VERSION HISTORY		: 
=====================================================================================*/
#include "NonRepairable.h"
#include "SemiPolyDBScn.h"
#include "PolymorphicVirus.h"
#include "MaxExceptionFilter.h"

/*-------------------------------------------------------------------------------------
	Function		: CNonRepairable
	In Parameters	: CMaxPEFile *pMaxPEFile, LPCTSTR pFilename
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CNonRepairable::CNonRepairable(CMaxPEFile *pMaxPEFile, LPCTSTR pFilename):
CPolyBase(pMaxPEFile),
m_pFileName(pFilename)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CNonRepairable
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CNonRepairable::~CNonRepairable(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirus
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Detection routine for list of malwares using polymorphism
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVirus()
{
	TCHAR	szLogLine[1024] = {0x00};
	if(!m_pMaxPEFile->m_byVirusRevIDs)
	{
		return VIRUS_NOT_FOUND;
	}

	LPCTSTR szOnlyFileName = NULL;
	szOnlyFileName = m_pFileName? _tcsrchr(m_pFileName, _T('\\')): NULL;
	if(szOnlyFileName && 0 == _tcsicmp(szOnlyFileName, REGSVR))
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.W32.Agent"));
		return VIRUS_FILE_DELETE;
	}
		
	typedef int (CNonRepairable::*LPFNDetectVirus)();
	
	LPFNDetectVirus pVirusList[] = 
	{
		&CNonRepairable::DetectSmalli,
		&CNonRepairable::DetectXorerei,
		&CNonRepairable::DetectVBEY,
		&CNonRepairable::DetectVBEL,
		&CNonRepairable::DetectSantana1104,
		&CNonRepairable::DetectHLLP41472e,
		&CNonRepairable::DetectHLLOMomacA,
		&CNonRepairable::DetectAgentCH,
		&CNonRepairable::DetectXorerEA,
		&CNonRepairable::DetectXorerBH,
		&CNonRepairable::DetectVBU,
		&CNonRepairable::DetectVBhq,
		&CNonRepairable::DetectVBBG,
		&CNonRepairable::DetectVBBC,
		&CNonRepairable::DetectSmallN,
		&CNonRepairable::DetectProjet2649,
		&CNonRepairable::DetectMezq,
		&CNonRepairable::DetectXbotor,
		&CNonRepairable::DetectVBC,
		&CNonRepairable::DetectSalityATBH,
		&CNonRepairable::DetectPesinA,
		&CNonRepairable::DetectLevi3205,
		&CNonRepairable::DetectVBLP,
		&CNonRepairable::DetectVBK,
		&CNonRepairable::DetectVBGP,
		&CNonRepairable::DetectVBCR,
		&CNonRepairable::DetectVBCM,
		&CNonRepairable::DetectVBBT,
		&CNonRepairable::DetectVBCS,
		&CNonRepairable::DetectSantana,
		&CNonRepairable::DetectLevi,
		&CNonRepairable::DetectLamerKL,
		&CNonRepairable::DetectCargo,
		&CNonRepairable::DetectFontraA,
		&CNonRepairable::DetectWLKSM,
		&CNonRepairable::DetectHLLWRologC,
		&CNonRepairable::DetectHLLWRandir,
		&CNonRepairable::DetectHLLWMintopA,
		&CNonRepairable::DetectHLLWProdvin,
		&CNonRepairable::DetectHLLWVBA,
		&CNonRepairable::DetectHLLWVBS,
		&CNonRepairable::DetectHLLPLaboxA,
		&CNonRepairable::DetectXorerA,
		&CNonRepairable::DetectHLLO28672,
		&CNonRepairable::DetectBubeG,
		&CNonRepairable::DetectBolzanoGen,
		&CNonRepairable::DetectVBCC,
		&CNonRepairable::DetectDelfB,
		&CNonRepairable::DetectDecon,
		&CNonRepairable::DetectInfector,
		&CNonRepairable::DetectPECorrupt,
		&CNonRepairable::DetectIdele,
		&CNonRepairable::DetectBakaver,
		&CNonRepairable::DetectLordPE,
		&CNonRepairable::DetectKME,
		&CNonRepairable::DetectStepar,
		//&CNonRepairable::DetectCrypto,
		&CNonRepairable::DetectCivut,
		&CNonRepairable::DetectLom,
		&CNonRepairable::DetectMental,
		&CNonRepairable::DetectBayan,
		&CNonRepairable::DetectAldebaran, //Emulator
		&CNonRepairable::DetectBlaken,
		&CNonRepairable::DetectLegacy,
		&CNonRepairable::DetectGolem,
		&CNonRepairable::DetectFunloveDam,
		&CNonRepairable::DetectKaze,
		&CNonRepairable::DetectSankei,
		&CNonRepairable::DetectEnerlam,
		&CNonRepairable::DetectTick,
		&CNonRepairable::DetectTolone,	
		&CNonRepairable::DetectVulcano,
		&CNonRepairable::DetectNakuru,
		&CNonRepairable::DetectRufis,
		&CNonRepairable::DetectDroworC,
		&CNonRepairable::DetectXorer,
		&CNonRepairable::DetectNGVCK,
		&CNonRepairable::DetectDockA,
		&CNonRepairable::DetectVB,
		&CNonRepairable::DetectDream,
		&CNonRepairable::DetectSuperThreat,
		&CNonRepairable::DetectDelf,
		&CNonRepairable::DetectSmall98,
		&CNonRepairable::DetectTwinny,
		&CNonRepairable::DetectAgentJ,
		&CNonRepairable::DetectHarrier,
		&CNonRepairable::DetectRedlofA,
		&CNonRepairable::DetectZMorph,
		&CNonRepairable::DetectMosquitoC,
		&CNonRepairable::DetectIkatA,
		&CNonRepairable::DetectGlyn,
		&CNonRepairable::DetectDurchinaA,
		&CNonRepairable::DetectIframerC,
		&CNonRepairable::DetectVBZ,
		&CNonRepairable::DetectVirusArisG,
		&CNonRepairable::DetectVirusTexelK,
		&CNonRepairable::DetectVBAZ,
		&CNonRepairable::DetectVbAA,
		&CNonRepairable::DetectSalityK		
	};

	int iRetStatus = VIRUS_NOT_FOUND;
	for(int i = 0; i < _countof(pVirusList); i++)
	{
		iRetStatus = (this->*(pVirusList[i]))();
		if(iRetStatus)
		{					
			return iRetStatus;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectIdele
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Idele
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectIdele(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wNoOfSections > 0x01 && m_wAEPSec == 0)
	{				
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[IDELE_BUFF_SIZE];
		
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + m_pSectionHeader[0].SizeOfRawData - 0x25, IDELE_BUFF_SIZE, IDELE_BUFF_SIZE))
		{
			BYTE byIdeleSig[] = {0x60, 0x68, 0x00, 0x20, 0x00, 0x00, 0x6A, 0x00, 0xFF, 0x15};
			BYTE byIdeleStubSig[] = {0x57, 0x61, 0x72, 0x6E, 0x69, 0x6E, 0x67, 0x21, 0x00, 0x52, 0x65, 0x61, 0x64, 0x79, 0x20, 0x74, 
				0x6F, 0x20, 0x62, 0x65, 0x20, 0x69, 0x6E, 0x66, 0x65, 0x63, 0x74, 0x65, 0x64, 0x0A, 0x0D, 0x62, 
				0x79, 0x20, 0x49, 0x64, 0x65, 0x6C, 0x65, 0x20, 0x20, 0x0A, 0x0D, 0x76, 0x69, 0x72, 0x75, 0x73};
			
			if(((memcmp(byIdeleSig, m_pbyBuff, sizeof(byIdeleSig)) == 0 || memcmp(byIdeleSig + 1, m_pbyBuff, sizeof(byIdeleSig) - 1) == 0) && 
				m_pbyBuff[0x1A] == 0xAD && m_pbyBuff[0x20] == 0xAB && m_pbyBuff[0x24] == 0xC3) ||
				memcmp(byIdeleStubSig, &m_pbyBuff[0x25], sizeof(byIdeleStubSig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Idele"));		
				return VIRUS_FILE_DELETE;
			}
		}
	}	
	return iRetStatus;
}


/*--------------------------------------------------------------------------------------
Function Name	:	DetectVirus
Author			:	omkar.p	
Input			:	None
Output			:   int VIRUS_NOT_FOUND/VIRUS_FILE_REPAIR
Description		:	Detection poly virus Virus.W32.Bakaver
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectBakaver()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	
	DWORD dwDecryptnLoopOff = m_pSectionHeader[m_wAEPSec].VirtualAddress + m_pSectionHeader[m_wAEPSec].Misc.VirtualSize;
	if(dwDecryptnLoopOff != m_pSectionHeader[m_wAEPSec + 1].VirtualAddress)
	{
		if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwDecryptnLoopOff, &dwDecryptnLoopOff))
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[BACAVER_LOOP_SZ + MAX_INSTRUCTION_LEN];
			if(m_pbyBuff)
			{
				memset(m_pbyBuff, 0, BACAVER_LOOP_SZ + MAX_INSTRUCTION_LEN);
				if(GetBuffer(dwDecryptnLoopOff, BACAVER_LOOP_SZ, BACAVER_LOOP_SZ))
				{
					if(GetBakaverParam())
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Bakaver.C"));
						iRetStatus = VIRUS_FILE_DELETE;
						return iRetStatus;
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*--------------------------------------------------------------------------------------
Function Name	:	GetBakaverParam
Author			:	omkar.p	
Input			:	None
Output			:   bool TRUE on success/FALES on FAIL
Description		:	Dissassemble virus body to get n check parameter for decryption
--------------------------------------------------------------------------------------*/
bool CNonRepairable::GetBakaverParam()
{
	DWORD		dwLength = 0x00, dwOffset = 0x00, dwSeq = 0;
	BYTE		B1 = 0, B2 = 0;
	bool		bConstInst = false;

	t_disasm	da;

	while(dwOffset < BACAVER_LOOP_SZ)
	{
		memset(&da, 0x00, sizeof(struct t_disasm) * 1);

		B1 = *((BYTE *)&m_pbyBuff[dwOffset]);
		
		if(bConstInst && dwSeq == 7 && (B1 == 0xC3 || B1 == 0xE8 || B1 == 0xE9))
		{	
			return true;
		}
		else if(dwSeq == 7)
		{
			dwOffset++;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (BACAVER_LOOP_SZ - dwOffset))
		{
			break;
		}

		if(	dwSeq < 4 &&
			((dwLength == 0x05 && strstr(da.result, "MOV") && 0x231F == da.immconst) ||
			(dwLength == 0x06 && strstr(da.result, "SUB") && -0x231F == da.immconst) ||
			(dwLength == 0x05 && strstr(da.result, "MOV")) ||
			(dwLength == 0x05 && strstr(da.result, "ADD")) ||
			(dwLength == 0x06 && strstr(da.result, "SUB")) ||
			(dwLength == 0x06 && strstr(da.result, "ADD")) ||
			(dwLength == 0x01 && strstr(da.result, "PUSH"))))
		{	
			if(0x231F == da.immconst || -0x231F == da.immconst)
			{
				bConstInst = true;
			}
			dwSeq++;
		}

		// Decryption Loop Start
		else if(dwSeq == 4 && ((dwLength == 2 && strstr(da.result, "MOV")) || dwLength == 1 && strstr(da.result, "LODS")))
		{
			dwSeq++;
		}
		else if(dwSeq > 4 && dwSeq < 8 && (strstr(da.result, "ADD") || strstr(da.result, "SUB") || strstr(da.result,"ROL") || strstr(da.result, "XOR")))
		{	
			dwSeq++;
		}
		
		dwOffset += dwLength;
	}//end while
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectLordPE
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Trojan.LordPE
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectLordPE()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x01 && m_pSectionHeader[0].PointerToRawData == 0x200)
	{
		const BYTE byLordPESig[] = {0x5B, 0x4C, 0x6F, 0x72};
		const BYTE byHelloWorldSig[] = {0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 
										0x6F, 0x00, 0x20, 0x00, 0x77, 0x00, 0x6F, 0x00, 
										0x72, 0x00, 0x6C, 0x00, 0x64, 0x00, 0x21, 0x00, 
										0x00, 0x00, 0x00, 0x00, 0x43, 0x00, 0x61, 0x00, 
										0x70, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6F, 0x00, 0x6E};
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[LORD_PE_BUFF_SIZE];
		if(GetBuffer(0x18, 4, 4))
		{
			if(memcmp(m_pbyBuff, byLordPESig, sizeof(byLordPESig))== 0)
			{
				memset(m_pbyBuff, 0x00, LORD_PE_BUFF_SIZE);
				if(GetBuffer(0x200, LORD_PE_BUFF_SIZE, LORD_PE_BUFF_SIZE))
				{
					for(DWORD dwOffset = 0; dwOffset < LORD_PE_BUFF_SIZE - sizeof(byHelloWorldSig); dwOffset++)
					{
						if(memcmp(&m_pbyBuff[dwOffset], byHelloWorldSig, sizeof(byHelloWorldSig))== 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.LordPE"));		
							iRetStatus = VIRUS_FILE_DELETE;
							break;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectStepar
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Stepar Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectStepar(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	TCHAR szVirusName[MAX_PATH] = {0};
	TCHAR SteparD_Sig[] ={ _T("E5B0B0729D2F778D636EACFB8DC2793C73B43A8C0860236F929B029B8ED16431D86A8D0CA448E3E9667F7B0982DB*7262321C8D9DC973048DCC81C172ADAB3F0000679AAB546A6405FB7D537BB117F0B2F3A4389D16617F83F78DF8950084865E00E80D8EB700737DC27247FF878C") };
	TCHAR Stepar_E_L_Sig[] = { _T("63A3A3FB8D30253E7354848D0860DF6C929BFA9C8E91862ED82A4BF3A4C862D5677F7C3781DB7262711E8D9D887D048DCE5C*C072AD923E0000999CAB546A6405FB7D9379B11730B4F3A4B89CD7607F84368EF8950084465C00E84D88B7007385C27247FF878C93C8898D96387772") };
	TCHAR Stepar_F_DR_Sig[] = { _T("DB61B0177B4A323D80ADCEB7B0729D5A748D633BA1FB8DC0503F73B4638F0860D161929BE2848EE9E94ED842860CA458DDC2*617F83308FDB7262311F8D9DB07E048D3EAAC6724D65310000776354546AA4FAFB7D3B88B1179849F3A4A8623F667F7CCE80F895009C9E5D00D8E589") };
	TCHAR SteparG_Sig[] = { _T("5894B0F21DFD9C46B1DF7E840D8FB046B95502D008E0973196CB444DDB7550662C5E6DF3A4D4F249933F2E5E79248D1DAD56*39310570040D718740B9291A1B8080C46154546AD4048122B7102A54BBEAF3A414EDD690BFB1587A076A00A25F7D005443E3B780C5412F7247FFBA46") };
	TCHAR SteparI_Sig[] = { _T("84A6EE17E8950834E48755001456D5978BA6FF73BA9BF9DA404583274F8D1D160139B17450040D70F624B9AAF06708E011B6*91CB4B41DD6331EA2B977AF3A49CED71F7BF310AAFDB8D9D194B3931F598040DF1D724B9A99F28008043625454EAD48482A24AFE295442B40CDBEC2D") };
	TCHAR SteparJ_Sig[] = { _T("27B1B0729DEB768D63ACA3FB8DCE243E73AC848D0860DF6C929BFA9C8E90862ED82B4BF3A4C862D4677F7C3881DB7262701E*8D9D8F7D048DC05BC072B5953E0000979CAB546A6405FB7D9C79B11707B4F3A4D89CD4607F84398EF8950084475C00E83288B7008D85C27247FF878C") };

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL &&
		(m_pMaxPEFile->m_stPEHeader.SizeOfStackCommit >= 0x10000))
	{
		DWORD dwAllocSize = STEPAR_BUFF_SIZE;
		DWORD dwReadOffset = m_pSectionHeader[m_wNoOfSections-1].PointerToRawData;

		if(m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData < STEPAR_BUFF_SIZE)
			dwAllocSize = m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData;
		else
			dwReadOffset = m_pSectionHeader[m_wNoOfSections-1].PointerToRawData +
						   m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData - STEPAR_BUFF_SIZE;

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}		
		m_pbyBuff = new BYTE[dwAllocSize];

		if(!m_pbyBuff)
			return iRetStatus;

		if(GetBuffer(dwReadOffset, dwAllocSize, dwAllocSize))
		{
			CSemiPolyDBScn polydbObj;
			if(polydbObj.LoadSigDBEx(SteparD_Sig, _T("Virus.Stepar.D"), TRUE) <= 1)
				return iRetStatus;

			polydbObj.LoadSigDBEx(Stepar_E_L_Sig, _T("Virus.Stepar.E"), TRUE);
			polydbObj.LoadSigDBEx(Stepar_F_DR_Sig, _T("Virus.Stepar.F"), TRUE);
			polydbObj.LoadSigDBEx(SteparG_Sig, _T("Virus.Stepar.G"), TRUE);
			polydbObj.LoadSigDBEx(SteparI_Sig, _T("Virus.Stepar.I"), TRUE);
			polydbObj.LoadSigDBEx(SteparJ_Sig, _T("Virus.Stepar.J"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], dwAllocSize, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName)>0)
				{
					iRetStatus = VIRUS_FILE_DELETE;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectKME
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.KME Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectKME()
{
	m_bySig = 0x00;
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL &&
		m_dwAEPMapped != 0 && 
		m_wAEPSec == m_wNoOfSections - 1 && 
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x8000 &&
		m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion != 0x5A)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[MAX_KME_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, MAX_KME_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, 0x200, 0x100))
		{
			if(GetKMESigByte())
			{
				DWORD dwBufferReadOff = m_dwAEPMapped;
				if(((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) - m_dwAEPMapped) < MAX_KME_BUFF_SIZE)
				{					
					dwBufferReadOff -= MAX_KME_BUFF_SIZE - ((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) - m_dwAEPMapped);
				}
	
				memset(m_pbyBuff, 0x00, MAX_KME_BUFF_SIZE);
				if(GetBuffer(dwBufferReadOff, MAX_KME_BUFF_SIZE, MAX_KME_BUFF_SIZE))
				{
					if(SearchKMEByteSig())
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.KME"));
						iRetStatus = VIRUS_FILE_DELETE;
					}
				}
			}
		}	
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKMESigByte
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.KME Family
--------------------------------------------------------------------------------------*/
bool CNonRepairable::GetKMESigByte()
{
	for(DWORD dwIndex = 0x00, dwTemp = 0x00; dwIndex < m_dwNoOfBytes;)
	{
		if(!GetKMESigByteStartOffset(dwIndex))
		{
			return false;
		}
		dwTemp = dwIndex;
		DWORD dwCount = 0;
		for(; dwCount < 0x30 && ((dwCount + dwIndex + 6) < m_dwNoOfBytes); dwCount++)
		{
			if(m_pbyBuff[dwIndex] == m_pbyBuff[dwIndex + 1])
			{
				dwIndex++;
				continue;
			}
			break;
		}
		if(dwCount == 0x30)
		{
			m_bySig = m_pbyBuff[dwTemp];
			return true;
		}
	}	
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: SearchKMEByteSig
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.KME Family
--------------------------------------------------------------------------------------*/
bool CNonRepairable::SearchKMEByteSig()
{
	DWORD dwSigMatchCount = 0, dwCount = 0, dwSigByteCount = 0;

	for(dwCount = 0x00; dwCount < m_dwNoOfBytes; dwCount++)
	{
		if(m_pbyBuff[dwCount] != m_bySig)
			break;
	}
	for(; dwCount < m_dwNoOfBytes; dwCount++)
	{
		dwSigByteCount = 0x00;
		if(m_pbyBuff[dwCount] != m_bySig || m_pbyBuff[dwCount+1] != m_bySig)
			continue;
		while(m_pbyBuff[dwCount] == m_bySig && dwCount < m_dwNoOfBytes)
		{
			dwCount++;
			dwSigByteCount++;
		}
		if(dwSigByteCount >= 0x20)
		{
			dwSigMatchCount++;
		}
		if(dwSigMatchCount >= 0x02)
		{
			if(m_bySig == 0x00)
			{
				if(dwSigMatchCount >= 0x05)
				{
					return true;
				}
			}
			else
			{
				return true;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetKMESigByteStartOffset
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.KME Family
--------------------------------------------------------------------------------------*/
bool CNonRepairable::GetKMESigByteStartOffset(DWORD &dwSigStart)
{
	DWORD dwOffset = dwSigStart, dwLength = 0, dwInstCount = 0x00;

	BYTE B1 = 0, B2 = 0, B3 = 0;
	t_disasm da = {0};

	while(dwOffset < m_dwNoOfBytes)
	{
		if(dwInstCount > 0x60)
		{
			return false;
		}
		memset(&da, 0x00, sizeof(struct t_disasm) * 1);
		B1 = *((BYTE *)&m_pbyBuff[dwOffset]);
		B2 = *((BYTE *)&m_pbyBuff[dwOffset + 1]);

		if((B1 == 0xC0 || B1 == 0xC1) && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x03;
			continue;
		}
		if(B1 == 0xD1 && (B2 >= 0xF0 && B2 <= 0xF7))
		{
			dwOffset+= 0x02;
			continue;
		}
		if(B1 == 0xE2 && dwLength == 0x01)
		{
			dwOffset += 2;
			continue;
		}

		dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
		if(dwLength > (m_dwNoOfBytes - dwOffset))
		{
			return false;
		}
		dwInstCount++;

		if(dwLength >= 0x05 && strstr(da.result, "J"))
		{
			dwSigStart = dwOffset + dwLength;
			return true;
		}		
		dwOffset += dwLength;
	}
	return false;
}


const int KRAP_BUFF_SIZE = 0x100;

/*-------------------------------------------------------------------------------------
	Function		: DetectKrap
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Krap
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectKrap()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 4 && m_dwAEPUnmapped == 0x1000 && m_pMaxPEFile->m_stPEHeader.SectionAlignment == 0x1000 && m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x200)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[KRAP_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, KRAP_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, KRAP_BUFF_SIZE))
		{
			if(m_pbyBuff[0] != 0x55 || m_pbyBuff[1] != 0x8B || m_pbyBuff[2] != 0xEC)
			{
				return iRetStatus;
			}
			BYTE		B1, B2;
			DWORD		dwLength = 0x00, dwInstructionCnt = 0x00, dwStartAddress = 0x00, dwCheckAdd =0x00;
			DWORD		dwValue = 0x00;
			t_disasm	da;

			while(dwStartAddress < m_dwNoOfBytes && dwInstructionCnt < 0x30)
			{
				memset(&da, 0x00, sizeof(struct t_disasm)*1);

				B1 = *((BYTE *)&m_pbyBuff[dwStartAddress]);
				B2 = *((BYTE *)&m_pbyBuff[dwStartAddress + 1]);

				//Handling for garbage instruction.
				if(B1==0xC1 && (B2>=0xF0 && B2<=0xF7))
				{
					dwStartAddress+= 0x03;
					continue;
				}
				if((B1 == 0xD0 || B1 == 0xD1 || B1 == 0xD2) && (B2 >= 0xF0 && B2 <= 0xF7))
				{
					dwStartAddress+= 0x02;
					continue;
				}
				
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwStartAddress], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > m_dwNoOfBytes - dwStartAddress)
				{
					return iRetStatus;
				}
				dwInstructionCnt++;
				dwStartAddress += dwLength;

				if(B1 == 0xE8 && dwValue == 0 && dwLength == 5 && strstr(da.result, "CALL"))
				{
					dwValue++;
				}
				else if(B1 == 0xFF && dwValue == 1 && dwLength == 6 && strstr(da.result, "+AC]")) 
				{
					dwValue++;
				}
				else if(B1 == 0xFF && dwValue == 1 && dwLength == 7 && strstr(da.result, "+A0]")) 
				{
					dwValue++;
				}				
				else if(B1 == 0xFF && dwValue == 1 && dwLength == 4 && strstr(da.result, "-17]"))
				{
					dwValue++;
				}
				else if(B1 == 0x75 && dwValue == 2 && dwLength == 2 && strstr(da.result, "JNZ SHORT"))
				{
					dwValue++;
				}
				else if(B1 == 0xB9 && dwValue == 3 && dwLength == 5 && strstr(da.result, "MOV ECX,"))
				{
					dwValue++;
					dwValue++;
				}
				/*else if(B1 == 0x64 && dwValue == 4 && dwLength == 7 && (strstr(da.result, "MOV FS:[") && strstr(da.result, ",ESP")))
				{
					dwValue++;
				}*/
				else if(B1 == 0x64 && dwValue == 5 && dwLength == 7 && (strstr(da.result, "POP DWORD PTR FS:[0]")))
				{
					dwValue++;
				}				
				else if(B1 == 0xC9 && dwValue == 6 && dwLength == 1 && strstr(da.result, "LEAVE"))
				{
					dwValue++;
				}				
				else if(B1 == 0xFF && dwValue == 7 && dwLength == 2 && strstr(da.result, "JMP EAX"))
				{
					iRetStatus = VIRUS_FILE_DELETE;
					break;
				}
				else if(B1 == 0x50 && B2 == 0xC3 && dwValue == 7 && dwLength == 1 && strstr(da.result, "PUSH EAX"))
				{
					iRetStatus = VIRUS_FILE_DELETE;
					break;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectCrypto
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Crypto
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectCrypto()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 && (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x80000000) ==  0x80000000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[CRYPTO_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(NULL == m_pbyBuff)
		{
			return iRetStatus;
		}

		memset(m_pbyBuff, 0, CRYPTO_BUFF_SIZE + MAX_INSTRUCTION_LEN);
		if(GetBuffer(m_dwAEPMapped, CRYPTO_BUFF_SIZE, CRYPTO_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwInstCount = 0, dwWeight = 0, dwOffset = 0;
			char cReqReg[4] ={0}, cReqReg1[10] = "ROR ", cReqReg2[10] = "NOT ";

			BYTE bFlag = false;
			t_disasm da ={0x00};

			while(dwOffset < m_dwNoOfBytes)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE );
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}

				if(dwLength == 5 && bFlag == false)
				{
					if(strstr(da.result, "MOV EAX"))		strcpy_s(cReqReg,4,"EAX");
					else if(strstr(da.result, "MOV EBX"))	strcpy_s(cReqReg,4,"EBX");
					else if(strstr(da.result, "MOV ECX"))	strcpy_s(cReqReg,4,"ECX");
					else if(strstr(da.result, "MOV EDX"))	strcpy_s(cReqReg,4,"EDX");
					else if(strstr(da.result, "MOV ESI"))	strcpy_s(cReqReg,4,"ESI");
					else if(strstr(da.result, "MOV EDI"))	strcpy_s(cReqReg,4,"EDI");
					else if(strstr(da.result, "MOV EBP"))	strcpy_s(cReqReg,4,"EBP");

					if(cReqReg[0] == 0x45)
					{
						dwWeight++;
						strcat_s(cReqReg1,10,cReqReg);
						strcat_s(cReqReg2,10,cReqReg);

					}				
				}		
				else if((dwWeight == 1) && (dwLength == 2 || dwLength == 3) && ((strstr(da.result, cReqReg1)) || (strstr(da.result, cReqReg2))))
				{
					bFlag = true;
					dwWeight++;
				}
				else if(dwWeight == 2 && dwLength == 1 && strstr(da.result, "INC"))
				{
					dwWeight++;
				}
				else if(dwWeight == 3 && dwLength == 2 && strstr(da.result, "MOV"))
				{
					dwWeight++;
				}
				else if(dwWeight == 4 && dwLength == 2 && strstr(da.result, "ROL"))
				{
					dwWeight++;
				}
				else if(dwWeight == 5 && dwLength == 6 && strstr(da.result, "XOR") && da.immconst == 0xACD78FA3)
				{
					dwWeight++;
				}
				else if(dwWeight == 6 && dwLength == 2 && strstr(da.result, "CMP"))
				{
					dwWeight++;
				}
				else if(dwWeight == 7 && dwLength == 6 && strstr(da.result, "JNZ") && da.jmpconst== 0x003FFFF3)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Crypto"));		
					return VIRUS_FILE_DELETE;
				}		
				dwOffset += dwLength;	
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPECorrupt
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Currupt PE File
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectPECorrupt(void)
{
	for(WORD i = 0; m_wNoOfSections > 0 && i < m_wNoOfSections - 1; i++)
	{	
		if(NEGATIVE_JUMP(m_pSectionHeader[i].SizeOfRawData))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.PECorrupt"));		
			return VIRUS_FILE_DELETE;			
		}
	}	
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectCivut
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Civut.A
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectCivut()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if ((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".MSA", 4) == 0) && 
	   ((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000020) == 0xE0000020) &&
		 m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x1000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int CIVUT_BUFF_SIZE = 0x55;
		m_pbyBuff = new BYTE[CIVUT_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}	
		memset(m_pbyBuff, 0, CIVUT_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, CIVUT_BUFF_SIZE, CIVUT_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwOffset = 0;
			int iStg = 0;
			t_disasm da;
			m_dwInstCount = 0;
			
			while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 40)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				m_dwInstCount++;

				if(dwLength == 0x01 && strstr(da.result, "PUSHAD") && iStg == 0)
				{
					iStg++;
				}
				if(dwLength == 0x05 && strstr(da.result, "CALL ") && iStg == 1)
				{
					iStg++;
				}
				if(dwLength == 0x01 && strstr(da.result, "POP ") && iStg == 2)
				{
					iStg++;
				}
				if(dwLength == 0x03 && strstr(da.result, "XOR ") && (iStg == 3 || iStg == 5 || iStg == 7 || iStg == 9))
				{
					iStg++;
				}
				if(dwLength == 0x01 && strstr(da.result, "INC ") && (iStg == 4 || iStg == 6 || iStg == 8 || iStg == 10))
				{
					if(iStg == 10)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Civut.A"));
						return VIRUS_FILE_DELETE;
					}
					iStg++;
				}
				dwOffset += dwLength; 
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectLom
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR 
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.LOM
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectLom()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.CheckSum == 0x026600 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0 &&
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x80000000) == 0x80000000) &&
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x27000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int LOM_BUFF_SIZE = 0x32;
		m_pbyBuff = new BYTE[LOM_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}	
		memset(m_pbyBuff, 0, LOM_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, LOM_BUFF_SIZE, LOM_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwOffset = 0, dwVirusStartOffset = 0;
			int iStg = 0;
			t_disasm da;
			m_dwInstCount = 0;
			
			while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 8)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				m_dwInstCount++;

				if(dwLength == 0x05 && strstr(da.result, "MOV") && iStg == 0)
				{
					dwVirusStartOffset = da.immconst - m_dwImageBase;
					iStg++;
				}
				else if(dwLength == 0x02 && strstr(da.result, "XOR") && iStg == 1)
				{
					iStg++;
				}
				else if(dwLength == 0x02 && strstr(da.result, "XCHG") && iStg == 2)
				{
					iStg++;
				}
				else if(dwLength == 0x02 && strstr(da.result, "ADD") && iStg == 3)
				{
					iStg++;
				}
				else if(dwLength == 0x02 && strstr(da.result, "CALL") && iStg == 4)
				{
					iStg++;
				}
				else if(dwLength == 0x05 && strstr(da.result, "JMP") && iStg == 5)
				{
					DWORD dwOriAEP = *(DWORD *)&m_pbyBuff[dwOffset + 1] + m_dwAEPUnmapped + dwOffset + 0x05;
					if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwOriAEP, &dwOriAEP))
					{
						if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusStartOffset, &dwVirusStartOffset))
						{
							if(GetBuffer(dwVirusStartOffset, LOM_BUFF_SIZE, LOM_BUFF_SIZE))
							{
								const BYTE bySignature[] = {0x00, 0x00, 0xE8, 0xD5, 0x02, 0x00, 0x00, 0xE9, 0x04, 0x03, 0x00, 0x00};
								if(memcmp(&m_pbyBuff[0x00], bySignature, sizeof(bySignature)) == 0)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.LOM"));
									return VIRUS_FILE_DELETE;
								}
							}
						}
					}
				}
				dwOffset += dwLength;
			}
		}
	}	
	//For dropped samples after unpacking (ASPack)
	else if (m_pMaxPEFile->m_stPEHeader.CheckSum == 0x026600 && m_dwAEPUnmapped == 0x1000 && 
		m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x4F000 && 
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x1000 || 
		m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x0))
	{
		const BYTE byLomSig[] = {0xA1, 0x70, 0x02, 0x45, 0x00, 0xC1, 0xE0, 0x02, 0xA3, 0x74, 0x02, 0x45,
			0x00, 0x57, 0x51, 0x33, 0xC0, 0xBF, 0x94, 0xBF, 0x45, 0x00, 0xB9, 0x70, 0x01, 0x46, 0x00,
			0x3B, 0xCF, 0x76, 0x05, 0x2B, 0xCF, 0xFC, 0xF3, 0xAA, 0x59};

		BYTE byBuff[sizeof(byLomSig)] = {0};
		if(m_pMaxPEFile->ReadBuffer(byBuff, m_dwAEPMapped, sizeof(byLomSig), sizeof(byLomSig)))
		{
			if(memcmp(byBuff, byLomSig, sizeof(byLomSig)) == 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.LOM"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectMental
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Mental.Gen
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectMental(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if( m_dwAEPUnmapped == m_pSectionHeader[0].VirtualAddress && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x3000 &&
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL &&
		(m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000020) == 0xE0000020)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int MENTAL_BUFF_SIZE = 0x70;
		m_pbyBuff = new BYTE[MENTAL_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}	
		memset(m_pbyBuff, 0, MENTAL_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, MENTAL_BUFF_SIZE, MENTAL_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwOffset = 0;
			t_disasm da;
			m_dwInstCount = 0;
			bool bPushFound = false;
			
			while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 0x25)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				m_dwInstCount++;
				if(dwLength == 0x05 && strstr(da.result, "PUSH"))
				{
					if((*(DWORD *)&m_pbyBuff[dwOffset + 1]) - m_dwImageBase == m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
					{
						bPushFound = true;
					}
				}
				else if(dwLength == 0x05 && strstr(da.result, "MOV"))
				{
					if((*(DWORD *)&m_pbyBuff[dwOffset + 1]) - m_dwImageBase == m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
					{
						bPushFound = true;
					}
				}
				else if(dwLength == 0x06 && strstr(da.result, "LEA"))
				{
					if((*(DWORD *)&m_pbyBuff[dwOffset + 2]) - m_dwImageBase == m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress ||
						(*(DWORD *)&m_pbyBuff[dwOffset + 2]) == 0x000009C5)
					{
						bPushFound = true;
					}
				}

				else if(bPushFound && dwLength == 0x05 && strstr(da.result, "JMP")) 
				{
					if((*(DWORD *)&m_pbyBuff[dwOffset + 1] + 0x05 + m_dwAEPUnmapped + dwOffset) == m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Mental.Gen"));
						return VIRUS_FILE_DELETE;
					}
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectBayan
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Bayan Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectBayan()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xE0000000) == 0xE0000000 && m_wAEPSec != m_wNoOfSections - 1)
	{
		WORD	wSigByte = 0;
		if(!(m_pMaxPEFile->ReadBuffer(&wSigByte, 0x38, 2, 2)) || wSigByte != 0x6E66)
		{
			return iRetStatus;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(m_pbyBuff == NULL)
		{
			return iRetStatus;
		}
		DWORD		dwReadOffset = m_dwAEPMapped;
		DWORD		dwReadRVA = m_dwAEPUnmapped;
		int			iCount  = 0;
		BYTE		bySig[] = {0xEB, 0x01, 0x83, 0xE9};

		DWORD	dwIndex = 0;
		do
		{
			memset(m_pbyBuff, 0x00, BUFF_SIZE);
			if(!GetBuffer(dwReadOffset, BUFF_SIZE, 5))
			{
				return iRetStatus;
			}
			for(dwIndex = 0; dwIndex < m_dwNoOfBytes - 5; dwIndex++)
			{
				if(0 == memcmp(&m_pbyBuff[dwIndex], bySig, sizeof(bySig)))
				{
					dwReadRVA = *((DWORD*)&m_pbyBuff[dwIndex + 4]) + dwReadRVA + dwIndex + sizeof(bySig) + 4;
					if(m_wAEPSec == m_pMaxPEFile->Rva2FileOffset(dwReadRVA,&dwReadOffset))
					{
						iCount++;
						break;
					}
				}
				else if(m_pbyBuff[dwIndex] == 0xE9)
				{
					DWORD	dwTemp = *((DWORD*)&m_pbyBuff[dwIndex + 1]) + dwReadRVA + dwIndex + 5;
					if((m_wNoOfSections - 1) == m_pMaxPEFile->Rva2FileOffset(dwTemp,NULL))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Bayan.A"));
						return VIRUS_FILE_DELETE;
					}
				}
			}
		}while(dwIndex != m_dwNoOfBytes - 5);
	}
	else if(m_wNoOfSections == 2 && m_dwAEPUnmapped == m_pSectionHeader[1].VirtualAddress &&
			m_pSectionHeader[0].Characteristics == 0xE00000E0 && m_pSectionHeader[1].Characteristics == 0xE00000E0 )
	{
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress == 0 && m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress == 0)
		{
			BYTE byAEPByte[0x02] = {0};
			if(m_pMaxPEFile->ReadBuffer(byAEPByte, m_dwAEPMapped, 1, 1))
			{
				if(byAEPByte[0] == 0x60)
				{
					const BYTE byBasedSig[] = {0x3E, 0x01, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x64, 0x64, 0x72, 
											   0x65, 0x73, 0x73, 0x00, 0x00, 0xC2, 0x01, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69,
											   0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00, 0x00, 0x4B, 0x45, 0x52, 0x4E, 0x45,
											   0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C};
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}
					const int BUFF_SIZE = 0x250;
					m_pbyBuff = new BYTE [BUFF_SIZE];
					if(GetBuffer(m_pMaxPEFile->m_dwFileSize - BUFF_SIZE, BUFF_SIZE, BUFF_SIZE))
					{
						for (DWORD dwCnt = 0; dwCnt < BUFF_SIZE - sizeof(byBasedSig); dwCnt++)
						{
							if(memcmp(&m_pbyBuff[dwCnt], byBasedSig, sizeof(byBasedSig)) == 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Bayan.Based"));
								return VIRUS_FILE_DELETE;
							}
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAldebaran
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Aldebaran Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectAldebaran(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.MinorOSVersion == 0x3073 &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		(m_pSectionHeader[m_wAEPSec].Characteristics & 0x80000000) == 0x80000000)
	{
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = _DetectAldebaran();
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: _DetectAldebaran
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Aldebaran.8365.A
--------------------------------------------------------------------------------------*/
int CNonRepairable::_DetectAldebaran(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	CEmulate m_objEmulate(m_pMaxPEFile);
	if(!m_objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}

	m_objEmulate.SetBreakPoint("__isinstruction('sub word ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('add word ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('rol word ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('ror word ptr')");
	
	m_objEmulate.SetBreakPoint("__isinstruction('sub dword ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('xor dword ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('rol dword ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('ror dword ptr')");

	m_objEmulate.SetBreakPoint("__isinstruction('sub byte ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('add byte ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('or byte ptr')");
	m_objEmulate.SetBreakPoint("__isinstruction('mov byte ptr')");
	
	m_objEmulate.SetNoOfIteration(250);

	char szInstruction[1024] = {0};                 
	while(1)
	{
		if(7 != m_objEmulate.EmulateFile()) 
		{
			return iRetStatus;
		}
		memset(szInstruction, 0, 1024);
		m_objEmulate.GetInstruction(szInstruction);  
		if(strstr(szInstruction, "[e"))
		{
			break;
		}
	}	

	DWORD dwDecEip = m_objEmulate.GetEip();
	if((m_objEmulate.GetMemoryOprand() - m_dwImageBase) < (m_pSectionHeader[m_wAEPSec].PointerToRawData + m_pSectionHeader[m_wAEPSec].SizeOfRawData)) 
	{			
		m_objEmulate.PauseBreakPoint(0);
		m_objEmulate.PauseBreakPoint(1);
		m_objEmulate.PauseBreakPoint(2);
		m_objEmulate.PauseBreakPoint(3);
		m_objEmulate.PauseBreakPoint(4);
		m_objEmulate.PauseBreakPoint(5);
		m_objEmulate.PauseBreakPoint(6);
		m_objEmulate.PauseBreakPoint(7);
		m_objEmulate.PauseBreakPoint(8);
		m_objEmulate.PauseBreakPoint(9);
		m_objEmulate.PauseBreakPoint(10);
		m_objEmulate.PauseBreakPoint(11);

		m_objEmulate.SetBreakPoint("__isinstruction('jmp')");

		m_objEmulate.SetNoOfIteration(200);
		DWORD dwJmpEip = 0, dwJmpOffset = 0;
		while(1)
		{
			int iRet = m_objEmulate.EmulateFile();
			if(7 != iRet)
			{
				if(0 == iRet)
				{
					return iRetStatus;
				}
				continue;
			}
			DWORD dwLen = m_objEmulate.GetInstructionLength();
			if(dwLen >= 5)
			{
				dwJmpOffset = m_objEmulate.GetJumpAddress();
				dwJmpEip = m_objEmulate.GetEip();
				if(dwJmpOffset < dwJmpEip)
				{
					break;
				}
			}
		}

		m_objEmulate.SetBreakPoint("__isinstruction('jz')");

		m_objEmulate.PauseBreakPoint(12);
		m_objEmulate.SetNoOfIteration(300);
		DWORD dwJEOffset = 0, dwJEEip = 0;
		while(1)
		{
			int iRet = m_objEmulate.EmulateFile();
			if(7 != iRet)
			{
				if(0 == iRet)
				{
					return iRetStatus;
				}
				continue;
			}
			else
			{
				dwJEOffset =  m_objEmulate.GetJumpAddress();
				dwJEEip    =  m_objEmulate.GetEip();
				if(dwJEOffset > dwJmpEip)
				{
					break;
				}
			}
		}

		if((dwJEEip < dwJmpEip || dwJEEip > dwDecEip) && 
			(dwJmpEip > dwDecEip || dwJEOffset > dwJmpEip)  && 
			dwDecEip > dwJmpOffset)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Aldebaran.8365.A"));
			iRetStatus = VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectBlaken
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Blakan Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectBlaken()
{	
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int BLAKAN_BUFF_SIZE = 0x3000;
	m_pbyBuff = new BYTE[BLAKAN_BUFF_SIZE];
	
	DWORD iBufferSize = 0;
	if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], (m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData - 0x1000), 0x1000, 0x1000))
	{
		iBufferSize += 0x1000;
	}
	if((m_pSectionHeader[m_wAEPSec + 1].SizeOfRawData+m_pSectionHeader[m_wAEPSec + 1].PointerToRawData - 0x1000) > 0x00)
	{
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], (m_pSectionHeader[m_wAEPSec + 1].SizeOfRawData + m_pSectionHeader[m_wAEPSec + 1].PointerToRawData - 0x1000), 0x1000, 0x1000))
		{
			iBufferSize += 0x1000;
		}
	}
	if((m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData+m_pSectionHeader[m_wAEPSec + 2].PointerToRawData - 0x1000) > 0x00)
	{
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[iBufferSize], (m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData + m_pSectionHeader[m_wAEPSec + 2].PointerToRawData - 0x1000), 0x1000, 0x1000))
		{
			iBufferSize += 0x1000;
		}
	}
	const TCHAR BLAK2016_SIG[] = _T("51696EF12F2E4B19697465D85C7920FA666163231B4A611B66*5C83A500646759FBFF8AD03D7404038EEBF7433B046639334D5A2CFE47EBAE86*62692B6F20731B636F6ED87B62652A5C6C6CD86165771D6E656EB83E");
	const TCHAR BLAK2020_SIG[] = _T("696E4F232E4B775C74654450206685602042824F636B36386163*418B6174727F4F2C20481E3033164B83ED1B5267A116EE8A18*692547FCF3BC4F75EB41DE2B7336BFEE4E64F1722425A50C30A3FA");
	const TCHAR BLAK2021_SIG[] = _T("4B88697465555D2066966D2042935C636B47456163922720419C6E74*6A6F044BBAE6F78B67FF65815F485A742A43EBF6B2533C8122FC0300*73638F6A6E20A85D657288676C208E6077659A606E006B702068886E74");
	const TCHAR BLAK2308_SIG[] = _T("2E4BD06A74658F5E7920B1686163DA1C4A61D267*3030A0FC5C835C02646710FDFF8A873F7408FF8C*617261DB682067D4736573D46A0044E41C6861E2");
	const TCHAR BLAK2309_SIG[] = _T("4B165D7465D5507920F75A6163200F4A61185A2C*636756EFFF8ACD317408457F90900082EBF3402F*547261215B20671A6665731A5D00442A0F686128");
	const TCHAR BLAK1_SIG[] = _T("4B785C746537507920595A6163820E4A617A592C205863*73748957612C3720303048EE5C8304F46367B8EEFF8A2F*6C2AC3448C0E62698A6220737A566F6E376F6265894F6C");
	const TCHAR BLAK2_SIG[] = _T("4B6265746521597920436361636C174A6164622C20426C*6367A2F7FF8A193A74044C8AEBF78C370466822F4D5A75*6269746B2073645F6F6E2178626573586C6C215E657766");
	const TCHAR BLAK3_SIG[] = _T("4B69607465285479204A5E616373124A616B5D2C204967*6367A9F2FF8A203574045385EBF793320466892A4D5A7C*89ED000408F272F20BCA813B583700007DDA8B5B80F5D78B7B");
	const TCHAR BLAK4_SIG[] = _T("2E4BD265746591597920B3636163DC174A61D4622C20B2*3030A2F75C835EFD636712F8FF8A893A7404BC8AEBF7FC*6F6E91786265E3586C6C915E6577D66A656E713B7520D958");
	const TCHAR BLAK5_SIG[] = _T("4BD904FB4BD94F6469122E29463A676F60F95A*741B1B655C5E4419455C3C64271B1A6E6E6F4B625C27F92A2B2B0AF9577EC6*795D604B5A6767F95F60723E6C6069D93C701B415A6E6FF95C6460F93A606D405E");
	const TCHAR BLAKAN2064_SIG[] = _T("4D7574792E6378005D83ED056467A100008B184374044B93*43616E20796F7520666F6C6C6F776D65*546F20696E66656374206F72206E6F7420746F20696E66656374*5765616B6E657373204156507300E95D020000427965212044657521204164696F732120536861796F6E61726121");

	TCHAR szVirusName[MAX_PATH] = {0};
	CSemiPolyDBScn polydbObj;

	polydbObj.LoadSigDBEx(BLAK2016_SIG, _T("Virus.Blakan.2016"), TRUE);
	polydbObj.LoadSigDBEx(BLAK2020_SIG, _T("Virus.Blakan.2020"), TRUE);
	polydbObj.LoadSigDBEx(BLAK2021_SIG, _T("Virus.Blakan.2020"), TRUE);
	polydbObj.LoadSigDBEx(BLAK2308_SIG, _T("Virus.Blakan.2308"), TRUE);
	polydbObj.LoadSigDBEx(BLAK2309_SIG, _T("Virus.Blakan.2308"), TRUE);
	polydbObj.LoadSigDBEx(BLAKAN2064_SIG, _T("Virus.Blakan.2064"), TRUE);
	polydbObj.LoadSigDBEx(BLAK1_SIG, _T("Virus.Blakan"), TRUE);
	polydbObj.LoadSigDBEx(BLAK2_SIG, _T("Virus.Blakan"), TRUE);
	polydbObj.LoadSigDBEx(BLAK3_SIG, _T("Virus.Blakan"), TRUE);
	polydbObj.LoadSigDBEx(BLAK4_SIG, _T("Virus.Blakan"), TRUE);
	polydbObj.LoadSigDBEx(BLAK5_SIG, _T("Virus.Blakan"), FALSE);

	if(polydbObj.ScanBuffer(&m_pbyBuff[0], BLAKAN_BUFF_SIZE, szVirusName) >= 0)
	{
		if(_tcslen(szVirusName) > 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectLegacy
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Legacy Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectLegacy()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pSectionHeader[m_wAEPSec].Characteristics & 0x80000000) == 0x80000000) &&
	   ((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x80000020) == 0x80000020) &&
	   m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x4000 && m_wAEPSec != m_wNoOfSections -1)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[LEGACY_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}	
		memset(m_pbyBuff, 0, LEGACY_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped, LEGACY_BUFF_SIZE, LEGACY_BUFF_SIZE))
		{
			DWORD dwLength = 0, dwOffset = 0, dwJmp = 0;
			int iStg = 0;
			t_disasm da;
			m_dwInstCount = 0;
			
			while(dwOffset < m_dwNoOfBytes && m_dwInstCount <= 70)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (m_dwNoOfBytes - dwOffset))
				{
					break;
				}
				m_dwInstCount++;

				if(dwLength == 0x05 && strstr(da.result, "CALL") && iStg == 0)
				{
					if((*(DWORD *)&m_pbyBuff[dwOffset + 1]) < 0x90)
					{
						iStg++;
					}
				}
				//checks file in kernel mode or debugger
				else if((dwLength == 0x04 || dwLength == 0x03) && strstr(da.result, "MOV") && strstr(da.result, "+8]") && strstr(da.result, ",[E") && iStg == 1)
				{
					iStg++;
				}
				// jmp aep sec to last sec
				else if(dwLength == 0x05 && strstr(da.result, "JMP") && iStg == 2) 
				{
					dwJmp = *(DWORD *)&m_pbyBuff[dwOffset + 1] + 0x05 + m_dwAEPUnmapped + dwOffset;
					if(dwJmp >= m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress)
					{
						if(GetLegacyParam(dwJmp))
						{
							iStg++;
						}
					}
				}
				//check antidebugging
				else if(strstr(da.result, "FS:[") && iStg == 3) 
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Legacy"));
					return VIRUS_FILE_DELETE;
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: GetLegacyParam
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Legacy Family
--------------------------------------------------------------------------------------*/
bool CNonRepairable::GetLegacyParam(DWORD dwJmp)
{
	BYTE *byBuffer = new BYTE[LEGACY_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!byBuffer)
	{
		return false;
	}
	memset(byBuffer, 0, LEGACY_BUFF_SIZE + MAX_INSTRUCTION_LEN);
	if(m_pMaxPEFile->Rva2FileOffset(dwJmp, &dwJmp))
	{
		if(m_pMaxPEFile->ReadBuffer(byBuffer, dwJmp, LEGACY_BUFF_SIZE, LEGACY_BUFF_SIZE))
		{
			DWORD dwLength = 0x00, dwOffset = 0x00, dwInstCount = 0x00;
			t_disasm da;
			while(dwOffset < LEGACY_BUFF_SIZE && dwInstCount < 35)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&byBuffer[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > (LEGACY_BUFF_SIZE - dwOffset))
				{
					break;
				}
				dwInstCount++;
				// checking CPU ID
				if(dwLength == 0x02 && strstr(da.result, "CPUID"))
				{
					if(byBuffer)
					{
						delete []byBuffer;
						byBuffer = NULL;
					}
					return true;						
				}
				dwOffset += dwLength;
			}
		}
	}
	if(byBuffer)
	{
		delete []byBuffer;
		byBuffer = NULL;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectGolem
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Golem
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectGolem()
{
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".tls", 4) == 0) &&
		((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000060) == 0xE0000060) &&
		m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress >= 5000)
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int GOLEM_BUFF_SIZE = 0x08;
		m_pbyBuff = new BYTE[GOLEM_BUFF_SIZE];

		DWORD dwSizeOptHeaOff = m_pMaxPEFile->m_stPEHeader.e_lfanew + + sizeof(IMAGE_FILE_HEADER);
		if(GetBuffer(dwSizeOptHeaOff, 0x02, 0x02))
		{
			dwSizeOptHeaOff = dwSizeOptHeaOff + 0x04 + *(WORD *)&m_pbyBuff[0] - 0x08;
			if(GetBuffer(dwSizeOptHeaOff, 0x04, 0x04))
			{
				if(*(DWORD *)&m_pbyBuff[0] == 0x04E54524D)
				{
					if(GetBuffer(m_dwAEPMapped, GOLEM_BUFF_SIZE, GOLEM_BUFF_SIZE))
					{
						const BYTE bySignature[] = {0x60, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00};
						if(!memcmp(&m_pbyBuff[0], bySignature, sizeof(bySignature)))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Golem"));
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectFunloveDam
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.FunLove (Corrupt Files)
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectFunloveDam()
{	
	if((m_pMaxPEFile->m_stPEHeader.Characteristics == 0x010E) && (m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x1) && 
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0xC0000020) ==  0xC0000020) &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".code", 5) == 0))		
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int FUNLOVE_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[FUNLOVE_BUFF_SIZE];

		DWORD dwBufferSize = 0;
		if(GetBuffer(0x50, 0x14, 0x14))
		{
			dwBufferSize += 0x14;
		}
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBufferSize], 0x6C2, 0x16, 0x16))
		{
			dwBufferSize += 0x16;
		}
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBufferSize], 0xBC4, 0x8F, 0x8F))
		{
			dwBufferSize += 0x8F;
		}

		const TCHAR FUNLOVE_SIG[] = _T("46756E204C6F76696E67*4372696D696E616C"); //FunLoving criminal
		const TCHAR FUNLOVE_SIG1[] = _T("446F6E6B65796F5661*6363696E6569457261736572"); //DonkeyoVaccineiEraser added by shreyas
		const TCHAR FUNLOVE_SIG2[] = _T("51514E544C4452003B4658*74073B4658EB073B475874073B4758*0757494E4E545C53797374656D33325C6E746F736B726E6C2E657865");

		TCHAR szVirusName[MAX_PATH] = {0};
		CSemiPolyDBScn polydbObj;

		polydbObj.LoadSigDBEx(FUNLOVE_SIG, _T("Virus.FunLove.Dam"), TRUE);
		polydbObj.LoadSigDBEx(FUNLOVE_SIG1, _T("Virus.FunLove.Dam"), TRUE);
		polydbObj.LoadSigDBEx(FUNLOVE_SIG2, _T("Virus.FunLove.Dam"), FALSE);		

		if(polydbObj.ScanBuffer(&m_pbyBuff[0], FUNLOVE_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}		
	}
	else if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && ((m_pMaxPEFile->m_dwFileSize % m_pMaxPEFile->m_stPEHeader.FileAlignment) == 3))
	{
		if((m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)) < 0x1000)
		{
			return VIRUS_NOT_FOUND;
		}
		DWORD dwOffset = 0;
		dwOffset = m_pMaxPEFile->m_dwFileSize - (m_pMaxPEFile->m_dwFileSize % m_pMaxPEFile->m_stPEHeader.FileAlignment) - 0xE00;
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int FUNLOVE_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[FUNLOVE_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			 return VIRUS_NOT_FOUND;
		}
		memset(m_pbyBuff,0x00,FUNLOVE_BUFF_SIZE);
		if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x00],dwOffset,0x10,0x10))
		{
			if(*(DWORD *)&m_pbyBuff[0x00] != 0x8AAE8)
			{
				return VIRUS_NOT_FOUND;
			}
			if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x10],dwOffset + 0x9A0,0xD0,0xD0))
			{
				const TCHAR FUNLOVE_SIG[] = _T("E8AA0800008DB3A70B00008B3C2483*073B4758EB0757494E4E545C53797374656D33325C6E746F736B726E6C2E657865*000C6F9400666C6373732E65786500464C43");

				TCHAR szVirusName[MAX_PATH] = {0};
				CSemiPolyDBScn polydbObj;

				polydbObj.LoadSigDBEx(FUNLOVE_SIG, _T("Virus.FunLove.Dam"), FALSE);
				if(polydbObj.ScanBuffer(&m_pbyBuff[0], FUNLOVE_BUFF_SIZE, szVirusName) >= 0)
				{
					if(_tcslen(szVirusName) > 0)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
						return VIRUS_FILE_DELETE;
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectKaze
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Kaze.4236
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectKaze()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const int KAZE_BUFF_SIZE = 0x100;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL))
	{
		return iRetStatus;
	}
	WORD wCheckKaze = 0;
	m_pMaxPEFile->ReadBuffer(&wCheckKaze, 0x24, 2, 2);
	if(wCheckKaze != 0x4142)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[KAZE_BUFF_SIZE + MAX_INSTRUCTION_LEN];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}		
	memset(m_pbyBuff, 0, KAZE_BUFF_SIZE + MAX_INSTRUCTION_LEN);

	if(GetBuffer(m_dwAEPUnmapped, KAZE_BUFF_SIZE, KAZE_BUFF_SIZE))
	{
		DWORD dwLength = 0, dwOffset = 0, dwVirusStartOff = 0, dwKey = 0;
		t_disasm da;
		m_dwInstCount = 0;
					
		while(dwOffset < m_dwNoOfBytes)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > (m_dwNoOfBytes - dwOffset))
			{
				break;
			}
			if(m_pbyBuff[dwOffset] == 0xE8  && dwLength == 0x05 && strstr(da.result, "CALL") && m_dwInstCount == 0)
			{
				if(*(DWORD *)&m_pbyBuff[dwOffset + 1] == 0)
				{
					dwVirusStartOff = m_dwAEPUnmapped + dwOffset + 5;
					m_dwInstCount++;
				}
			}
			else if(m_pbyBuff[dwOffset] == 0x81  && dwLength == 0x06 && strstr(da.result, "SUB EDI") && m_dwInstCount == 1)   // changes done here
			{
				dwVirusStartOff -= *(DWORD *)&m_pbyBuff[dwOffset + 2];
				m_dwInstCount++;
			}
			else if(m_pbyBuff[dwOffset] == 0xc7  && dwLength == 0x06 && strstr(da.result, "MOV EAX,") && m_dwInstCount == 2)
			{
				dwKey = *(DWORD *)&m_pbyBuff[dwOffset + 2];
				m_dwInstCount++;
			}
			else if(m_pbyBuff[dwOffset] == 0xc7  && dwLength == 0x06 && strstr(da.result, "MOV ECX,") && m_dwInstCount == 3)
			{
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusStartOff, &dwVirusStartOff))
				{
					if(GetBuffer(dwVirusStartOff, 0x30, 0x30))
					{
						for(int i = 0; i < 0x30; i += 4)
						{
							*(DWORD *)&m_pbyBuff[i] ^= dwKey;
						}
						const BYTE KAZE_SIG[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED, 0x05, 0x10, 0x40, 0x00, 0xE8, 0x93, 0x0A, 0x00, 
							0x00, 0x8B, 0x44, 0x24, 0x20, 0xE8, 0x69, 0x0A, 0x00, 0x00, 0x89, 0x85, 0x7D, 0x12, 0x40, 0x00, 
							0x8D, 0xB5, 0x81, 0x12, 0x40, 0x00, 0x8D, 0xBD, 0xC9, 0x12, 0x40, 0x00, 0x89, 0xC3, 0xAD, 0x85};
					
						if(memcmp(m_pbyBuff, KAZE_SIG, 0x30) == 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Kaze.4236"));
							return VIRUS_FILE_DELETE;
						}
					}
				}
				break;
			}
			dwOffset += dwLength;
		}
	}		
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSankei
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Sankei Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectSankei(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if((m_wAEPSec == m_wNoOfSections - 1 || m_wAEPSec == m_wNoOfSections - 2) && 
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0xF0000060) == 0xF0000060) &&
		((m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size == 0x00000020) ||
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size == 0x00000022)) &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData > 0x1AC)
	{		
		BYTE bChk[0xE] = {0};
		if(m_pMaxPEFile->ReadBuffer(bChk, m_dwAEPMapped, 0xE, 0xE))
		{
			if(bChk[0] == 0xE8 && bChk[5] == 0x5D && (bChk[8] == 0x05 || bChk[8] == 0x03) && (bChk[9] == 0x10 ||
				bChk[9] == 0x00) && (bChk[0xC] == 0x8D || bChk[0xC] == 0xED) && (bChk[0xD] == 0xB5 || bChk[0xD] == 0x05))
			{
				DWORD dwKey = 0x0, dwBufferStart = 0;

				BYTE SANKEI_SIG[] = {0x57, 0x69, 0x6E, 0x39, 0x78, 0x2E, 0x53, 0x61, 0x6E, 0x6B, 0x65, 0x69,
					0x20, 0x63, 0x6F, 0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x6B, 0x61, 0x7A, 0x65};
				BYTE SANKEI_1455[] = {0x6B, 0x61, 0x7A, 0x65, 0x2F, 0x46, 0x41, 0x54, 0x00, 0x49, 0x6E, 0x66,
					0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x72, 0x65, 0x75, 0x73, 0x73, 0x69, 0x65};

				if (m_pbyBuff)
				{
					delete []m_pbyBuff; 
					m_pbyBuff = NULL;
				}
				
				const int SANKEI_BUFF_SIZE = m_pSectionHeader[m_wAEPSec].SizeOfRawData - 0x1B4;
				m_pbyBuff = new BYTE[SANKEI_BUFF_SIZE];
				if(GetBuffer(m_dwAEPMapped + 0x1AC, SANKEI_BUFF_SIZE, SANKEI_BUFF_SIZE))						
				{
					if(memcmp(&m_pbyBuff[0x56C], SANKEI_SIG, sizeof(SANKEI_SIG)) == 0x00)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.3001"));
						return VIRUS_FILE_DELETE; 
					}
					else if((m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size == 0x00000020) && memcmp(m_pSectionHeader[m_wAEPSec].Name, "kaze/FAT", 8) == 0
						&& m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x657a616b)
					{
						BYTE bKey = 0x0;
						m_pMaxPEFile->ReadBuffer(&bKey, m_dwAEPMapped + 0x25, sizeof(BYTE), sizeof(BYTE));
						dwBufferStart = 0x3D;
						for(DWORD j = dwBufferStart ; j <= dwBufferStart + 0x38; j++)
						{
							m_pbyBuff[j] ^= bKey;
						}
						if(OffSetBasedSignature(SANKEI_SIG, sizeof(SANKEI_SIG), NULL)|| OffSetBasedSignature(SANKEI_1455, sizeof(SANKEI_1455), NULL))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.1493")); //Sankei.1493 & Keisan.B
							return VIRUS_FILE_DELETE; 
						}
					}
					else if((m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size == 0x00000020))
					{											
						if((*((DWORD*)&m_pbyBuff[0x324]) ^ *((DWORD*)&m_pbyBuff[0x6D0]))==0x6E695700)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.3418"));
							dwKey =*((DWORD*)&m_pbyBuff[0x324]);
							dwBufferStart = 0x6D0;
						}
						else if((*((DWORD*)&m_pbyBuff[0x37C]) ^ *((DWORD*)&m_pbyBuff[0x72C]))==0x6E695700)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.3510"));
							dwKey =*((DWORD*)&m_pbyBuff[0x37C]);
							dwBufferStart = 0x72C;
						}
						else if((*((DWORD*)&m_pbyBuff[0x388]) ^ *((DWORD*)&m_pbyBuff[0x738]))==0x396E6957)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.3580"));
							dwKey =*((DWORD*)&m_pbyBuff[0x388]);
							dwBufferStart = 0x738;
						}
						else if((*((DWORD*)&m_pbyBuff[0x380]) ^ *((DWORD*)&m_pbyBuff[0x730]))==0x6E695700)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.3514"));
							dwKey =*((DWORD*)&m_pbyBuff[0x380]);
							dwBufferStart = 0x730;
						}
					}
					else if((m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size == 0x00000022))
					{
						if(memcmp(m_pSectionHeader[m_wAEPSec].Name, "kaze/FAT", 8) == 0) 
						{
							if((*((DWORD*)&m_pbyBuff[0x2E4]) ^*((DWORD*)&m_pbyBuff[0x0C])) == 0x2F657A61)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.1455"));
								dwKey =*((DWORD*)&m_pbyBuff[0x2E4]);
								dwBufferStart = 0x08;
							}
							else if((*((DWORD*)&m_pbyBuff[0x3D4]) ^*((DWORD*)&m_pbyBuff[0x00])) == 0x616B0065) 
						    {
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.1409"));
								dwKey =*((DWORD*)&m_pbyBuff[0x3D4]);
								dwBufferStart = 0x00;
						    }
						}
						else if((*((DWORD*)&m_pbyBuff[0x37C]) ^*((DWORD*)&m_pbyBuff[0x734])) == 0x6957002E)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.358"));
							dwKey =*((DWORD*)&m_pbyBuff[0x37C]);
							dwBufferStart = 0x734;
						}
						
						else if((*((DWORD*)&m_pbyBuff[0x344]) ^*((DWORD*)&m_pbyBuff[0x6FC])) == 0x57002E2E)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Sankei.3464"));
							dwKey =*((DWORD*)&m_pbyBuff[0x344]);
							dwBufferStart = 0x6FC;
						}
					}
						
				}
				for(DWORD j = dwBufferStart ; j <= dwBufferStart + 0x1F; j += 4)
				{
					*((DWORD*)&m_pbyBuff[j]) ^=	dwKey;
				}
				if(OffSetBasedSignature(SANKEI_SIG, sizeof(SANKEI_SIG), NULL)|| OffSetBasedSignature(SANKEI_1455, sizeof(SANKEI_1455), NULL))
				{
					return VIRUS_FILE_DELETE; 
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectEnerlam
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Enerlam Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectEnerlam()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec != m_wNoOfSections - 1 && 
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0x80000000) == 0x80000000) || ((m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000040) == 0xE0000040) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress >= m_pSectionHeader[m_wAEPSec].SizeOfRawData) &&
		(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size == 0x0000005F))
	{
		DWORD dwImportTable = 0;
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress, &dwImportTable))
		{
			return iRetStatus;
		}
		const BYTE ENERLAM_SIG[] = {0x4B,0x45,0x52,0x4E,0x45,0x4C,0x33,0x32,0x2E,0x64,0x6C,0x6C,
			0x00,0x00,0x4C,0x6F,0x61,0x64,0x4C,0x69,0x62,0x72,0x61,0x72,0x79,0x41,0x00,
			0x00,0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0x64,0x64,0x72,0x65,0x73,0x73};
		
		if (m_pbyBuff)
		{
			delete []m_pbyBuff; 
			m_pbyBuff = NULL;
		}		
		DWORD dwChunk = 0x1000;
		m_pbyBuff = new BYTE[dwChunk];

		if(!GetBuffer(dwImportTable + 0x34, sizeof(ENERLAM_SIG), sizeof(ENERLAM_SIG)))	
		{
			return iRetStatus;
		}
		if(memcmp(&m_pbyBuff[0], ENERLAM_SIG , sizeof(ENERLAM_SIG)) == 0x00)
		{
			DWORD dwSearchEndAddress = m_pSectionHeader[m_wAEPSec].SizeOfRawData + m_pSectionHeader[m_wAEPSec].PointerToRawData, dwSearchStartAddress = m_dwAEPMapped;
			while(dwSearchStartAddress < dwSearchEndAddress)
			{
				if((dwSearchEndAddress - dwSearchStartAddress) < dwChunk)
				{
					dwChunk = dwSearchEndAddress - dwSearchStartAddress;
				}
				if(!GetBuffer(dwSearchStartAddress, dwChunk, dwChunk))
				{
					return iRetStatus;
				}
				DWORD  dwCallOff = 0, dwCallValue = 0;
				for(DWORD dwIndex = 0; dwIndex <= dwChunk; dwIndex++)
				{ 
					BYTE bCallChk[] = {0xFF ,0x15};
					if(memcmp(&m_pbyBuff[dwIndex], bCallChk, sizeof(bCallChk)) == 0)
					{								
						m_pMaxPEFile->Rva2FileOffset((*(DWORD *)&m_pbyBuff[dwIndex + 0x2] - m_dwImageBase), &dwCallValue);
						if(dwCallValue != 0)
						{
							if(!m_pMaxPEFile->ReadBuffer(&dwCallOff, dwCallValue, 0x4))
							{
								return iRetStatus;
							}
							m_pMaxPEFile->Rva2FileOffset(dwCallOff - m_dwImageBase, &dwCallOff);
							if(dwCallOff <= m_pMaxPEFile->m_dwFileSize)
							{
								if(!GetBuffer(dwCallOff, 0x10, 0x10))
								{
									return iRetStatus;
								}
								if(m_pbyBuff[0]== 0x68 && m_pbyBuff[5]== 0xE9)
								{
									DWORD dwVirusStartOff = ((*(DWORD *)&m_pbyBuff[6]) + dwCallOff + m_dwImageBase + 0xA);
									if(!GetBuffer(dwVirusStartOff - m_dwImageBase, 0x100, 0x100))
									{
										return iRetStatus;
									}
									DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0;
									t_disasm	da;
									while(dwOffset < m_dwNoOfBytes)
									{
										dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
										if(dwLength > m_dwNoOfBytes - dwOffset)
										{
											break;
										}
										if(dwLength == 1 && dwInstructionCnt == 0 && strstr(da.result, "PUSHAD"))
										{
											dwInstructionCnt++;
										}
										else if(dwLength == 1 && dwInstructionCnt == 1 && strstr(da.result, "PUSHFD"))
										{
											dwInstructionCnt++;
										}
										else if(dwLength == 5 && dwInstructionCnt == 2 && strstr(da.result, "MOV EDI")|| strstr(da.result, "MOV ESI"))
										{
											dwInstructionCnt++;
										}
										else if(dwLength == 5 && dwInstructionCnt == 3 && (strstr(da.result, "MOV E")&& strstr(da.result, "1870")))
										{
											dwInstructionCnt++;
										}
										else if(dwLength == 1 && dwInstructionCnt == 4 && strstr(da.result, "PUSH E"))
										{
											dwInstructionCnt++;
										}
										else if(dwLength == 1 && dwInstructionCnt == 5 && strstr(da.result, "POP E"))
										{
											_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Enerlam"));
											return VIRUS_FILE_DELETE;

										}
										dwOffset += dwLength;
									}
								}
							}
						}
						return iRetStatus;
					}
				}
				dwSearchStartAddress +=dwChunk;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTick
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Tick Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectTick()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) && m_wAEPSec == 0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int TICK_BUFF_SIZE = 0xA00;
		m_pbyBuff = new BYTE[TICK_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, TICK_BUFF_SIZE, TICK_BUFF_SIZE))
		{			
			if(m_pbyBuff[0]== 0x60 && m_pbyBuff[1] == 0xE9)
			{
				const BYTE TickSig[] = {0x54,0x68,0x75,0x6E,0x64,0x65,0x72,0x50,0x69,0x63,0x6B,0x20,0x56};
				DWORD dwOffset = *(DWORD *)&m_pbyBuff[2];

				if((dwOffset + 0x75 < TICK_BUFF_SIZE - sizeof(TickSig) && memcmp(&m_pbyBuff[dwOffset + 0x75], TickSig, sizeof(TickSig)) == 0) ||
					(dwOffset + 0x7C < TICK_BUFF_SIZE - sizeof(TickSig) && memcmp(&m_pbyBuff[dwOffset + 0x7C], TickSig, sizeof(TickSig)) == 0))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Tick"));
					return VIRUS_FILE_DELETE;					
				}

				DWORD dwLength = 0, dwMatchedInstr = 0 ,dwMemOps = 0;
				t_disasm da;

				dwOffset += 0x6;
				while(dwOffset < 0x500 && dwMatchedInstr <= 0xA)
				{
					memset(&da, 0x00, sizeof(struct t_disasm));
					dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
					if(dwLength == 5 && dwMatchedInstr == 0 && strstr(da.result,"MOV E"))
					{
						dwMatchedInstr++;							
					}
					else if(dwLength == 5 && dwMatchedInstr == 2 && strstr(da.result,"MOV E"))
					{
						dwMatchedInstr++;
						if(m_pbyBuff[dwOffset + dwLength] != 0xE9)
						{
							return iRetStatus;
						}
					}
					else if(dwLength ==5 && strstr(da.result,"JMP"))
					{
						dwMatchedInstr++;
						dwOffset = *(DWORD *)&m_pbyBuff[dwOffset+1] + dwOffset ;
					}
					else if(dwLength == 6 && dwMatchedInstr == 6 && (strstr(da.result,"SUB E") || strstr(da.result,"XOR E")))
					{
						dwMemOps++;
						dwMatchedInstr++;
						if(m_pbyBuff[dwOffset + dwLength] != 0xE9)
						{
							return iRetStatus;
						}
					}						
					else if(dwLength == 2 && dwMatchedInstr == 8 && dwMemOps == 1 && (strstr(da.result,"SUB E") || strstr(da.result,"XOR E")))
					{
						dwMemOps++;
						dwMatchedInstr++;
						if(m_pbyBuff[dwOffset + dwLength] != 0xE9)
						{
							return iRetStatus;
						}
					}
					else if(dwLength == 6 && dwMatchedInstr == 10 && dwMemOps == 2 &&(strstr(da.result,"SUB E") || strstr(da.result,"XOR E")))
					{
						dwMatchedInstr++;
						if(m_pbyBuff[dwOffset + dwLength] != 0xE9)
						{
							return iRetStatus;
						}
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Tick"));
						return VIRUS_FILE_DELETE;
					}	
					dwOffset += dwLength;
				}			
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
Analyst     : Satish, Prashant 
Type        : Virus
Name        : Virus.Tolone
Description : Change 
                - Get virus start offset.
				- patch in  AEP section only one call that point to virus start.
-------------------------------------------------------------------------------------*/
int CNonRepairable::DetectTolone()
{
	int		iRetStatus = VIRUS_NOT_FOUND;	

	if (m_pSectionHeader[0].Characteristics == 0x60000020 && 
		m_wAEPSec == 0x00 && m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x3000 &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))  
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff  = NULL;
		}
		const int	BUFF_SIZE = 0xA00;
		m_pbyBuff = new BYTE[BUFF_SIZE];	
		
		DWORD	dwVirusStart = 0;
		if(GetPatchedCalls(m_dwAEPMapped,m_dwAEPMapped + 0x150,m_wAEPSec))	// Added by praShant
		{
			LPVOID lpPos = m_arrPatchedCallOffsets.GetHighest();
			while(lpPos)
			{
				m_arrPatchedCallOffsets.GetKey(lpPos, dwVirusStart);
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(dwVirusStart,&dwVirusStart))
				{
					if(GetBuffer(dwVirusStart, 0x02, 0x2))
					{
						if(m_pbyBuff[0x0] == 0x60 && m_pbyBuff[0x1] == 0x9C)
						{
							break;
						}
					}
				}

				lpPos = m_arrPatchedCallOffsets.GetHighestNext(lpPos);
			}
		}
		if(dwVirusStart > 0)
		{
			memset(m_pbyBuff, 0, BUFF_SIZE);
			if(!GetBuffer(dwVirusStart, BUFF_SIZE, BUFF_SIZE))
			{
				return iRetStatus;
			}
			
			DWORD		dwLength = 0, dwValidInstruction = 0, dwOffset = 0;
			t_disasm	da;
			while(dwOffset < m_dwNoOfBytes && m_dwInstCount < 0x20)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(dwLength > m_dwNoOfBytes - dwOffset)
				{
					break;
				}

				m_dwInstCount++;
				if(dwLength == 5 && (m_dwInstCount == 4 || m_dwInstCount == 3) && strstr(da.result, "CALL"))
				{
					DWORD dwCalledOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwLength + dwOffset;
					if(dwCalledOffset < m_dwNoOfBytes)
					{
						if(m_pbyBuff[dwCalledOffset] == 0x5A)
						{
							dwValidInstruction++;
						}
					}

				}
				else if(dwValidInstruction == 1 && dwLength == 3 && (strstr(da.result, "SUB ESP,24") || strstr(da.result, "ADD ESP,-24")))
				{
					dwValidInstruction++;
				}

				else if(dwValidInstruction == 2 && dwLength == 3 && (strstr(da.result, "SUB ESP,-C") || strstr(da.result, "ADD ESP,C")))
				{
					dwValidInstruction++;
				}

				else if(dwValidInstruction == 3 && dwLength == 6 && strstr(da.result, "JNZ"))
				{
					dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 2] + dwLength + dwOffset;
					if((dwOffset < 0x4000) && (dwOffset > 0x1000))//added by satish
					{
						if(GetBuffer((dwOffset + dwVirusStart),0x20,0x20))
						{
							dwOffset = 0;
						}
					}
					dwValidInstruction++;
					continue;
				}
				else if(dwValidInstruction == 3 && dwLength == 5 && strstr(da.result, "JMP"))
				{
					dwOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1] + dwLength + dwOffset;
					dwValidInstruction++;
					continue;
				}
				else if(dwValidInstruction == 4 && dwLength == 1 && strstr(da.result, "POPFD"))
				{
					dwValidInstruction++;
				}
				else if(dwValidInstruction == 5 && dwLength == 1 && strstr(da.result, "POPAD"))
				{
					dwValidInstruction++;
				}
				else if(dwValidInstruction == 6 && dwLength == 5 && strstr(da.result, "JMP"))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Tolone"));
					return VIRUS_FILE_DELETE;
				}
				dwOffset += dwLength;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVulcano
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Vulcano Family
--------------------------------------------------------------------------------------*/
int	CNonRepairable::DetectVulcano()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.DataDirectory[0x05].VirtualAddress == 0x00 &&         //Base relocation table
	 (!memcmp(m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].Name, ".reloc", 6)) &&
	  (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		const int VULCANO_BUFF_SIZE = 0x30;
		BYTE byBuff[VULCANO_BUFF_SIZE + MAX_INSTRUCTION_LEN] = {0};
		
		DWORD dwReadOffset = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		if(!m_pMaxPEFile->ReadBuffer(byBuff, dwReadOffset, VULCANO_BUFF_SIZE, VULCANO_BUFF_SIZE))
		{
			return iRetStatus;
		}
		DWORD dwLength = 0, dwValidInsCnt = 0, dwOffset = 0, dwInsCnt = 0;
		t_disasm	da;
		while(dwOffset < VULCANO_BUFF_SIZE)
		{
			dwLength = m_objMaxDisassem.Disasm((char *)&byBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
			if(dwLength > VULCANO_BUFF_SIZE - dwOffset || dwInsCnt > 0x15)
			{
				break;
			}
			dwInsCnt++;
			if(dwLength == 5 && dwValidInsCnt == 0 && dwInsCnt < 4 && strstr(da.result, "CALL") && 
			   *(DWORD *)&byBuff[dwOffset + 1] == 0x1910)
			{
				dwReadOffset = *(DWORD *)&byBuff[dwOffset + 1] + dwOffset + dwLength + dwReadOffset;
				if(!m_pMaxPEFile->ReadBuffer(byBuff, dwReadOffset, VULCANO_BUFF_SIZE, VULCANO_BUFF_SIZE))
				{
					return iRetStatus;
				}
				dwOffset = 0;
				dwValidInsCnt++;
				continue;
			}
			else if(dwLength == 1 && dwValidInsCnt == 1 && dwInsCnt < 0x10 && strstr(da.result, "PUSHAD"))
			{
				dwValidInsCnt++;
			}
			else if(dwLength == 5 && dwValidInsCnt == 2 && strstr(da.result, "CALL") && *(DWORD *)&byBuff[dwOffset + 1] == 0x06)
			{
				dwValidInsCnt++;
			}
			else if(dwLength == 4 && dwValidInsCnt == 3 && strstr(da.result, "MOV ESP,[ESP+8]"))
			{
				dwValidInsCnt++;
			}
			else if(dwLength == 2 && dwValidInsCnt == 4 && strstr(da.result, "JMP SHORT") && byBuff[dwOffset + 1] == 0x0C)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Vulcano"));
				iRetStatus = VIRUS_FILE_DELETE;
				break;
			}
			dwOffset += dwLength;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectNakuru
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Nakuru Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectNakuru()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_wNoOfSections == 0x8 || m_wNoOfSections == 0x3) && (m_pSectionHeader[0].SizeOfRawData == 0x3800 || (m_dwAEPUnmapped % 0x10) == 0xC))
		|| (m_wNoOfSections > 0x8 && m_wAEPSec == m_wNoOfSections - 2 && m_pSectionHeader[0].SizeOfRawData == 0x3800))
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int NAKURU_BUFF_SIZE = 0x2000;
		m_pbyBuff = new BYTE[NAKURU_BUFF_SIZE];
		if((m_dwAEPUnmapped % 0x10) == 0xC)
		{
			if(!GetBuffer(m_dwAEPMapped + 0x50, 0x100,0x100))
			{
				return iRetStatus;
			}
		}
		else if(!GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x3000, NAKURU_BUFF_SIZE))
		{
			return iRetStatus;
		}
		
		TCHAR szVirusName[MAX_PATH] = {0};
		TCHAR Nakuru_Sig[] ={ _T("554B5552414E5F454B535452414B544F52*434F4D53504543*2F632064656C202200000000FFFFFFFF0100000022")};
		TCHAR Nakuru_Sig1[] = {_T("494E5354414C4C*6B73706F6F6C6461656D6F6E")};
		CSemiPolyDBScn objPolyDB;
		objPolyDB.LoadSigDBEx(Nakuru_Sig, _T("Virus.Nakuru.A"), TRUE);
		objPolyDB.LoadSigDBEx(Nakuru_Sig1, _T("Virus.Nakuru.A"), FALSE);
		
		if(objPolyDB.ScanBuffer(&m_pbyBuff[0], NAKURU_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName)>0)
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectGobi
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Gobi Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectGobi()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0x0  && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData !=0 &&
		m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize == m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData &&
		(m_pSectionHeader[0].Characteristics & 0xE0000020) == 0xE0000020 &&
		(m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)		 
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int GOBI_BUFF_SIZE = m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - 0x5000;
		m_pbyBuff = new BYTE[GOBI_BUFF_SIZE];
		BYTE GobiSig1[] = {0x43, 0x3A, 0x5C, 0x72, 0x75, 0x6E, 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65};
		BYTE GobiSig2[] = {0x72, 0x75, 0x6E, 0x6D, 0x65, 0x2E, 0x65, 0x78, 0x65};
		if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData  + 0x5000, GOBI_BUFF_SIZE))
		{
			return iRetStatus;
		}
		for(int i = 0; i <= GOBI_BUFF_SIZE; i++)
		{
			if((memcmp(&m_pbyBuff[i],GobiSig1, sizeof(GobiSig1)) == 0) || (memcmp(&m_pbyBuff[i], GobiSig2, sizeof(GobiSig2)) == 0))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Gobi.A"));
				iRetStatus = VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectRufis
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Rufis Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectRufis()
{
	if((m_wAEPSec == 5 || m_wNoOfSections == 4) && (memcmp(m_pMaxPEFile->m_stSectionHeader[1].Name, ".data", 5) == 0) && 
		(memcmp(m_pMaxPEFile->m_stSectionHeader[3].Name, ".data", 5) == 0))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x500];
		if(GetBuffer(0x3000, 0x500, 0x500))
		{
			TCHAR RufisBSig[] = _T("650072006E0061006D006500000000000A000000460041004A00410052*2E006500780065*2E007000690066");
			TCHAR szVirusName[MAX_PATH] = {0};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(RufisBSig, _T("Virus.Rufis.B"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], 0x500, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDroworC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Drowor.C Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectDroworC()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0 && m_dwAEPUnmapped == 0x814C && (memcmp(m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Name, ".Upack", 6) == 0))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x700];
		
		GetBuffer(0x3A00, 0x500);
		
		DWORD dwReadBytes = 0;		
		m_pMaxPEFile->ReadBuffer(&m_pbyBuff[m_dwNoOfBytes], 0x5C00, 0x100, 0x100, &dwReadBytes);		
		m_dwNoOfBytes += dwReadBytes;

		m_pMaxPEFile->ReadBuffer(&m_pbyBuff[m_dwNoOfBytes], 0x7C00, 0x100, 0x100, &dwReadBytes);
		m_dwNoOfBytes += dwReadBytes;
		
		if(m_dwNoOfBytes == 0x700)
		{
			TCHAR DroworCSig[] = _T("2E444C4C000000004973446562756767657250726573656E74*7764666E67722E6578650000FFFFFFFF0900000053657475702E657865*433A5C5F2E646164*4D4349574143452E544D5000FFFFFFFF0B0000004D4349574143452E445256");
			//TCHAR DroworCSig[] = _T("2E444C4C000000004973446562756767657250726573656E74*2E6578650000FFFFFFFF0900000053657475702E657865*433A5C5F2E*4D4349574143452E544D5000FFFFFFFF0B0000004D4349574143452E445256");
			TCHAR szVirusName[MAX_PATH] = {0};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(DroworCSig, _T("Virus.Drowor.C"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectXorer
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Xorer Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectXorer()
{
	if((m_wAEPSec == 0) && ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL) &&
		(m_dwAEPUnmapped == m_dwAEPMapped) && (m_wNoOfSections == 5) && 
		((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) == 0x60000020) &&
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x42000040) == 0x42000040)  &&
		(memcmp(m_pSectionHeader[2].Name, ".data", 5) == 0))
	{
		if(m_pbyBuff)
		{
			delete[] m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int XORER_DLL_BUFF = 0x1000;
		m_pbyBuff = new BYTE[XORER_DLL_BUFF];
		if(GetBuffer(m_pSectionHeader[2].PointerToRawData, XORER_DLL_BUFF, XORER_DLL_BUFF))
		{
			CSemiPolyDBScn polydbObj;	 
			const TCHAR XORER_SIG1[] = {_T("00000000584F5200*646174612E676966*636F6D*687474703A2F2F")};
			const TCHAR XORER_SIG2[] = {_T("000000004F52000058000000*646174612E676966*636F6D*687474703A2F2F")};
			const TCHAR XORER_SIG3[] = {_T("00000000520000004F000000580000*646174612E676966*636F6D*687474703A2F2F")};
			
			const TCHAR XORER_SIG4[] = {_T("726200006966000067000000612E00007400000064*687474703A2F2F")};
			const TCHAR XORER_SIG5[] = {_T("72620000646174612E67696600000000*687474703A2F2F")};
			const TCHAR XORER_SIG6[] = {_T("72620000612E67696600000064617400*687474703A2F2F")};
			const TCHAR XORER_SIG7[] = {_T("7262000067696600612E0000740000006461*687474703A2F2F")};
			const TCHAR XORER_SIG8[] = {_T("436F6D204170*626F6F742E696E69000000005C636F6D5C6C736173732E657865")};
			polydbObj.LoadSigDBEx(XORER_SIG1, _T("Virus.XORER.DLL"), TRUE);
			polydbObj.LoadSigDBEx(XORER_SIG2, _T("Virus.XORER.DLL"), TRUE);
			polydbObj.LoadSigDBEx(XORER_SIG3, _T("Virus.XORER.DLL"), TRUE);
			polydbObj.LoadSigDBEx(XORER_SIG4, _T("Virus.XORER.DLL"), TRUE);
			polydbObj.LoadSigDBEx(XORER_SIG5, _T("Virus.XORER.DLL"), TRUE);
			polydbObj.LoadSigDBEx(XORER_SIG6, _T("Virus.XORER.DLL"), TRUE);
			polydbObj.LoadSigDBEx(XORER_SIG7, _T("Virus.XORER.DLL"), TRUE);
			polydbObj.LoadSigDBEx(XORER_SIG8, _T("Virus.XORER.DLL"), FALSE);
			
			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectNGVCK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.NGVCK.Gen Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectNGVCK()
{
	if(m_wAEPSec == m_wNoOfSections - 1 && 
		m_dwAEPUnmapped == m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress &&
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".Cuttlef", 8) == 0) && 
		m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x43757474)
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.NGVCK.Gen"));
		return VIRUS_FILE_DELETE;
	}

	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDockA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Dock.A Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectDockA()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x4 && m_wAEPSec == 0x0 && 
		((m_dwAEPUnmapped == 0x5716 && m_pSectionHeader[1].SizeOfRawData == 0x3800) || 
		(m_dwAEPUnmapped == 0x68D8 && m_pSectionHeader[1].SizeOfRawData == 0x3600)) &&
		(m_pSectionHeader[0].Characteristics & 0x60000020) == 0x60000020)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int DOCKA_BUFF_SIZE = m_pSectionHeader[1].SizeOfRawData;
		m_pbyBuff = new BYTE[DOCKA_BUFF_SIZE];
		
		if(!GetBuffer(m_pSectionHeader[1].PointerToRawData , DOCKA_BUFF_SIZE, DOCKA_BUFF_SIZE))
		{
			return iRetStatus;
		}
		TCHAR szVirusName[MAX_PATH] = {0};
		TCHAR DockA_Sig[] ={ _T("77733268656C702E646C6C*7061676566696C65732E646174")};
		
		CSemiPolyDBScn objPolyDB;
		objPolyDB.LoadSigDBEx(DockA_Sig, _T("Virus.Dock.A"), FALSE);
		
		if(objPolyDB.ScanBuffer(&m_pbyBuff[0], DOCKA_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName)>0)
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.VB.dp Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVB()
{
	if(m_wNoOfSections >= 3 && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x300;
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(GetBuffer(0x1E00, BUFF_SIZE, BUFF_SIZE))
		{
			TCHAR RufisBSig[] = _T("45003A005C0077006F0072006B005C006B0069006C006C00*7465737400457863656C0000B9A4B3CC31");
			TCHAR szVirusName[MAX_PATH] = {0};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(RufisBSig, _T("Virus.VB.dp"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}

		if(GetBuffer(m_dwAEPMapped + 0xF00, BUFF_SIZE, BUFF_SIZE))
		{
			TCHAR VB_GB[] = _T("6C626C506573616E0001011F00*6C65656E612028626163613A20276C696E6127292069206C6F766520796F75");			

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(VB_GB, _T("Virus.VB.gb"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	if (m_wAEPSec == 0x0 && (m_wNoOfSections >= 0x3 && m_wNoOfSections <= 0x5) && 
	   ((m_dwAEPUnmapped >= 0x13F8 && m_dwAEPUnmapped <= 0x16F0) || m_dwAEPUnmapped == 0x65B0) &&
	   (m_pSectionHeader[0].SizeOfRawData == 0x6000 || m_pSectionHeader[0].SizeOfRawData == 0x3000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		
		const int	BUFF_SIZE = 0x300;
		DWORD		dwOffset = 0x0;
		TCHAR		szVirusName[MAX_PATH] = {0};

		m_pbyBuff = new BYTE[BUFF_SIZE];

		if(m_dwAEPUnmapped == 0x65B0 || m_dwAEPUnmapped == 0x16F0)
		{
			dwOffset = 0x2AA0;
		}
		else
		{
			if(!m_pMaxPEFile->ReadBuffer(&dwOffset, m_dwAEPMapped + 0x1, 0x4, 0x4))
				return VIRUS_NOT_FOUND;

			if( OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwOffset - m_dwImageBase, &dwOffset))
				return VIRUS_NOT_FOUND;
		}


		if(GetBuffer(dwOffset, BUFF_SIZE, BUFF_SIZE))
		{
			CSemiPolyDBScn polydbObj;

			TCHAR	bVBBU_Sign1[] = {_T("E90000007C1940004C19400004144000*77736374662E657865*F4010000C81E400000000000A0264000203A4000")}; 
			TCHAR	bVBBU_Sign2[] = {_T("280046006C007900200066006F0072002000460075006E0029*51005100470061006D0065*770073006300740066002E006500780065")};
			TCHAR	szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(&bVBBU_Sign1[0], _T("Virus.W32.VB.bu"), TRUE);
			polydbObj.LoadSigDBEx(&bVBBU_Sign2[0], _T("Virus.W32.VB.bu"), FALSE);

			
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	if((m_wNoOfSections == 0x3 || m_wNoOfSections == 0x2) && m_wAEPSec == 0x0 && ((m_dwAEPUnmapped == 0x1880 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0xC000) ||
		((m_dwAEPUnmapped & 0xF00F) == 0x1008 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x6000)))
	{
		DWORD	dwReservedBytes = 0;

		m_pMaxPEFile->ReadBuffer(&dwReservedBytes, 0x20, sizeof(DWORD), sizeof(DWORD));
		if(dwReservedBytes == 0x010F00E0)
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int	VBDV_BUFF_SIZE = 0x600;
			m_pbyBuff = new BYTE[VBDV_BUFF_SIZE];

			DWORD	dwReadOff = m_dwAEPMapped + 0x930;
			DWORD	dwBytes2Read = VBDV_BUFF_SIZE;
			if(m_dwAEPUnmapped == 0x1880)
			{
				dwReadOff = m_dwAEPMapped + 0xB00;
				dwBytes2Read = 0x100;
			}
			if(!GetBuffer(dwReadOff, dwBytes2Read, dwBytes2Read))
			{
				return VIRUS_NOT_FOUND;
			}
			TCHAR szVirusName[MAX_PATH] = {0};
			TCHAR szVBDV[] = _T("5C0044005200490056004500520053005C00530045005200560049004300450053002E004500580045*5C0044005200490056004500520053005C00570049004E004C004F0047004F004E002E004500580045*530059005300540045004D002E0049004E0049");	
			TCHAR szVBDV1[] = _T("4F00500045004E003D00530045005400550050002E004500580045*530045005200560049004300450053002E004500580045*530068007500740044006F0077006E002E004500580045*570049004E004C004F0047004F004E002E004500580045");		

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(szVBDV, _T("Virus.VB.DV"), TRUE);
			polydbObj.LoadSigDBEx(szVBDV1, _T("Virus.VB.DV"), FALSE);
		
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDream
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.W32.Dream Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectDream()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const int BUFF_SIZE = 0x1500;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[BUFF_SIZE];
	if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xE0000020) == 0xE0000020) && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		if(GetBuffer(0x11600, BUFF_SIZE, BUFF_SIZE))
		{
			TCHAR DreamBSig[] = _T("6865727A20*2032396668616C68*676F687265657468");

			TCHAR szVirusName[MAX_PATH] = {0};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(DreamBSig, _T("Virus.W32.Dream"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSuperThreat
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.SuperThreat.B Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectSuperThreat()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	const BYTE bySig[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0x45, 0x07, 0x40, 0xFF, 0xE0};
	BYTE byBuff[sizeof(bySig)] = {0};

	if(!m_pMaxPEFile->ReadBuffer(byBuff, m_dwAEPMapped, sizeof(bySig), sizeof(bySig)))
	{
		return iRetStatus;
	}

	if(memcmp(byBuff, bySig, sizeof(bySig)) == 0)
	{
		DWORD dwOffset = 0;
		if(!m_pMaxPEFile->ReadBuffer(&dwOffset, m_dwAEPMapped + sizeof(bySig), 4, 4))
		{
			return iRetStatus;
		}

		if(m_wNoOfSections - 1 == m_pMaxPEFile->Rva2FileOffset(dwOffset + 1 - m_dwImageBase, &dwOffset))
		{
			if(dwOffset % m_pMaxPEFile->m_stPEHeader.FileAlignment == 0x00)
			{
				const BYTE bySig1[] = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x0F, 0x31, 0x89, 0x85, 0x9E, 0x00};
				m_pMaxPEFile->ReadBuffer(byBuff, dwOffset, sizeof(bySig1), sizeof(bySig1));
				
				BYTE bySig2[sizeof(bySig1)] = {0};
				if(dwOffset >= m_pMaxPEFile->m_dwFileSize || memcmp(byBuff, bySig1, sizeof(bySig1)) == 0 || memcmp(byBuff, bySig2, sizeof(bySig2)) == 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.SuperThreat.B"));
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}

	return iRetStatus;
}

/*--------------------------------------------------------------------------------------
Analyst     : Prashant
Type        : Virus + File Infector
Name        : Virus.Win32.Delf Family
Description : 
            Virus code size exe = 266KB
			    dll = 61kb
            FileSystem Modification
                 : 
                     Infect exe files.

            Registry Modifications
                 :   
		     No modification
           
            Infection 
                  :	inject code in iexplore.exe and infection of Virus.Win32.Downloader.e

	    Signature : EXE: 1. Mutex name
			     2. file name

			DLL: Inter file name

		*Dll are armadillo packed  
		

--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectDelf()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	//---------------------------------------------Virus.W32.Delf.av--------------------------------------------------------
	if((m_wAEPSec == 0) && (m_wNoOfSections >= 6 || m_wNoOfSections == 3) && (m_pSectionHeader[m_wAEPSec].SizeOfRawData >=9600) && (m_dwAEPUnmapped >= 0xA20C))
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int DELFAV_BUF_SIZE = 0x100;
		m_pbyBuff = new BYTE[DELFAV_BUF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(GetBuffer(m_dwAEPMapped - 0x900,DELFAV_BUF_SIZE,DELFAV_BUF_SIZE))
		{
			TCHAR Delfav_sig[] = {_T("633A5C54656D705C*2E455845*633A5C54656D705C4175746F72756E2E696E66")};
			
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(Delfav_sig, _T("Virus.W32.Delf.av"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], 0x100, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					iRetStatus = VIRUS_FILE_DELETE;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);					
				}
			}
		}
	}
	//---------------------------------------------Virus.W32.Delf.bh--------------------------------------------------------
	else if(m_wAEPSec == 0x0 && (m_wNoOfSections == 0x4 || m_wNoOfSections == 0x8) && 
		(((m_dwAEPUnmapped & 0xFFFF0) == 0x17B40 && ( m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x16C00 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x24000) && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL )||
		(m_dwAEPUnmapped == 0x19EA && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x6000 && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int DELFBH_BUF_SIZE = 0x200;
		m_pbyBuff = new BYTE[DELFBH_BUF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwBuffOffset = m_dwAEPMapped - 0x3DC;
		
		if(m_dwAEPUnmapped == 0x19EA)
			dwBuffOffset = m_pSectionHeader[m_wAEPSec + 1].PointerToRawData + 0xEE0;

		if(GetBuffer(dwBuffOffset, DELFBH_BUF_SIZE, DELFBH_BUF_SIZE))
		{
			CSemiPolyDBScn polydbObj;
			TCHAR szVirusName[MAX_PATH] = {0};
			LPCTSTR Delfbh_sig = {_T("4D592049532050524F4752414D4D4552*6B6C6E65772E657865*7368652E646C6C")}; //MY IS PROGRAMMER * klnew.exe *she.dll  for EXE
			if(m_dwAEPUnmapped == 0x19EA)
			{
				SecureZeroMemory(&Delfbh_sig, sizeof(Delfbh_sig));
				Delfbh_sig = (_T("4D61784D696E2E646C6C*4D617831004D696E31"));								//MaxMin.dll * Max1.Min1    for DLL
			}
			polydbObj.LoadSigDBEx(Delfbh_sig, _T("Virus.W32.Delf.bh"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], DELFBH_BUF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					iRetStatus = VIRUS_FILE_DELETE;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);					
				}
			}
		}
	}
	return iRetStatus;
}

int CNonRepairable::DetectSmall98()					// Virus.Win98.Small.98
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wAEPSec == 0)
	{
		DWORD	dwReadOff			= 0x0000FFFF;
		const int SMALL_BUFF_SIZE	= 0x62;

		if (m_pbyBuff)
		{
			delete []m_pbyBuff; 
			m_pbyBuff = NULL;
		}

		m_pbyBuff = new BYTE[SMALL_BUFF_SIZE];
		dwReadOff  = m_dwAEPMapped & dwReadOff;

		if(!GetBuffer(dwReadOff, SMALL_BUFF_SIZE,SMALL_BUFF_SIZE))
		{
			return iRetStatus;
		}

		const TCHAR Win9x_Small_98[] = {_T("9366B8003F506A42598BD7*66B800405A6A6259")};		
		
		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(Win9x_Small_98, _T("Virus.W9X.Small.98"), FALSE);

		TCHAR szVirusName[MAX_PATH] = {0};
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], SMALL_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				iRetStatus = VIRUS_FILE_DELETE;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTwinny
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Twinny Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectTwinny()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_wNoOfSections >= 6) || (m_wNoOfSections ==3)) && (m_pSectionHeader[m_wAEPSec].Characteristics == 0x60000020) &&
		(m_pMaxPEFile->m_stPEHeader.SizeOfStackCommit > 0x10000))
	{
		DWORD dwVal1 = 0x0,dwVal2 = 0;	
		if((m_pMaxPEFile->ReadBuffer(&dwVal1,m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x8,0x4,0x4)) &&
			(m_pMaxPEFile->ReadBuffer(&dwVal2,m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x60,0x4,0x4)))
		{
			if(((dwVal1 >= 0x10000) && (m_wNoOfSections == 3)) || (dwVal2 != 0x110000) || ((dwVal1 != 0) && m_wNoOfSections != 3))
			{
				return iRetStatus;
			}
		}
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		iRetStatus = _DetectTwinny();
		SetEvent(CPolymorphicVirus::m_hEvent);		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectTwinny
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Twinny Family
--------------------------------------------------------------------------------------*/
int CNonRepairable::_DetectTwinny()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwCount = 0,dwOffset = 0;
	BYTE TWINNY_BUF[0x100] = {0};
	char szInstruction[1024];
	CEmulate m_objEmulate(m_pMaxPEFile);
	if(!m_objEmulate.IntializeProcess())
	{
		return iRetStatus;
	}
	m_objEmulate.SetEip(m_dwAEPUnmapped+m_dwImageBase);
	m_objEmulate.SetNoOfIteration(130);
	
	m_objEmulate.SetBreakPoint("__isinstruction('push')");
	m_objEmulate.SetBreakPoint("__isinstruction('call')");
	m_objEmulate.SetBreakPoint("__isinstruction('j')");
	while(1)
	{
		if(7 != m_objEmulate.EmulateFile(false))
		{
			dwOffset = m_objEmulate.GetSpecifyRegValue(4);
			break;
		}
		m_objEmulate.GetInstruction(szInstruction);
		if(strstr(szInstruction,"call") || strstr(szInstruction,"j"))
		{
			dwCount = 0;
			break;
		}
		dwCount++;
	}
	if(dwCount < 0x20 || dwCount > 0x3A)
	{
		return iRetStatus;
	}
	if(m_objEmulate.ReadEmulateBuffer(&TWINNY_BUF[0x00],(dwCount*4),dwOffset))
	{
		TCHAR Twinny_Sig[] ={_T("57696E39382E5477696E6E792d4949*6279204C55434B5920422E522E4420313939342D3939")};
		TCHAR Zombie_Sig[] = {_T("57696E39582E5A304D4269452D494920*6279205A304D4269452F3239412020582D29")};
		TCHAR TWINNY1_Sig[] = {_T("C3E9E5FBFFFF434F4D4D3F4E443F3F*A8A2A5E23F3F5745423F3FA2E1A5AC3F*E0ACEDA9AAA5445341563F3F*4558454E4F443F3F3F")};
		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(Twinny_Sig, _T("Virus.Twinny.16384.a"), TRUE);
		polydbObj.LoadSigDBEx(TWINNY1_Sig, _T("Virus.Twinny.16384.a"), TRUE);
		polydbObj.LoadSigDBEx(Zombie_Sig, _T("Virus.Zombie"), FALSE);
		TCHAR szVirusName[MAX_PATH] = {0};

		if(polydbObj.ScanBuffer(&TWINNY_BUF[0x00], 0x100, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				iRetStatus = VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
Analyst     : Alisha
Type:       : Virus
Name        : Virus.W32.Agent.j
Sig Region  : AEP
Intension   : Message dispayed string
Description :
		Drops file:
			   C:\WINDOWS\SYSTEM\Cexplorer.exe
			   C:\WINDOWS\Java.exe
			   C:\Tedy.exe
			   C:\Update.zip it contain setup.exe which is exact copy of virus stub
		Cexplorer.exe,Java.exe these copy of virus stub.
		Tedy.exe is packed with FSG 2.0 -> bart/xt
chnages in registry:
		Values added:
				HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewal: 0x00000001
 -------------------------------------------------------------------------------------*/

int CNonRepairable::DetectAgentJ()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	WORD wReservedBytes = 0,wReservedBytes1 = 0;;
	m_pMaxPEFile->ReadBuffer(&wReservedBytes, 0x34, sizeof(WORD), sizeof(WORD));
	m_pMaxPEFile->ReadBuffer(&wReservedBytes1, 0x38, sizeof(WORD), sizeof(WORD));

	// Primary checks 	
	if(m_wNoOfSections != 0x03 || m_dwAEPMapped != 0x227A || m_wAEPSec != 0x00 || wReservedBytes != 0x227A ||
	wReservedBytes1 != 0x1000)
	{
		return iRetStatus;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int AGENTJ_BUFF_SIZE = 0x100;
	m_pbyBuff = new BYTE[AGENTJ_BUFF_SIZE];	
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	if(!GetBuffer(m_dwAEPMapped + 0xD846, AGENTJ_BUFF_SIZE, AGENTJ_BUFF_SIZE))
	{
		return iRetStatus;
	}

	TCHAR szAgentJSig[] = _T("433A5C546564792E657865*53657879206D6F7669653A20687474703A2F2F68312E7269707761792E636F6D*433A5C53657475702E65786520433A5C5570646174652E7A6970");
				//Sign:- (C:\Tedy.exe*Sexy movie: http://h1.ripway.com*C:\Setup.exe C:\Update.zip)
	CSemiPolyDBScn polydbObj;
	polydbObj.LoadSigDBEx(szAgentJSig, _T("Virus.Agent.j"), FALSE);

	TCHAR szVirusName[MAX_PATH] = {0};
	if(polydbObj.ScanBuffer(&m_pbyBuff[0], AGENTJ_BUFF_SIZE, szVirusName) >= 0)
	{
		if(_tcslen(szVirusName) > 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
Analyst     : Satish
Type:       : Virus
Name        : Virus.Win32.Harrier
Analysis    :1)it displays MessageBox of Virus Information
	     2)it is having Multiple Decryption loop. After Decryption It contains Virus Name 'Harrier'
	     3)detecting Decryption Loop.		
-------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHarrier()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_wAEPSec == m_wNoOfSections -1) && (m_dwAEPMapped == m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		(m_pSectionHeader[m_wNoOfSections -1].Characteristics == 0xE0000040) && 
		(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".TEXT", 5) == 0) &&
		(m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData >= 0x18000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int HARRIER_BUFF_SIZE = 0x300;
		m_pbyBuff = new BYTE[HARRIER_BUFF_SIZE + MAX_INSTRUCTION_LEN];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, HARRIER_BUFF_SIZE + MAX_INSTRUCTION_LEN);

		if(GetBuffer(m_dwAEPMapped,HARRIER_BUFF_SIZE,HARRIER_BUFF_SIZE))
		{
			DWORD dwOffset = 0,dwLength = 0,dwMatchedInst = 0,dwInstCnt = 0;
			BYTE B1 = 0,B2 =0,bJmp = 0,bLoop = 0;
			t_disasm	da;
			while(dwOffset < HARRIER_BUFF_SIZE && dwInstCnt < 0x100)
			{
				B1 = m_pbyBuff[dwOffset];
				B2 = m_pbyBuff[dwOffset + 1];
				memset(&da, 0x00, sizeof(struct t_disasm));
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);
				if(B1 == 0xE2 && B2 == 0)
				{
					bLoop++;
					dwOffset += 2;
					continue;
				}
				dwInstCnt++;
				if(dwOffset > (HARRIER_BUFF_SIZE - dwLength))
				{
					break;
				}
				else if(dwInstCnt >= 0x20 && dwMatchedInst == 0)
				{
					return iRetStatus;
				}
				else if(dwLength == 5 && strstr(da.result,"CALL") && (*(DWORD *)&m_pbyBuff[dwOffset + 1] < 0x100))
				{
					if(dwMatchedInst >= 1 || dwInstCnt >= 0x20)
					{
						return iRetStatus;
					}
					dwOffset += *(DWORD *)&m_pbyBuff[dwOffset + 1];
					dwMatchedInst++;
				}
				else if(dwMatchedInst == 1 && dwLength == 6 && strstr(da.result,"XCHG [E"))
				{
					dwMatchedInst++;
				}
				else if((dwMatchedInst ==2) && dwLength == 6 && (strstr(da.result,"ADD [E")))
				{
					dwMatchedInst++;
				}
				else if((dwMatchedInst == 3) && dwLength >= 6 && strstr(da.result,"SUB DWORD PTR"))
				{
					dwMatchedInst++;
				}
				else if((dwMatchedInst >= 0x1) && dwLength == 2 && strstr(da.result,"JMP SHORT"))
				{
					dwOffset += m_pbyBuff[dwOffset + 1];
					bJmp++;
				}
				else if((dwMatchedInst >= 0x1) && dwLength == 3 && strstr(da.result,"JMP SHORT"))
				{
					dwOffset += m_pbyBuff[dwOffset + 2];					
					bJmp++;
				}
				else if((dwMatchedInst >= 0x1) && dwLength == 5 && strstr(da.result,"JMP"))
				{
					dwOffset += *(DWORD *)&m_pbyBuff[dwOffset + 1];
					bJmp++;
				}				
				else if((dwMatchedInst > 3) && (strstr(da.result,"SUB DWORD PTR") || strstr(da.result,"SUB [E") || strstr(da.result,"ADD [E")))
				{
					dwMatchedInst++;
				}
				dwOffset += dwLength;
			}
			if(dwMatchedInst > 8 && bJmp >= 0x1 && ((bLoop >= 0x3) || ((bLoop == 0) && bJmp >= 4)))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Harrier"));							
				 iRetStatus = VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectRedlofA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Redlof
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectRedlofA()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if (m_wNoOfSections == 0x4 && m_dwAEPUnmapped == 0x1844 && m_wAEPSec == 0x0 && 
		m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x13000 &&
		memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".moron", 6) == 0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int	REDLOFA_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[REDLOFA_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD	dwReadOff = 0x0;
		if(m_pMaxPEFile->ReadBuffer(&dwReadOff,m_dwAEPMapped + 0x1,sizeof(DWORD),sizeof(DWORD)))
		{
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwReadOff - m_dwImageBase,&dwReadOff))
			{
				return iRetStatus;
			}
		}
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x0],dwReadOff + 0x1090,REDLOFA_BUFF_SIZE,REDLOFA_BUFF_SIZE))
		{
			return iRetStatus;
		}

		TCHAR	szVirusName[MAX_PATH] = {0};
		TCHAR	szRedlofASig[] = _T("4D0061006E00690065007A*500075006E00790061*5C00540065006D0070005C0046006F006C006400650072002E006800740074*630068002E00620069006E*5C00540065006D0070005C007300790073002E006500780065*540075006700610073");
				            //M.a.n.i.e.z*P.u.n.y.a*\.T.e.m.p.\.F.o.l.d.e.r...h.t.t*c.h...b.i.n*\.T.e.m.p.\.s.y.s...e.x.e*T.u.g.a.s

		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(szRedlofASig, _T("Virus.Reflof.A"), FALSE);

		if(polydbObj.ScanBuffer(&m_pbyBuff[0], REDLOFA_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

int CNonRepairable::DetectZMorph()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	__try
	{
		iRetStatus = DetectZMorph2784();
	}
	__except (CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in VirusScanner Dll::WorkerThread")))
	{
		return iRetStatus;
	}
	return iRetStatus;

}
/*--------------------------------------------------------------------------------------
Analyst     : Prashant
Type        : Virus + File Infector
Name        : Virus.Win9x.ZMorph.2784
Description : Type = Appender[At last section] + Metamorphic.
			  Size = Varies file to file.
		      A. Installation: 
				 1. Infect all *.exe files.
			  B. File Modification :                   
                 	- in fect all *.exe files.
              C. Registry Modification :
                        - No modifications.
		      D. Infection : 
				1. 1st it create it code on stack.
				2. Execute that code ande then control pass to Host file.

			  * AEP is not geting.
Intention   : Infected files: 1ST 3 PUSHED DWORDS bye virus code on stack.
	      
		      For Stub : 
			1. Fix offsets From AEP Section.
			2. Fix Offsets 
			3. String from AEP section [KME.Z0MBiE-4.b]
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectZMorph2784()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	int		iPushCount = 0;
	DWORD	dwStackOffset = 0x00;
	

	if((m_wAEPSec == (m_wNoOfSections - 1)) && 
	   (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL && 
	   (m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0x60000020) != 0x60000020 &&
	   m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize >= 0x9000)
	{	
		BYTE	bySign[] = {0xC1, 0xC8, 0XE9, 0x70, 0xFD, 0xFF, 0xFF, 0x87, 0xDB, 0x87, 0xDB, 0x90};
		BYTE	byBuff[0xC]={0};

		CEmulate m_objEmulate(m_pMaxPEFile);
		if(!m_objEmulate.IntializeProcess())
		{
			return iRetStatus;
		}
		m_objEmulate.SetNoOfIteration(40);
		m_objEmulate.SetBreakPoint("__isinstruction('push e')");

		while( iPushCount <= 3)
		{
			if(7 == m_objEmulate.EmulateFile(false)) 
			{
				DWORD dwTemp = m_objEmulate.GetEip();
				iPushCount++;
			}
			else
			{
				return iRetStatus;
			}
		}
		dwStackOffset = m_objEmulate.GetSpecifyRegValue(4);
		m_objEmulate.ReadEmulateBuffer(byBuff, 0xC, dwStackOffset);

		if(memcmp(&byBuff[0], bySign, 0x0C) == 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win9x.ZMorph.2784"));
			iRetStatus = VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*--------------------------------------------------------------------------------------
Analyst     : Sneha Kurade
Type:       : Virus
Name        : Virus.BAT.Mosquito.c
Note 	    :      

>this virus is drop one ".bat" file
>it added two files in current folder i.e "setup.exe" and "setup.BMP"
>setup.exe is a clean file
>it added two folder in temp "afolder" and "ytmp"
>it added two files ".bat" and ".exe" in "ytmp" this folder
>it loads all dll and do get pro adress
>it searches the cmd.exe in windows
>after that it open that file and read it and get file attributes
>after that it write on console window by setting cursor position
>it write on console window by one byte
>it writes on console window i.e This program made by using "BATCH COMPILER" 
>and "Advanced BAT to EXE Convertor"
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectMosquitoC()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections != 0x4 && m_dwAEPMapped !=0x8D56 && m_pSectionHeader[0].SizeOfRawData != 0xF000)
		return iRetStatus;

	const BYTE byMosquitoCSig[] = {0x42,0x41,0x54,0x43,0x48};   //(B A T C H)

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int MOSQUITOC_BUFF_SIZE = 0x6C;
	m_pbyBuff = new BYTE[MOSQUITOC_BUFF_SIZE];

	if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x4224,MOSQUITOC_BUFF_SIZE,MOSQUITOC_BUFF_SIZE))
	{
		int i = 1,j = 0;
		for (i=1; i<=0x69,j<0x5; i+=0X1A, j++)
		{
			if(m_pbyBuff[i] != byMosquitoCSig[j])
				break;

		}

		if(j == 0x5)
		{	
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.BAT.Mosquito.c"));		
			iRetStatus = VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}  

/*-------------------------------------------------------------------------------------
	Function		: DetectIkatA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Ikat.a
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectIkatA()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections != 0x8 && m_dwAEPMapped !=0x3F184 && m_pSectionHeader[0].SizeOfRawData != 0x3F000)
		return iRetStatus;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int IKAT_BUFF_SIZE = 0x37;
	m_pbyBuff = new BYTE[IKAT_BUFF_SIZE];

	if(GetBuffer(m_pSectionHeader[7].PointerToRawData + 0x1DC1,IKAT_BUFF_SIZE,IKAT_BUFF_SIZE))
	{
		TCHAR IKAT_CZ_Sig[] = {_T("45003A005C003200320032003200*5C005200450053004F0055005200430045005300*5C00740061006B002E0064006F0063")};
		//E.:.\.2.2.2.2.\.R.E.S.O.U.R.C.E.S.\.t.a.k...d.o.c
		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(IKAT_CZ_Sig, _T("Virus.Ikat.a"), FALSE);

		TCHAR szVirusName[MAX_PATH] = {0};

		if(polydbObj.ScanBuffer(&m_pbyBuff[0], IKAT_BUFF_SIZE , szVirusName)>=0)	
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;

			}
		}
	}      
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectGlyn
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Glyn
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectGlyn()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x24AB && (m_pSectionHeader[0].SizeOfRawData == 0x2200 || m_pSectionHeader[0].SizeOfRawData == 0x2400))
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int GLYN_BUFF_SIZE = 0x50;
		m_pbyBuff = new BYTE[GLYN_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x1FE9, GLYN_BUFF_SIZE, GLYN_BUFF_SIZE))
		{
			TCHAR			GLYN_CZ_Sig[] = {_T("B9002000008B7508800623803612C00602464975F38D0500564000*5669722E657865")};
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(GLYN_CZ_Sig, _T("Virus.Win32.Glyn"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], GLYN_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}

	return iRetStatus;
}


/*--------------------------------------------------------------------------------------
Analyst     : Sneha Kurade
Type:       : virus
Name        : Virus.Durchina.a
Detection   : 100%
Signature   :  string :  :\Autorun.inf
                         muniu.exe
                         http://www.md80.cn/muniu/new/?v=2
                         temp.exe
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectDurchinaA()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	if(m_wAEPSec == 0 && (m_wNoOfSections == 0x3 || m_wNoOfSections == 0x6) && m_dwAEPMapped == 0x1D7F0 &&  (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1D600 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2F000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int	DURCHINA_BUFF_SIZE = 0x3E8;
		m_pbyBuff = new BYTE[DURCHINA_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x1CDBC, DURCHINA_BUFF_SIZE, DURCHINA_BUFF_SIZE))
		{
			TCHAR			DURCHINA_CZ_Sig[] = {_T("3A5C4175746F72756E2E696E66*6D756E69752E657865*687474703A2F2F7777772E6D6438302E636E2F6D756E69752F6E65772F3F763D32*74656D702E657865")};
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(DURCHINA_CZ_Sig, _T("Virus.Durchina.a"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0],DURCHINA_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectIframerC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha Kurade + Virus Team
	Description		: Detection routine for malwares : Virus.Iframer.C
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectIframerC()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	if(m_wAEPSec == 0 && m_wNoOfSections == 0x4 && m_dwAEPMapped == 0x7261 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x7600 && 
		(m_pSectionHeader[m_wNoOfSections - 3].Characteristics & 0xC0000080) == 0xC0000080 && memcmp(m_pSectionHeader[m_wNoOfSections - 3].Name, ".bss", 4) == 0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int IFRAMER_BUFF_SIZE = 0x87;
		m_pbyBuff = new BYTE[IFRAMER_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x1FA3, IFRAMER_BUFF_SIZE, IFRAMER_BUFF_SIZE))
		{
			TCHAR IFRAMER_CZ_Sig[] = {_T("8A91000100008855F48B45108A880101*8B55F083C201*80C101884DF48B55F481E2FF000000*25FF0000008B4DF481E1FF000000*81E1FF000000")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(IFRAMER_CZ_Sig, _T("Virus.Iframer.C"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],IFRAMER_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBZ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha Kurade + Virus Team
	Description		: Detection routine for malwares : Virus.Iframer.C
					 > it drops one file in windows i.e
					 > Explorer.exe
					 > it infect .exe files in current folder
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBZ()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	//if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0 && m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x189C && m_dwAEPMapped == m_dwAEPUnmapped && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x8000) 
	if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0 && m_wNoOfSections == 0x3 && (m_dwAEPMapped == 0x189C || m_dwAEPMapped == 0x0C9C)&& (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x8000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xA000) )//Change Aniket
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int	VBZ_BUFF_SIZE = 0x64;
		m_pbyBuff = new BYTE[VBZ_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0xE90, VBZ_BUFF_SIZE, VBZ_BUFF_SIZE))
		{
			TCHAR			VBZ_CZ_Sig[] = {_T("EC1E400002F037*A81D40005C1D4000A818400078*456C697A6100303031*456C697A615263")};
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(VBZ_CZ_Sig, _T("Virus.VB.Z"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0],VBZ_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirusArisG
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Gaurav Pakhale + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Aris.G
					  >it make changes in registry.
					  >it added "pf" files in C:\WINDOWS\Prefetch\ directory.
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVirusArisG()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if( m_wNoOfSections == 0x0004 && m_dwAEPMapped == 0x1000 && m_wAEPSec == 0x0003 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x9A00 )
	{

		TCHAR byArisGSig[] = {_T("BBAA03673B81C356FC98AF*BE4A37657381EE4A377D70*B921D1AE9E81E96DAC9E8E*B97CE7581A81E9F9FA4F8F")};
		
		if (CheckSigInBuffer(0x0A5A0,0x200,byArisGSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,  _T("Virus.Win32.Aris.G"));
			return VIRUS_FILE_DELETE;
		}
		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int ARISG_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[ARISG_BUFF_SIZE];

		if(GetBuffer(  0x0A5A0, ARISG_BUFF_SIZE, ARISG_BUFF_SIZE)) 
		{
			TCHAR THS_CZ_Sig[] = {_T("BBAA03673B81C356FC98AF*BE4A37657381EE4A377D70*B921D1AE9E81E96DAC9E8E*B97CE7581A81E9F9FA4F8F")}; 
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(THS_CZ_Sig, _T("Virus.Win32.Aris.G"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], ARISG_BUFF_SIZE , szVirusName)>=0)	
			{

				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					return VIRUS_FILE_DELETE;

				}
			}
			return iRetStatus;

		}
		*/

	}	
	return iRetStatus;

}

/*-------------------------------------------------------------------------------------
	Function		: DetectVirusTexelK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Gaurav Pakhale + Virus Team
	Description		: Detection routine for malwares : Texel Family
					  >it make changes in registry.
					  >it added "pf" files in C:\WINDOWS\Prefetch\ directory.
					  > malicious exe file name with path
Note   :

>This is windows excutable file written in C++.
>It makes changes in registery.
>It adds "pf" files in C:\WINDOWS\Prefetch\ directory.
>This is windows excutable file used to infect the system.
>When we click to this file, it opens 'cmd.exe' and run "cacls" command to modify access control list. 
>Using these command, it makes "sethc.exe" file available to everyone with full control. It also allows power user to run this file in next booting.
>When we click to this file, It makes changes in registry and drops "sethc.exe" in C:\windows\LastGood\system32 folder and 'dllcache' folder.
>"sethc.exe" is mfc application in which it ask for password(valid password:qi19921016) and "Enter" button. 
>When we hit enter, it opens file explorer to choose file and infect that file.
>It adds 'C:\windows\LastGood' folder which used to save configruation and it will run after next booting process.
>When we restart the system, malicious functionality by sethc.exe saves in registry with password and then it infect the system automatically.
-------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVirusTexelK()
{

	int		iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwDiff = 0x00;

	if(  m_wNoOfSections == 0x04)
	{
		dwDiff = 0x05270;
	}
	else
	{
		dwDiff = 0x05270 + 0x10000;
	}

	if( ( m_wNoOfSections == 0x0003 || m_wNoOfSections == 0x04) && (m_dwAEPMapped == 0x05DC3 || m_dwAEPMapped == 0x1D06 ) && m_wAEPSec == 0x0 && ( m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xD000 ))
	{

		TCHAR	bTexelKSig[] = {_T("73797374656D333273657468632E657865*646C6C636163686573657468632E657865*5C73657468632E657865")};

		if (CheckSigInBuffer(dwDiff,0x200,bTexelKSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Texel.K"));
			return VIRUS_FILE_DELETE;
		}

		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		
	
		const int TEXELK_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[TEXELK_BUFF_SIZE];


		
	
		
		if(GetBuffer( dwDiff, TEXELK_BUFF_SIZE, TEXELK_BUFF_SIZE)) 
			{
					TCHAR THS_CZ_Sig[] = {_T("73797374656D333273657468632E657865*646C6C636163686573657468632E657865*5C73657468632E657865")};   
					CSemiPolyDBScn polydbObj;
					polydbObj.LoadSigDBEx(THS_CZ_Sig, _T("Virus.Win32.Texel.k"), FALSE);
					TCHAR szVirusName[MAX_PATH] = {0};

					if(polydbObj.ScanBuffer(&m_pbyBuff[0], TEXELK_BUFF_SIZE , szVirusName)>=0)	
					{

						if(_tcslen(szVirusName) > 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
	
							return VIRUS_FILE_DELETE;
					
						}
					}
						return iRetStatus;

				}
		*/

	}	
	return iRetStatus;

}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBAZ
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar + Virus Team
	Description		: Detection routine for malwares : Virus.VB.AZ
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBAZ()
{
	int iRetStatus = VIRUS_NOT_FOUND;	
	DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
	//DWORD dwOverlaySize = m_pMaxPEFile->m_dwFileSize -(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);
	
	if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0 && (m_wNoOfSections == 0x3 || m_wNoOfSections == 0x4) && (m_dwAEPMapped == 0x2A64 ||m_dwAEPMapped == 0x1E64) && 	(m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x28000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x22000) && (dwOverlayStart == 0x2B000 || dwOverlayStart == 0x2D200))
	{
		TCHAR pbyVBAZSig[] = {_T("AC39400002F8300000FF*04364000B0344000702A400078000000*416E617068616C6973206A6176616E696361*416E617068616C697300004564656C7765697373*4500640065006C00770065006900730073002000460069007800*5C004500640065006C00770065006900730073002E007600620070")};

		if (CheckSigInBuffer(m_pSectionHeader[0].PointerToRawData + 0x2684,0x3CB,pbyVBAZSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,  _T("Virus.VB.AZ"));
			return VIRUS_FILE_DELETE;
		}
		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int VBZ_BUFF_SIZE = 0x3CB;
		m_pbyBuff = new BYTE[VBZ_BUFF_SIZE];
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x2684, VBZ_BUFF_SIZE, VBZ_BUFF_SIZE))
		{
			TCHAR VBZ_CZ_Sig[] = {_T("AC39400002F8300000FF*04364000B0344000702A400078000000*416E617068616C6973206A6176616E696361*416E617068616C697300004564656C7765697373*4500640065006C00770065006900730073002000460069007800*5C004500640065006C00770065006900730073002E007600620070")};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(VBZ_CZ_Sig, _T("Virus.VB.AZ"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],VBZ_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
		*/

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVbAA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Vb.AA

		*>Malicious file path and name : 
			*> C.:.\.S.k.u.n.k...e.x.e..
			*>\.S.t.a.r.t.u.p.\.S.k.u.n.k...e.x.e..
			*>S.k.u.n.k...e.x.e
			*>A.:.\.S.k.u.n.k...e.x.e..

		*>Malicious Website :
			*>h.t.t.p.:././.w.w.w...u.d.7.s.w.e...t.3.5...c.o.m./.3.w.Y.2.6.s.s...c.o.m.
Note   :
>it make changes in registery.
>it alter the registry entries.
>Modify files from C Drive.
>it drop "Skunk.exe" file in C:\ , system32 , C:\Documents and Settings\All Users\Start Menu\Programs\Startup directory.
>"Skunk.exe" is exact same copy of orignal file.
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVbAA()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x02 && m_dwAEPMapped == 0x613C  && m_dwAEPUnmapped == 0x613C &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x296000 && m_pMaxPEFile->m_stPEHeader.CheckSum == 0x25CD8 && m_pMaxPEFile->m_dwFileSize == 0x299000)
	{
		TCHAR  pbyVIRVBAASig[] = {_T("43003A005C0053006B0075006E006B002E0065007800650000*5C0053007400610072007400750070005C0053006B0075006E006B002E0065007800650000*53006B0075006E006B002E006500780065*41003A005C0053006B0075006E006B002E0065007800650000*4600550043004B0059004F00550021*68007400740070003A002F002F007700770077002E007500640037007300770065002E007400330035002E0063006F006D00*2F0033007700590032003600730073002E0063006F006D00")};

		if (CheckSigInBuffer(0x9228,0x15B7,pbyVIRVBAASig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Vb.AA"));
			return VIRUS_FILE_DELETE;
		}
		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int VIRVBAA_BUFF_SIZE = 0x15B7;
		m_pbyBuff = new BYTE[VIRVBAA_BUFF_SIZE];

		if(GetBuffer(0x9228, VIRVBAA_BUFF_SIZE, VIRVBAA_BUFF_SIZE))
		{
			TCHAR  VIRVBAA_CZ_Sig[] = {_T("43003A005C0053006B0075006E006B002E0065007800650000*5C0053007400610072007400750070005C0053006B0075006E006B002E0065007800650000*53006B0075006E006B002E006500780065*41003A005C0053006B0075006E006B002E0065007800650000*4600550043004B0059004F00550021*68007400740070003A002F002F007700770077002E007500640037007300770065002E007400330035002E0063006F006D00*2F0033007700590032003600730073002E0063006F006D00")};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(VIRVBAA_CZ_Sig, _T("Virus.Win32.Vb.AA"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], VIRVBAA_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					return VIRUS_FILE_DELETE;
				}
			}
		}
		*/
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Sality.K
		Note		:
>it make changes in registery.
>it alter the registry entries.
-------------------------------------------------------------------------------------*/
int CNonRepairable::DetectSalityK()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	DWORD	dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
	DWORD	dwOverlaySize = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);

	if(m_wNoOfSections == 0x04 && m_dwAEPMapped == 0x1890C || m_dwAEPMapped == 0x13E8 &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x22000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1000  && dwOverlaySize == 0x1000 || dwOverlaySize == 0x5000)
	{
		TCHAR  pbySalityKSig[] = {_T("57696E33322E484C4C50*2E4B756B75*2076332E30362073747562")};

		if (CheckSigInBuffer(dwOverlayStart + 0x564,0x27,pbySalityKSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Sality.K"));
			return VIRUS_FILE_DELETE;
		}
		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int SALITYK_BUFF_SIZE = 0x27;
		m_pbyBuff = new BYTE[SALITYK_BUFF_SIZE];

		if(GetBuffer(dwOverlayStart + 0x564, SALITYK_BUFF_SIZE, SALITYK_BUFF_SIZE))
		{
			TCHAR  SALITYK_CZ_Sig[] = {_T("57696E33322E484C4C50*2E4B756B75*2076332E30362073747562")};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(SALITYK_CZ_Sig, _T("Virus.Win32.Sality.K"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], SALITYK_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					return VIRUS_FILE_DELETE;
				}
			}
		}
		*/
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDelfB
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.Delf.B
					>It Alters Registry entries.
					>It Drops the same copy in C:\Windows\System32\sysmng.exe.
					>It makes changes in registry.
-------------------------------------------------------------------------------------*/
int CNonRepairable::DetectDelfB()
{
	int           iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x000A && m_dwAEPMapped == 0x4FEF4 && m_wAEPSec == 0x000 && m_pSectionHeader[m_wAEPSec].SizeOfRawData== 0x4F000)
	{
		if(CheckSigInBuffer(0x4FBF0,0x85,_T("48616C6C6F00000054696475726C6168*20736179616E672C207375646168206D*616C616D2C0000005469616461207961*6E67206C656269682062657268617267*612073656C61696E2063696E74616B75*2079616E672074756C75732C20526F73*6568656172742E2E2E00000049204C6F*766520596F7520526F726F2100000000")))
		{

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.Delf.B"));
			return VIRUS_FILE_DELETE;

		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectDecon
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.Decon.a
					>This Makes changes in registry.
					>It Drops Malicious File in C:\Windows\SVCHOST.EXE .
-------------------------------------------------------------------------------------*/
int CNonRepairable::DetectDecon()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x002 && m_dwAEPMapped == 0x1A90 && m_wAEPSec == 0x000 && m_pSectionHeader[m_wAEPSec].SizeOfRawData== 0x0A200)
	{
		if(CheckSigInBuffer(0x55C,0x2F,_T("546869732070726F6772616D*206E6F742077696E3332206D6F6465*535643484F53542E455845")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.Decon.a"));
			return VIRUS_FILE_DELETE;

		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectInfector
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.Decon.a
						*>It infects .txt and .gif files.
						*>It Encrypts all the data Within those Infected files.
						*>It also adds .xxx Extension at the end of infected files.
--------------------------------------------------------------------------------------*/
int  CNonRepairable::DetectInfector()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x00A && m_dwAEPMapped == 0xC2264 && m_wAEPSec == 0x001 && m_pSectionHeader[m_wAEPSec].SizeOfRawData== 0x0E00)
	{

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int Infector_BUFF_SIZE = 0x824;
		m_pbyBuff = new BYTE[Infector_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		const BYTE	SPYSIG[] = {0x50,0x57,0x43,0x53,0x48}; //PWCSH
		if(!GetBuffer(0xCB9EC, 0x07, 0x07))
		{
			return iRetStatus;
		}
		if(memcmp(&m_pbyBuff[0x0], SPYSIG, sizeof(SPYSIG)) == 0x00)
		{
			if(!GetBuffer(0xB905F, Infector_BUFF_SIZE, Infector_BUFF_SIZE))
			{
				return iRetStatus;
			}

			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};
			TCHAR			Infector_SIG[] = {_T("C745C03C000000C745C440000000A1FCDD4C00*8B80700100008945C8*52004500410044004D0045005F005800580058002E005400580054")};

			polydbObj.LoadSigDBEx(Infector_SIG, _T("Virus.Win32.Infector.GEN"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], Infector_BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}

	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x004 && m_dwAEPMapped == 0x1A00 && m_wAEPSec == 0x003 && m_pSectionHeader[m_wAEPSec].SizeOfRawData== 0x0A00)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		if(CheckSigInBuffer(0x1A00,0x35,_T("E8000000005D81ED05104000BA001040*00E91806000056669C66813E4D5A7513*03763C66813E50457509669D5EB80100")))
		{

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Infector.GEN"));
			return VIRUS_FILE_DELETE;

		}
	}

	if((m_wAEPSec == (m_wNoOfSections - 1)) && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL )
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int InfectorAni_BUFF_SIZE = 0x830;
		m_pbyBuff = new BYTE[InfectorAni_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return VIRUS_NOT_FOUND;
		}

		if(GetBuffer(m_pMaxPEFile->m_dwFileSize - 0x1000, InfectorAni_BUFF_SIZE, InfectorAni_BUFF_SIZE))
		{

			const TCHAR szInfectorSign[] = {_T("E8000000005D81ED05104000BA001040*00E91806000056669C66813E4D5A7513*03763C66813E50457509669D5EB80100")};

			CSemiPolyDBScn polydbObj;

			polydbObj.LoadSigDBEx(szInfectorSign, _T("Virus.W32.Infector.GEN"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], InfectorAni_BUFF_SIZE, szVirusName) >=0)
			{

				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;

			}
		}

	}

	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectVBCC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha Kurade + Virus Team
	Description		: Detection routine for malwares : Virus.VB.CC
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBCC()
{
	int iRetStatus = VIRUS_NOT_FOUND;	


	if(m_wAEPSec == 3 && m_wNoOfSections == 0x5 && m_dwAEPMapped == 0x15001 && m_dwAEPMapped == m_dwAEPUnmapped && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x4000) 

	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int VBCC_BUFF_SIZE = 0x64;
		m_pbyBuff = new BYTE[VBCC_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x21C0, VBCC_BUFF_SIZE, VBCC_BUFF_SIZE))
		{
			TCHAR VBCC_CZ_Sig[] = {_T("04404000FEF9F80120FF*3432400034304000DC11400078*57696E576F726400546F6D6220526169646572")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(VBCC_CZ_Sig, _T("Virus.VB.CC"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],VBCC_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectBolzanoGen
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha Kurade + Virus Team
	Description		: Detection routine for malwares : 
					Virus.Win32.Bolzano.2676
					Virus.Win32.Bolzano.3120
					Virus.Win32.Bolzano.3164
					virus.win32.bolzano.5396.a
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectBolzanoGen()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wNoOfSections == 0x05 && m_dwAEPMapped == 0x0600  &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x0200 && (memcmp(m_pSectionHeader[4].Name, ".debug", 6) == 0))
	{
		DWORD	dwStartBuff = m_pMaxPEFile->m_dwFileSize - 0x81;

		TCHAR  pbyBolzanoGenSig[] = {_T("424F4C5A414E4F2E41534D*00010000000000000010000C0006000000")};

		if (CheckSigInBuffer(dwStartBuff,0x35,pbyBolzanoGenSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Bolzano.GEN"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectBubeG
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha Kurade + Virus Team
	Description		: Detection routine for malwares : 
					Virus.Win32.Bube.g
					Virus.Win32.Bube.i
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectBubeG()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	if(m_wAEPSec == 0 && m_wNoOfSections == 0x1 && (m_dwAEPMapped == 0x20BA || m_dwAEPMapped == 0x20A7) && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2200) 
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int	BUBE_BUFF_SIZE = 0x700;
		m_pbyBuff = new BYTE[BUBE_BUFF_SIZE];

		if(GetBuffer(0x3F0, BUBE_BUFF_SIZE, BUBE_BUFF_SIZE))
		{
			int j = 0x5C;
			for(int i = 0x0; i < 0x700; i++)
			{
			   *(byte*)&m_pbyBuff[i] = *(byte*)&m_pbyBuff[i]^j;
				   j++;

			}
			TCHAR			BubeG_CZ_Sig[] = {_T("5C6578706C6F7265722E6E6577*5C736F66742E657865*5C77696E696E69742E696E69")};
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(BubeG_CZ_Sig, _T("Virus.Win32.Bube.g"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0],BUBE_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLO28672
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha Kurade + Virus Team
	Description		: Detection routine for malwares : 
					Virus.Win32.HLLO.28672
					Virus.Win32.Xorer.a
					Virus.Win32.HLLP.Labox.a
					Virus.Win32.HLLW.VB.s
					Virus.Win32.HLLW.VB.a
Detection    : 100%
-------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLO28672()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_pMaxPEFile->m_bIsVBFile && m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x12BC  &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x4000)
	{
        TCHAR  pbyHLLO28672Sig[] = {_T("941D400000F0360000FFFFFF08*B01C4000A81C4000C812400078*7069636F666D6579756D0072656E616D65")};

		if (CheckSigInBuffer(0x1D30,0x70,pbyHLLO28672Sig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLO.28672"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectXorerA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Xorer.a
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectXorerA()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x14FF  && m_dwAEPMapped == m_dwAEPUnmapped && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x4000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x7000))
	{
        TCHAR  pbyXorerASig[] = {_T("732E657865*5C6C736173000000*5C636F6D00000000*233332373730*584F52")};

		if (CheckSigInBuffer(0x5030,0xA0,pbyXorerASig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Xorer.a"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectHLLPLaboxA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLP.Labox.a
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLPLaboxA()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wAEPSec == 0x0E && m_wNoOfSections == 0x0f && m_dwAEPMapped == 0x13D600 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2000 && memcmp(m_pSectionHeader[m_wAEPSec].Name, "pebundle", 8) == 0)
	{
        TCHAR  pbyHLLPLaboxASig[] = {_T("43003A005C00570069006E0064006F0077007300*5C0049006D0070006F007200740061006E0074002E006500780065*48004B00430055005C0053006F006600740077006100720065005C*004D006900630072006F0073006F00660074005C00570069006E0064006F0077007300*5C00430075007200720065006E007400560065007200730069006F006E00*5C00520075006E005C00570069006E0064006F00770073")};

		if (CheckSigInBuffer(0x4670,0xE0,pbyHLLPLaboxASig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLP.Labox.a"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLWVBS
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.VB.s
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLWVBS()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0x0 && m_wNoOfSections == 0x05 && m_dwAEPMapped == 0xA5C && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x6000)
	{
        TCHAR  pbyHLLWVBSSig[] = {_T("A821400000F8300000FFFFFF080000000100000001*8020400080204000681640*4F646979616E")};

		if (CheckSigInBuffer(0x1558,0x68,pbyHLLWVBSSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.VB.s"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLWVBA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.VB.a
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLWVBA()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0x0 && m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x13F4 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x4000)
	{
        TCHAR  pbyHLLWVBASig[] = {_T("1C1C400002F8300000FFFFFF08*381B4000E81A40000014400078*73657276696365*50726F6A65637431")};

		if (CheckSigInBuffer(0x1BB8,0x88,pbyHLLWVBASig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.VB.a"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLWMintopA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.Mintop.A
	Detection		: 100%
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLWMintopA()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0x0 && m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x1B30 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xA000)
	{
		TCHAR  pbyHLLWMintopASig[] = {_T("3022400000F8300000FFFFFF08*F81F4000681F40003C1B400078*4D73696D6E*4D73696D6E*5169757469616E")};

		if (CheckSigInBuffer(0x2120,0x90,pbyHLLWMintopASig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.Mintop.A"));
			return VIRUS_FILE_DELETE;
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLWProdvin
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.Prodvin
	Detection		: 100%
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLWProdvin()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0x0 && m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x106C && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2000)
	{
		TCHAR  pbyHLLWProdvinSig[] = {_T("C018400000F0300000FFFFFF08*BC154000A41540007810400078*50726F73747965204476697A68656E697961")};

		if (CheckSigInBuffer(0x163C,0x88,pbyHLLWProdvinSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.Prodvin"));
			return VIRUS_FILE_DELETE;
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLWRologC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.Rolog.c
	Detection		: 100%
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLWRologC()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x0A && m_dwAEPMapped == 0x15B98 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x16000)
	{
        TCHAR  pbyHLLWRologCSig[] = {_T("5C73734576744D67722E657865*433A5C7E54656D702E646F63*433A5C7E54656D702E646F63")};

		if (CheckSigInBuffer(0x16600,0x160,pbyHLLWRologCSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.Rolog.c"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLWRandir
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Tushar Kadam + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLW.Randir
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectHLLWRandir()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x0A && m_dwAEPMapped == 0x15B98 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x16000)
	{
        TCHAR  pbyHLLWRandirSig[] = {_T("5B57696E33322E484C4C572E52616E446972*202863292062792044756B652F534D465D")};

		if (CheckSigInBuffer(0x9DA8,0x58,pbyHLLWRandirSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLW.Randir"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectWLKSM
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: ANiket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.WLKSM.A
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectWLKSM()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec !=0x0 && m_pSectionHeader[m_wAEPSec].PointerToRawData != 0x0400 && m_pSectionHeader[m_wAEPSec].PointerToRawData != 0x1000 && (m_pSectionHeader[m_wAEPSec].Misc.VirtualSize != m_pSectionHeader[m_wAEPSec].SizeOfRawData))		// Primary Checks
		return iRetStatus;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	const int WLKSM_BUFF_SIZE = 0x1E;
	m_pbyBuff = new BYTE[WLKSM_BUFF_SIZE];
	
	if(GetBuffer(m_dwAEPMapped + 0x014,WLKSM_BUFF_SIZE,WLKSM_BUFF_SIZE))
	{

		DWORD dwLength = 0;
		t_disasm da = {0};
		int iInstructionNo = 0;

		DWORD dwOffset=0;

		while(dwOffset<0x1E)
		{
			dwOffset=dwOffset+dwLength;

			dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE); 



			if(dwLength == 0x2 && iInstructionNo == 0x0 && strstr(da.result, "PUSH 40"))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x5 && iInstructionNo == 0x1 && strstr(da.result,"PUSH 1000"))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x7 && iInstructionNo == 0x2 && strstr(da.result, "LEA ECX,[EBX*4+4]"))
			{
				iInstructionNo++;
				continue;
			}

			else if(dwLength == 0x1 && iInstructionNo == 0x3 && strstr(da.result, "PUSH ECX"))
			{
				iInstructionNo++;
				continue;
			}

			else if(dwLength == 0x2 && iInstructionNo == 0x4 && strstr(da.result, "PUSH 0"))
			{
				iInstructionNo++;
				continue;
			}

			else if(dwLength == 0x2 && iInstructionNo == 0x5 && strstr(da.result, "CALL EAX"))
			{
				iInstructionNo++;
				continue;
			}

			else if(dwLength == 0x2 && iInstructionNo == 0x6 && strstr(da.result, "MOV ECX,EBX"))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x3 && iInstructionNo == 0x7 && strstr(da.result, "MOV EBX,"))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x2 && iInstructionNo == 0x8 && strstr(da.result, "XOR EBX,EDI"))
			{
				iInstructionNo++;
				continue;
			}
			else if(dwLength == 0x3 && iInstructionNo == 0x9 && strstr(da.result,"MOV [EAX+ECX*4],EBX"))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.WLKSM.a"));
				return VIRUS_FILE_DELETE;
			}
		}
	}

	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DetectFontraA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Fontra.A
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectFontraA()
{
	int iRetStatus = VIRUS_NOT_FOUND;	

	if(m_wAEPSec == 0x04 || m_wAEPSec == 0x03 && m_wNoOfSections == 0x6 || m_wNoOfSections == 0x05 || m_wNoOfSections == 0x07 && (m_dwAEPMapped == 0x44000 || m_dwAEPMapped == 0xD000) && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x4000 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x37B1 && memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".psu", 7) == 0) 
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		DWORD dwBufferReadOffset = m_dwAEPMapped+0x61C;
		const int	FONTRA_BUFF_SIZE = 0x500;
		m_pbyBuff = new BYTE[FONTRA_BUFF_SIZE];

		if(GetBuffer(dwBufferReadOffset, FONTRA_BUFF_SIZE, FONTRA_BUFF_SIZE))
		{
			DWORD j = 0x31;
			for(DWORD i = 0x00; i < 0x500; i++)
			{
			   *(byte*)&m_pbyBuff[i] = *(byte*)&m_pbyBuff[i]^j;

			}
			TCHAR			FontraA_Sig[] = {_T("633a5c00483240337325264b326b32*336a4068736439382164660025*00000047006e00750063006c0065007500730000004d006f0072*0070006800650075007300000049006e0066*0065006300740069006e0067003a000000430061*006e006e006f00740020006f00700065006e00000041006c")};
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(FontraA_Sig, _T("Virus.Win32.Fontra.a"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0],FONTRA_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectCargo
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Cargo
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectCargo()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x04 && m_dwAEPMapped == 0x600 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x3000)
	{
		TCHAR  CargoSig[] = {_T("436172676F202843292031393939204C6F7264204A756C7573*497320746869732066756E2C206F7220776861743F*4865617679204D6574616C2072756C65732121*5C6F677261632E65786500636172676F006F6772616300000040")};

		if (CheckSigInBuffer(0x1AC1,0x340,CargoSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Cargo.11935"));
			return VIRUS_FILE_DELETE;
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectLamerKL
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Lamer.KL
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectLamerKL()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wNoOfSections == 0x08 && m_dwAEPMapped == 0x0600  && m_dwAEPUnmapped == 0x1000 && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xF400 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xFA00))
	{
		DWORD dwReadBuffer = m_pSectionHeader[m_wAEPSec].SizeOfRawData + 0x777;

        TCHAR  pbyLamerKLSig[] = {_T("433A5C536572766963655C536572766963652E657865*433A5C536572766963655C6461742E646174*687474703A2F2F7777772E646F6A6B692E636F6D2F*687474703A2F2F7879752E74762F*48656C6C6F206D7920667269656E64212121204D79206E616D652069*73204665646F742E2049276D20626F7265642C206C65742773206861766520736F6D652066756E3F*4665646F740053454E44202573202573002A004D6179626520736F6D6520626565723F203A2D29")};

		if (CheckSigInBuffer(dwReadBuffer,0x1DF,pbyLamerKLSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Lamer.kl"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectLevi
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Levi.3244
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectLevi()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x04 && m_dwAEPMapped == 0x600 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1E00)
	{
		TCHAR  LeviSig[] = {_T("57696E33322E4C657669617468616E2028632920313939392062792042656E6E79*4865792073747570696420210D0D5468697320697320676F6E6E612062*6520796F7572206E696768746D6172652E2E2E0D333074682067656E65726174*696F6E206F66204C657669617468616E20697320686572652E2E2E20626577617265206F66206D652021")};

		if (CheckSigInBuffer(0x1121,0x100,LeviSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Levi.3244"));
			return VIRUS_FILE_DELETE;
		}

	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectSantana
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Santana.1104
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectSantana()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections -1 && m_wNoOfSections == 0x04 || m_wNoOfSections == 0x05  &&  m_dwAEPMapped == 0xE00 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x650)
	{
		if(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress == 0x3000 || m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress == 0x40000 )

		{
			if (CheckSigInBuffer(m_dwAEPMapped,0x450,_T("E8320400008E*605581ED05004200EBCF0000000068*7AF7")))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Santana.1104"));
				return VIRUS_FILE_DELETE;
			}
		}
	}

	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVBCS
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.CS
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBCS()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x10D8 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5000)
	{
        TCHAR  pbyVBCSSig[] = {_T("200020002000480065006C006C006F002E002E002E00210021002100200041006B007500200056004900520055005300200042004C0041004E0047004B004F004E002E002E002E0021002100210000*6E0065007400530065006E0064002E0065007800650000")};

		if (CheckSigInBuffer(0x3440,0xFF,pbyVBCSSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.cs"));
			return VIRUS_FILE_DELETE;
		}
		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBBT
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.W32.VB.BT
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBBT()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x0BC0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x19000)
	{
		TCHAR pbyvbsign[] = {_T("F88D400000F8320000FFFFFF08*288C4000EC8B4000CC1740*636F6E74656E65646F72*636F6E74656E65646F72*5C00560042005C004800410043004B")};

		if(CheckSigInBuffer(0x8190, 0x100, pbyvbsign))
		{
			_tcscpy_s(m_szVirusName,MAX_VIRUS_NAME, _T("VIRUS.W32.VB.BT"));

			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBCM
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.W32.VB.BT
--------------------------------------------------------------------------------------*/
int CNonRepairable ::DetectVBCM()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x10C4 && m_pSectionHeader[0].SizeOfRawData == 0x3000)
	{
		if(CheckSigInBuffer(0x1190, 0x100, _T("BC124000C812400000F8300000FFFFFF08*1C1140000C114000D010400078")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.VB.CM"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBCR
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.W32.VB.CR
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBCR()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x152C && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x6000)
	{
		TCHAR pbyvbsign[] = {_T("501C400000F8300000FFFFFF08*F01A4000A41A40003815400078*6261726167617A756C31*6261726167617A756C31")};

		if(CheckSigInBuffer(0x1BE0, 0x100, pbyvbsign))
		{
			_tcscpy_s(m_szVirusName,MAX_VIRUS_NAME, _T("Virus.W32.VB.CR"));

			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBGP
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.W32.VB.GP
--------------------------------------------------------------------------------------*/
int CNonRepairable ::DetectVBGP()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x173C && m_pSectionHeader[0].SizeOfRawData == 0xA000)
	{
		if(CheckSigInBuffer(0x4E40, 0x100, _T("C04E400004F1340000FFFFFF08*E9000000C84D4000B84D4000481740*4669726577616C6C*4D6963726F736F6674416C6C46696C654669726577616C6C*706A7442696E646572")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.VB.GP"));

			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVBK
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.W32.VB.K
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBK()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x13D0 && m_pSectionHeader[0].SizeOfRawData == 0x5000)
	{
		if(CheckSigInBuffer(0x2680, 0x100, _T("F42640000AF8300000FFFFFF08*4825400008254000DC13400078*5365786F21212121*50726F796563746F31")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.VB.K"));
			return VIRUS_FILE_DELETE;
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBLP
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.W32.VB.LP
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBLP()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x10BC && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x9000)
	{
		TCHAR pbyvbsign[] = {_T("2C24400000F8300000FFFFFF08*3C214000EC204000C810400078*7733322E566972476561722E4D756C74696D65646961")};
		if(CheckSigInBuffer(0x21B0, 0x100, pbyvbsign))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.VB.LP"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectLevi3205
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Levi.3205
--------------------------------------------------------------------------------------*/
int CNonRepairable ::DetectLevi3205()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x04 && m_dwAEPMapped == 0x0600 && m_pSectionHeader[0].SizeOfRawData == 0x1E00)
	{
		if(CheckSigInBuffer(0x750 , 0x100, _T("57696E39382E4D696C656E6E69756D2062792042656E6E792F32394100*4669727374206D756C746966696265722076697275732069732068657265*2C20626577617265206F66206D652021203B2D290D436C69636B204F4B20*696620752077616E6E612072756E20746869732073686974")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Levi.3205"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectPesinA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Pesin.A
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectPesinA()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x09 && m_dwAEPMapped == 0xB800 && m_pSectionHeader[0].SizeOfRawData == 0x9E00 && (memcmp(m_pSectionHeader[m_wAEPSec].Name, ".aspack", 7) == 0) && (memcmp(m_pSectionHeader[m_wAEPSec - 8].Name, "CODE FMX", 8) == 0))
	{
		if(CheckSigInBuffer(0xC370, 0x100, _T("8B8B600200008A143102D0*80E20F8854342446")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Pesin.a"));

			return VIRUS_FILE_DELETE;
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSalityATBH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.WIN32.Sality.atbh
--------------------------------------------------------------------------------------*/
int CNonRepairable ::DetectSalityATBH()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x33A746 && m_pSectionHeader[0].SizeOfRawData == 0x000)
	{
		if(CheckSigInBuffer(0x33E30 , 0x100, _T("7A496E7465726E2E20446F776E6C6F6164204D616E61672676DB*6D452E636F6D006361731A6F76612F694F5441003237B06CE3FF2D30322D32303132*66697273BA646179")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.WIN32.Sality.atbh"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectVBC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.C
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBC()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x143C && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xA000)
	{
		TCHAR pbyVBsig[] = {_T("10894000D018400052F830*941540008C1440004814400078*4163746976654465736B746F70*4163746976654465736B746F70")};
		if(CheckSigInBuffer(0x1660, 0xC0, pbyVBsig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.C"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectXbotor
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Xbotor
--------------------------------------------------------------------------------------*/
int CNonRepairable ::DetectXbotor()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x071E && m_pSectionHeader[0].SizeOfRawData == 0x600)
	{
		if(CheckSigInBuffer(0x5C0, 0x100, _T("5C00500032005000001D64006F0074006E00650074*006800610063006B002E006500780065*2D780062006F00780064006F0074006E006500740065006D0075006C00610074*006F0072002E006500780065")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Xbotor"));
			return VIRUS_FILE_DELETE;
		}

	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: DetectMezq
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Mezq
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectMezq()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x1B20 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x12000)
	{
		TCHAR  pbyMezqSig[] = {_T("2C45400000F8300000FFFFFF08*E900000050444000484440002C1B4000780000007E*78736B2E52*78736B2E52*736F6674")};

		if (CheckSigInBuffer(0x44D0,0xE0,pbyMezqSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Mezq"));
			return VIRUS_FILE_DELETE;
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectProjet2649
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Projet.2649
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectProjet2649()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
   
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x600 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x0C00)
	{
        TCHAR  pbyPROJECTSig[] = {_T("C685D5184000018B85D118400066C740384141BF00000000*B928000000F7E183C678*834E2420814E2400000020814E2400000080")};

		if (CheckSigInBuffer(0x0C00,0xE0,pbyPROJECTSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Projet.2649"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSmallN
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Small.n
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectSmallN()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x05 && m_dwAEPMapped == 0x400 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2A00)
	{
		TCHAR  pbySmallNSig[] = {_T("496E66656374696E6720272573272E2E2E20*2863757272656E742066696C653A20257329*636F7079202F422022257322202F422022257322202F59*72656E20257325732E6578652025732E6F6D66")};

		if (CheckSigInBuffer(0x6A0 ,0x690,pbySmallNSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Small.n"));
			return VIRUS_FILE_DELETE;
		}

	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBBC
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.BC
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBBC()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x13A4 && m_pSectionHeader[0].SizeOfRawData == 0xB000)
	{
		if(CheckSigInBuffer(0x7980, 0X1000, _T("E879400002F8300000FFFFFF08*A078400060784000B013400078*546865205465737420736572766572*2F0065006E00640020006F00660020006C006900660065002E007400780074")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.BC"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBBG
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.BG
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBBG()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x1E34 && m_pSectionHeader[0].SizeOfRawData == 0x1B000)
	{
		if(CheckSigInBuffer(0x3DD0, 0x100, _T("E842400000F8300000FFFFFF0800000001*543D40003C3C4000401E400078*746F6C6F6E67206A616E67616E20646962756B61")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.BG"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBhq
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.HQ
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBhq()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x2200 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x28000)
	{
		TCHAR  pbyVBhqSig[] = {_T("441F4200CC26400016F9300100FFFFFF08*8C254000482240000C2240007800000088*76697275732062617275206C616769003424680000617368*0043003A005C00760069007200750073005C00610073006800*5C006100730068002E007600620070")};

		if (CheckSigInBuffer(0x2410,0x340,pbyVBhqSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.HQ"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBU
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.U
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBU()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x1570  && m_dwAEPMapped == m_dwAEPUnmapped &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x7000)
	{
		TCHAR  pbyVBUSig[] = {_T("2039400000F0300000FFFFFF080000000100000001000000E9*EC364000E43640007C15400078000000810000008A*6578706C6F726572*6578706C6F723372")};
		if (CheckSigInBuffer(0x3760,0xE0,pbyVBUSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.U"));
			return VIRUS_FILE_DELETE;
		}	
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectXorerBH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Xorer.BH
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectXorerBH()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x0560 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2600)
	{
		TCHAR  pbyXorerBHSig[] = {_T("681B400000F8300000FFFFFF08*C8184000B81840006C134000780000007D*736D7373*736D7373")};

		if (CheckSigInBuffer(0xB40,0xA8,pbyXorerBHSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Xorer.BH"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectXorerEA
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Xorer.EA
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectXorerEA()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x0560 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2600)
	{
		TCHAR  pbyXorerEASig[] = {_T("681B400000F8300000FFFFFF08*C8184000B81840006C134000780000007D*736D7373*736D7373")};
		if (CheckSigInBuffer(0xB40,0xA8,pbyXorerEASig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Xorer.EA"));
			return VIRUS_FILE_DELETE;
		}		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAgentCH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Aniket + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Agent.ch
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectAgentCH()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x07 && m_dwAEPMapped == 0x8E84 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x9000)
	{
		TCHAR  pbyAgentCHSig[] = {_T("8B45FCE896ECFFFF8B55F88A541AFF0FB7CFC1E90832D1*885418FF8B45F80FB64418FF6603F86669C76DCE6605BF588BF8434E75CB")};
		if (CheckSigInBuffer(0x39E0,0xE0,pbyAgentCHSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Agent.ch"));
			return VIRUS_FILE_DELETE;
		}		
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectAgentCH
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.WIN32.HLLO.Momac.a
--------------------------------------------------------------------------------------*/
int CNonRepairable :: DetectHLLOMomacA()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0xA && m_pSectionHeader[0].SizeOfRawData == 0x2200 && memcmp(m_pSectionHeader[m_wNoOfSections-1].Name, ".rebld_i", 8) == 0 && memcmp(m_pSectionHeader[m_wNoOfSections-2].Name, ".rebld_rh", 9) == 0)
	{
		if(CheckSigInBuffer(0x1F10, 0x100, _T("2D2D2D2D206D4F43414D202D2D2D2D*633A5C70726F6772616D2066696C65735C6B617A6161*5C6D792073686172656420666F6C6465725C")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.WIN32.HLLO.Momac.a"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectHLLP41472e
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.HLLP.41472.e
--------------------------------------------------------------------------------------*/
int CNonRepairable ::DetectHLLP41472e()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x08 && m_dwAEPMapped == 0x74E4 && m_pSectionHeader[0].SizeOfRawData == 0x7400)
	{
		if(CheckSigInBuffer(0x1CB0 , 0x100, _T("66A1189040006625C0FF668B55F86683*E23F660BC266A3189040008BE55DC3")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.HLLP.41472.e"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSantana1104
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sagar + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Santana.1104
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectSantana1104()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x4 && m_wAEPSec == 0x03 && m_dwAEPUnmapped == 0x4200 && m_dwAEPMapped ==0xe00 &&
		m_pSectionHeader[m_wAEPSec].PointerToRawData == 0xc00 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x650 &&
		m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x5000 && m_pSectionHeader[m_wAEPSec].VirtualAddress == 0x4000 &&
		(memcmp(m_pSectionHeader[m_wNoOfSections-2].Name, ".idata", 5) == 0))
	{
		if(CheckSigInBuffer(0xe30, 0x50,_T("A558437EDD9CBB4726DB5D1C5B25AD1E*D765A0DB69BCEE9970F56A56D3A2C0A4*7F99AD4FDD46429F07FD7FDB18AD274E*07EB6D8BA1E3EFD7699E4FB3263D5E85")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Santana.1104"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBEL
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sneha + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.EL
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBEL()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x05 && m_dwAEPMapped == 0x14E4 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5000)
	{
		TCHAR  pbyVBELSig[] = {_T("741B400000F8300000FFFFFF08*A01A4000701A4000F0144000780000007B*766D004B6F4B6F*5C0041005F00560069007200750073005F004B006F004B006F00")};
		if (CheckSigInBuffer(0x1B20,0x120,pbyVBELSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.EL"));
			return VIRUS_FILE_DELETE;
		}	
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectVBEY
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sagar + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.VB.ey
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectVBEY()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x3 && m_wAEPSec == 0x00 && m_dwAEPUnmapped == 0x1764 && m_dwAEPMapped ==m_dwAEPUnmapped &&
		m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x1000 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x25000 &&
		m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x24950 && m_pSectionHeader[m_wAEPSec].VirtualAddress == 0x1000 &&
		(memcmp(m_pSectionHeader[m_wNoOfSections-2].Name, ".data", 5) == 0))
	{
		if(CheckSigInBuffer(0x1ba90,0x60,_T("5C0052006F006E0074006F006B00420072006F002E0065007800650000*5C00730079007300740065006D00330032005C0052006F*006E0074006F006B00420072006F002E006500780065")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.EY"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}     

/*-------------------------------------------------------------------------------------
	Function		: DetectXorerei
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sagar + Virus Team
	Description		: Detection routine for malwares : Virus.Win32.Xorer.ei
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectXorerei()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x5 && m_wAEPSec == 0x00 && m_dwAEPUnmapped == 0x5af && m_dwAEPMapped ==m_dwAEPUnmapped &&
		m_pSectionHeader[m_wAEPSec].PointerToRawData == 0x300 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x480 &&
		m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x450 && m_pSectionHeader[m_wAEPSec].VirtualAddress == 0x300 &&
		(memcmp(m_pSectionHeader[m_wNoOfSections-2].Name, ".rsrc", 5) == 0))
	{
		if(CheckSigInBuffer(0x380, 0x50,_T("453A5C44444B5C646464325C4472697665725C6F626A6672655C*693338365C646464322E706462*0068AC030100E834030000598B4C240883611800")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Xorer.ei"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: DetectSmalli
	In Parameters	: 
	Out Parameters	: Status : VIRUS_NOT_FOUND or VIRUS_FILE_DELETE or VIRUS_FILE_REAPIR
	Purpose			: 
	Author			: Sagar + Virus Team
	Description		: Detection routine for malwares : Virus.Small.I
--------------------------------------------------------------------------------------*/
int CNonRepairable::DetectSmalli()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections >= 0x3 && m_wAEPSec >= 0x02)
	{
		if(CheckSigInBuffer((m_dwAEPMapped-0xF0F),0x80,_T("687474703A2F2F76677561726465722E3931692E6E65742F757365722E68746D*687474703A2F2F76677561726465722E6272617665686F73742E636F6D2F757365722E68746D")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("virus.small.i"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}


