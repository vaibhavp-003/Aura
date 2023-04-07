/*======================================================================================
FILE				: SemiPoly.cpp
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
CREATION DATE		: 12 Jun 2013
NOTES				: This is detection module for malware using * base detection pattern.
					  Aho-corasick binary seraching is used to fasten the detection 
					  It is the collection of different malwares for which we use Aho-corasick 
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "SemiPoly.h"
#include "SemiPolyDBScn.h"
#include "MaxBMAlgo.h"
#include "PolymorphicVirus.h"


/*-------------------------------------------------------------------------------------
	Function		: CPolyDeemo
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDeemo::CPolyDeemo(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDeemo
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDeemo::~CPolyDeemo(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Deemo Family
--------------------------------------------------------------------------------------*/
int CPolyDeemo::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, "UPX", 3) == 0 && m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xE0000020 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 3000) ||
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xE2000060 && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData >= 0x2000)))
	{		
		if(GetPatchedCalls(m_dwAEPMapped, m_dwAEPMapped + 0x1000, m_wNoOfSections - 1))
		{
			TCHAR Deemo3253_Sig[] ={ _T("00005D8B7C2424B9050000002BF9897C24248DB5A40C0000F3A48D95A90C0000*E8030C00007533E8D00B00008985BE0C000089ADA000000033C050545055E802*88D9E8E4080000FFD058619DC38B6C2404E8DE0B00008985C20C00008D9D9E00*47FC3D4558450074193D6578650074123D72637300740B3D524353000F859702")};
			TCHAR Deemo_Sig[] = {_T("45584500741A3D6578650074133D72637300740C3D5243530074*394B45524E740881396B65726E7512817904454C333274*464668646C6541686548616E686F64756C684765744D")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(Deemo3253_Sig, _T("Virus.Deemo.3253"), TRUE);
			polydbObj.LoadSigDBEx(Deemo_Sig, _T("Virus.Deemo"), FALSE);

			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}

			const int DEEMO_BUFF_SIZE = 0x500;
			m_pbyBuff = new BYTE[DEEMO_BUFF_SIZE];
			DWORD dwVirusStartOffset = 0;
			TCHAR szVirusName[MAX_PATH] = {0};
			LPVOID lpPos = m_arrPatchedCallOffsets.GetHighest();
			while(lpPos)
			{
				m_arrPatchedCallOffsets.GetKey(lpPos, dwVirusStartOffset);
				m_arrPatchedCallOffsets.GetData(lpPos, m_dwOriPatchOffset);
				if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwVirusStartOffset, &m_dwCallAddr))
				{
					return iRetStatus;
				}
				if(GetBuffer(m_dwCallAddr, DEEMO_BUFF_SIZE, DEEMO_BUFF_SIZE))
				{
					if(m_pbyBuff[0] == 0)
					{
						lpPos = m_arrPatchedCallOffsets.GetHighestNext(lpPos);
						continue;
					}
					if(polydbObj.ScanBuffer(&m_pbyBuff[0], DEEMO_BUFF_SIZE, szVirusName) >= 0)
					{
						if(_tcslen(szVirusName) > 0)
						{
							if(_tcsstr(szVirusName,_T("Virus.Deemo.3253")))
							{
								iRetStatus = VIRUS_FILE_REPAIR;
							}
							else if(_tcsstr(szVirusName, _T("Virus.Deemo")))
							{
								iRetStatus = VIRUS_FILE_DELETE;
							}
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							break;
						}
					}
				}
				lpPos = m_arrPatchedCallOffsets.GetHighestNext(lpPos);
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Deemo Family
--------------------------------------------------------------------------------------*/
int CPolyDeemo::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	m_dwCallAddr += 0xCAC;
	if(GetBuffer(m_dwCallAddr, 4, 4))
	{
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0], m_dwOriPatchOffset + 1, 4, 4))
		{
			if(m_pMaxPEFile->RemoveLastSections())
			{
				iRetStatus = REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolyLamer
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyLamer::CPolyLamer(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalFileOffset = 0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyLamer
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyLamer::~CPolyLamer(void)
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
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Lamer Family (Prepender)
					  Virus.W32.Lamer.es,Virus.W32.Lamer.fx,Virus.W32.Lamer.hk,Virus.W32.Lamer.cw
--------------------------------------------------------------------------------------*/
int CPolyLamer::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_dwAEPMapped == 0x3498 && m_wNoOfSections == 0x8 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x3200)
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int	LAMERFV_BUFF_SIZE = 0x30;
		m_pbyBuff = new BYTE[LAMERFV_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		if(GetBuffer(0x2F9C, LAMERFV_BUFF_SIZE, LAMERFV_BUFF_SIZE))
		{
			TCHAR szLamerFVSig[] = {_T("7E284D7565726520426162796C6F6E20*5B4A4148204348494C4452454E5D204D7565726520426162796C6F6E297E")};
										//~(Muere Babylon [JAH CHILDREN] Muere Babylon)~
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(szLamerFVSig, _T("Virus.W32.Lamer.fv"), FALSE);
           
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], LAMERFV_BUFF_SIZE, szVirusName) >= 0)
			{
				if(m_pbyBuff)
				{
					delete m_pbyBuff;
					m_pbyBuff = NULL;
				}
				m_pbyBuff = new BYTE[0x7];
				if(!m_pbyBuff)
				{
					return iRetStatus;
				}

				if(!GetBuffer(m_pMaxPEFile->m_dwFileSize - 0x7,0x7,0x7))  // getting original size from end of file
				{
					return iRetStatus;
				}
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				}
				int j =0;						
				for( j = 0; j<0x7;j++)      // skiping zero
				{
					if(m_pbyBuff[j] != 0)
					{
						break;
					}
				}
				if(j==0)						// if original file size is not end of file deleting file
				{
					return VIRUS_FILE_DELETE;
				}

				unsigned int	m_iBufferSize = 0;
				char szFilesizeBuff[0x7], *szDummmy = NULL ;
				int i =0;
				m_dwOriginalFileOffset = j -1;
				for( i = 0; i < 0x7, j<0x7; i++,j++)				// bytes to string (file size)
				{
					sprintf(szFilesizeBuff + i,"%c",m_pbyBuff[j]);
				}

				m_dwOriginalFileSize = strtol(szFilesizeBuff,&szDummmy,10);
				m_dwOriginalFileOffset	= m_pMaxPEFile->m_dwFileSize - (m_dwOriginalFileSize + 7) + m_dwOriginalFileOffset;
			    return VIRUS_FILE_REPAIR;	   
		    }
	   }
	}

	if(m_wNoOfSections == 0x8 && m_dwAEPUnmapped == 0x15844 && m_wAEPSec == 0 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x14C00 )
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff	= new BYTE[0x20];

		const BYTE bySign[] = {0x8B,0x15,0x1C,0x76,0x41,0x00,0x33,0xC9,0x89,0x4C,0x82,0xF4,0x40,0x3D,0x01,0x04,0x00,0x00,0x75,0xEC};
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0xA3B,sizeof(bySign),sizeof(bySign)))
		{
			if(memcmp(&m_pbyBuff[0],bySign,sizeof(bySign))== 0)
			{
				const BYTE bySign1[] = {0xB8,0x13,0x00,0x00,0x00,0x81,0xC4,0x04,0xF0,0xFF,0xFF,0x50,0x48,0x75,0xF6,0x8B,0x45,0xFC,0x81,0xC4,0xDC,0xF3,0xFF,0xFF};
				if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x838,sizeof(bySign1),sizeof(bySign1)))
				{
					if(memcmp(&m_pbyBuff[0],bySign1,sizeof(bySign1)))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Lamer.es"));
						if(!GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x129BA, 0x4, 0x4))
						{
							return iRetStatus;
						}

						m_dwOriginalFileOffset = *(DWORD *)&m_pbyBuff[0];

						WORD	byCheckMz = 0x0;
						if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwOriginalFileOffset,0x2,0x2))
						{
							return VIRUS_FILE_DELETE;
						}
						else if(byCheckMz == 0x5A4D)
						{
							return VIRUS_FILE_REPAIR;
						}
						else
						{
							return VIRUS_FILE_DELETE;
						}
					}
				}
			}
		}
	}
	
	if(m_dwAEPUnmapped == 0x4384 && m_wNoOfSections == 0x6 && m_wAEPSec == 0x0 &&
		m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData == 0x0)
	{
		const int LAMER_BUFF_SIZE = 0x2400;
		if(m_pbyBuff)
		{			
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[LAMER_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x1F88, 0x30, 0x30))
		{
			TCHAR	szLAMERFX_SIG[] = {_T("C7052060400048E70000B8D8304000A318604000807D0800*7412BA002400008D85B4BDF0FF80307B404A75F96A")};

			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(szLAMERFX_SIG, _T("Virus.Lamer.FX"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], LAMER_BUFF_SIZE, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				if(!GetBuffer(m_pMaxPEFile->m_dwFileSize - LAMER_BUFF_SIZE, LAMER_BUFF_SIZE, LAMER_BUFF_SIZE))
				{
					return VIRUS_FILE_DELETE;
				}
				if((*(WORD *)&m_pbyBuff[0] ^ 0x7B7B) != 0x5A4D)
				{
					return VIRUS_FILE_DELETE;
				}
				for(int i = 0x0; i < 0x2400; i++)
				{
					m_pbyBuff[i] = m_pbyBuff[i] ^ 0x7B;
				}
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	if(m_wNoOfSections == 0x05 &&  m_wAEPSec == 0x00 && 
		(m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData ==  0x200 || m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData ==  0x1400)  && 
		(m_pSectionHeader[m_wNoOfSections -2].Misc.VirtualSize == 0x1B4 || m_pSectionHeader[m_wNoOfSections -2].Misc.VirtualSize == 0x1300))
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}
	
	
		DWORD dwReadOffset = m_pMaxPEFile->m_stPEHeader.DataDirectory[6].VirtualAddress + m_pMaxPEFile->m_stPEHeader.DataDirectory[6].Size - 4;
		if(m_pMaxPEFile->Rva2FileOffset(dwReadOffset,&dwReadOffset))
		{
			if(m_pMaxPEFile->ReadBuffer(&dwReadOffset,dwReadOffset,0x4,0x4))
			{
				DWORD		dwBuff_Start = dwReadOffset - 0x368;
				const int	LAMERHK_BUFF_SIZE = 0x395;
				
				m_pbyBuff = new BYTE[0x395];

				if(!m_pbyBuff)
				{
					return iRetStatus;
				}
				if(GetBuffer(dwBuff_Start, LAMERHK_BUFF_SIZE, LAMERHK_BUFF_SIZE))
				{
					TCHAR			szLamerHKSig[] = {_T("536F6674776172655C4B61724E657400*50726F6A6563745F4B61726E656A")};//(Software\KarNet. * Project_Karnej)
					CSemiPolyDBScn	polydbObj;
					TCHAR			szVirusName[MAX_PATH] = {0};

					polydbObj.LoadSigDBEx(szLamerHKSig, _T("Virus.W32.Lamer.HK"), FALSE);
					if(polydbObj.ScanBuffer(&m_pbyBuff[0], LAMERHK_BUFF_SIZE, szVirusName) >= 0)
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
	}


	if(m_dwAEPUnmapped == 0x1C9C && m_wNoOfSections == 0x3 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xE000)
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int	LAMERCW_BUFF_SIZE = 0x350;
		m_pbyBuff = new BYTE[LAMERCW_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		if(GetBuffer(m_dwAEPMapped + 0x19D0, LAMERCW_BUFF_SIZE, LAMERCW_BUFF_SIZE))
		{
			TCHAR szLamerCWSig[] = {_T("6D006C006D0079002E0033003300320032002E006F0072006700*7500700064006100740065002E007400780074*770069006E006C006F0067002E004500580045")};
			//.m.l.m.y...3.3.2.2...o.r.g*u.p.d.a.t.e...t.x.t*w.i.n.l.o.g...E.X.E
			
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(szLamerCWSig, _T("Virus.W32.Lamer.CW"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], LAMERCW_BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					m_dwOriginalFileOffset = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData - 0x2;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					if(!GetBuffer(m_dwOriginalFileOffset, 0x10, 0x10))
					{
						return VIRUS_FILE_DELETE;
					}
					DWORD	iIndex = 0x0;
					BYTE	byCheckMz[] = {0x4D, 0x5A}; //MZ
			
					if(OffSetBasedSignature(byCheckMz,sizeof(byCheckMz),&iIndex))
					{
						m_dwOriginalFileOffset += iIndex;
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	//////Alisha
	if(m_dwAEPMapped == 0x433C && m_wNoOfSections == 0x8 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x4200)
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int	LAMERK_BUFF_SIZE = 0x80;
		m_pbyBuff = new BYTE[LAMERK_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		if(GetBuffer(0x4460, LAMERK_BUFF_SIZE, LAMERK_BUFF_SIZE))
		{
			TCHAR szLamerKSig[] = {_T("534146454D4F4445*5468697320574F524D2069732064657369676E6564*536166657479476174652E7275")};

			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};

			polydbObj.LoadSigDBEx(szLamerKSig, _T("Virus.W32.Lamer.k"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], LAMERK_BUFF_SIZE, szVirusName) >= 0)
			{

				if(m_pbyBuff)
				{
					delete m_pbyBuff;
					m_pbyBuff = NULL;
				}
				m_pbyBuff = new BYTE[0x9];
				if(!m_pbyBuff)
				{
					return iRetStatus;
				}

				if(!GetBuffer(m_pMaxPEFile->m_dwFileSize - 0x9,0x9,0x9))  // getting original size from end of file
				{
					return iRetStatus;
				}
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				}
				int j =0;						
				for( j = 0; j<0x9;j++)     
				{
					if(m_pbyBuff[j] == 0x2)
						break;
				}
				m_dwOriginalFileOffset = j;
				j++;

				unsigned int	m_iBufferSize = 0;
				char szFilesizeBuff[0x9], *szDummmy = NULL ;
				int i =0;
				for( i = 0; i < 0x8, j<0x8; i++,j++)				// bytes to string (file size)
				{
					sprintf(szFilesizeBuff + i,"%c",m_pbyBuff[j]);
				}

				m_dwOriginalFileSize = strtol(szFilesizeBuff,&szDummmy,10);

				m_dwOriginalFileOffset	= m_pMaxPEFile->m_dwFileSize - m_dwOriginalFileSize - 0x13 - i;
				return VIRUS_FILE_REPAIR;
			}
		}
	}

	//Tushar ==> Virus.Win32.Lamer.KN
	if(m_dwAEPUnmapped == 0x1D58 && m_wNoOfSections == 0x4 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x7400)
	{
		if(m_pbyBuff)
		{
			delete m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int	LAMERCW_BUFF_SIZE = 0x50;
		m_pbyBuff = new BYTE[LAMERCW_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}

		if(GetBuffer(0x7494, LAMERCW_BUFF_SIZE, LAMERCW_BUFF_SIZE))
		{
			BYTE  byLamerKNSig[] = {0x69, 0x6E, 0x66, 0x65, 0x63, 0x74, 0x20, 0x25, 0x73, 0x0A, 0x00, 0x00, 0x2E, 0x45, 0x58, 0x45};	
			//infect %s....EXE

			if(memcmp(&m_pbyBuff[0],byLamerKNSig,sizeof(byLamerKNSig)) == 0x00)
			{
				BYTE	byCheckMz[] = {0x4D, 0x5A}; //MZ
				DWORD	iIndex = 0x00;

				m_dwOriginalFileOffset = 0xC200;
				_tcscpy(m_szVirusName, _T("Virus.Win32.Lamer.KN"));
				if(!GetBuffer(m_dwOriginalFileOffset, 0x10, 0x10))
				{
					return VIRUS_FILE_DELETE;
				}
				if(OffSetBasedSignature(byCheckMz,sizeof(byCheckMz),&iIndex))
				{
					return VIRUS_FILE_REPAIR;
				}
				else
				{
					return VIRUS_FILE_DELETE;
				}
			}
		}			
	}

	//Tushar ==> Virus.Win32.Lamer.KO (Virus Patch 98)
	//Modified by Sagar Bade on 16 Nov 2018
	if(m_dwAEPUnmapped == 0x9623 && m_wNoOfSections == 0x4)
     {
           DWORD VarOffset=0x0;
           if(m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1b000) //condition added
           {
                VarOffset=0x212D0;
           }
           else {
                  VarOffset=0X206D0;
           }
           if (m_pMaxPEFile->m_dwFileSize > 0x20750)
           {
                if(m_pbyBuff)
                {
                     delete m_pbyBuff;
                     m_pbyBuff = NULL;
                }

                const int  LAMERKO_BUFF_SIZE = 0x50;
                m_pbyBuff = new BYTE[LAMERKO_BUFF_SIZE];
                if(!m_pbyBuff)
                {
                     return iRetStatus;
                }

                
                if(GetBuffer(VarOffset, LAMERKO_BUFF_SIZE, LAMERKO_BUFF_SIZE))
                {
                     BYTE  byLamerKOSig[] = {0x33, 0x36, 0x30, 0x5C, 0x33, 0x36, 0x30, 0x53, 0x61, 0x66, 0x65, 0x5C, 0x64, 0x65, 0x65, 0x70};    
                     //infect %s....EXE

                     if(memcmp(&m_pbyBuff[0],byLamerKOSig,sizeof(byLamerKOSig)) == 0x00)
                     {
                           BYTE byCheckMz[] = {0x4D, 0x5A}; //MZ
                           DWORD iIndex = 0x00;

                           m_dwOriginalFileOffset = 0x3FB20;
                           _tcscpy(m_szVirusName, _T("Virus.Win32.Lamer.KO"));
                           if(!GetBuffer(m_dwOriginalFileOffset, 0x10, 0x10))
                           {
                                return VIRUS_FILE_DELETE;
                           }
                          if(OffSetBasedSignature(byCheckMz,sizeof(byCheckMz),&iIndex))
                           {
                                return VIRUS_FILE_REPAIR;
                           }
                           else
                           {
                                return VIRUS_FILE_DELETE;
                           }
                     }
                }          
           }
     }

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Lamer Family
--------------------------------------------------------------------------------------*/
int CPolyLamer::CleanVirus(void)
{	
	DWORD	dwOriginalFileSize;

	if(m_dwAEPUnmapped == 0x4384)
	{
		if(m_pMaxPEFile->CopyData(m_pSectionHeader[0].PointerToRawData + 0x4400, m_pSectionHeader[0].PointerToRawData + 0x2000, m_pMaxPEFile->m_dwFileSize - 0x4800))
		{
			if(m_pMaxPEFile->WriteBuffer(m_pbyBuff,0,0x2400,0x2400))
			{
				if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - 0x4800))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	if(m_dwAEPMapped == 0x3498 || m_dwAEPMapped == 0x433C)
	{
		if(m_pMaxPEFile->CopyData(m_dwOriginalFileOffset, 0, m_dwOriginalFileSize))
		{
			if(m_pMaxPEFile->ForceTruncate(m_dwOriginalFileSize))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	else
	{
		dwOriginalFileSize = m_pMaxPEFile->m_dwFileSize - m_dwOriginalFileOffset;
		if(m_pMaxPEFile->CopyData(m_dwOriginalFileOffset, 0, dwOriginalFileSize))
		{
			if(m_pMaxPEFile->ForceTruncate(dwOriginalFileSize))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMkar
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMkar::CPolyMkar(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwReplaceOffset = 0; 
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMkar
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMkar::~CPolyMkar(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Mkar Family
--------------------------------------------------------------------------------------*/
int CPolyMkar::DetectVirus(void)
{	
	int iRetStatus = VIRUS_NOT_FOUND;
	const int MKAR_BUFF_SIZE = 0x200;	
	TCHAR szVirusName[MAX_PATH] = {0};
	CSemiPolyDBScn polydbObj;

	if((memcmp(m_pSectionHeader[0].Name, "UPX0", 4) == 0) && m_pSectionHeader[0].SizeOfRawData == 0 && m_pSectionHeader[1].PointerToRawData == 0x400)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		m_pbyBuff = new BYTE[MKAR_BUFF_SIZE];
		if(GetBuffer((m_pSectionHeader[1].PointerToRawData + 0x3064), MKAR_BUFF_SIZE, MKAR_BUFF_SIZE))
		{
			TCHAR Mkar_D[] = _T("43555808F9841559FB05DB652ADD5683609AAA*0CC83D9385*58CA8978F13542EDFF");
			TCHAR Mkar_E[] = _T("56B20CAF62B2112FD97861EF7B89CD10C605CD*30068453F6*5D3D913F03F233844A");
			TCHAR Mkar_G[] = _T("555808F9841559FB055683602EEF9A4A9AAAE9*06E4678537*428978F18D3C227525");
			polydbObj.LoadSigDBEx(Mkar_D, _T("Virus.Mkar.D"), TRUE);
			polydbObj.LoadSigDBEx(Mkar_E, _T("Virus.Mkar.E"), TRUE);
			polydbObj.LoadSigDBEx(Mkar_G, _T("Virus.Mkar.G"), FALSE);		

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], MKAR_BUFF_SIZE, szVirusName) >= 0)
			{ 
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
//Changes
	else if(m_wAEPSec != m_wNoOfSections - 1 && 
		   ((m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) ==  0x60000020 || (m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000080) ==  0xE0000080 || (m_pSectionHeader[m_wAEPSec].Characteristics & 0xE00000A0) ==  0xE00000A0) && //ADDED
		   m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData == 0x1000 || m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData == 0x400 || m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData == 0x200)
	{			
		DWORD dwReadOffset = m_pSectionHeader[m_wAEPSec + 2].PointerToRawData; 
		if(m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData == 0x400)
		{
			dwReadOffset = m_pSectionHeader[m_wAEPSec + 1].PointerToRawData + 0x3000;
		}
		else if(m_pSectionHeader[m_wAEPSec + 2].SizeOfRawData == 0x200)
		{
			dwReadOffset = m_pSectionHeader[m_wAEPSec + 1].PointerToRawData + 0x30C0; // ADDED
		}

		m_pbyBuff = new BYTE[MKAR_BUFF_SIZE];		
		if(GetBuffer(dwReadOffset, MKAR_BUFF_SIZE, MKAR_BUFF_SIZE))
		{
			const TCHAR MKAR_SIG[] = _T("6D72616B4D61696E576E64436C617373*6D72616B31*4D72616B317061636B");
			polydbObj.LoadSigDBEx(MKAR_SIG, _T("Virus.Mkar"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], MKAR_BUFF_SIZE, szVirusName) >= 0)
			{ 
				if(m_pMaxPEFile->ReadBuffer(&m_dwReplaceOffset, m_pMaxPEFile->m_dwFileSize - 0x8, 4, 4))
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					WORD	byCheckMz = 0x0;     // ADDED
					if(m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwReplaceOffset,0x2,0x2))
					{
						if(byCheckMz != 0x5A4D)
						{
							return VIRUS_FILE_DELETE;
						}
					}

					if(m_dwReplaceOffset > m_pMaxPEFile->m_dwFileSize || m_dwReplaceOffset == 0x00)
					{	
						return VIRUS_FILE_DELETE;
					}
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Mkar Family
--------------------------------------------------------------------------------------*/
int CPolyMkar::CleanVirus(void)
{	
	DWORD dwOriFileSize = m_pMaxPEFile->m_dwFileSize - m_dwReplaceOffset;
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0, dwOriFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(dwOriFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyTyhos
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTyhos::CPolyTyhos(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTyhos
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTyhos::~CPolyTyhos(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Tyhos Family
--------------------------------------------------------------------------------------*/
int CPolyTyhos::DetectVirus(void)
{
	const int TYHOS_BUFF_SIZE = 1000;

	if((m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint == 0x0154) && 
		(m_pSectionHeader[0].PointerToRawData == 0x0000) && 
		(m_pSectionHeader[0].Characteristics ==  0xC00000E0))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[TYHOS_BUFF_SIZE];
		if(GetBuffer((m_pSectionHeader[1].PointerToRawData + 0x3F00), TYHOS_BUFF_SIZE, TYHOS_BUFF_SIZE))
		{
			TCHAR szVirusName[MAX_PATH] = {0};
			TCHAR Tyhos_Sig[] = _T("63003A5C696E6465782E0E68746D6C0A3C06063E0D0A101065616487626F7379*2047484F5354592E3A4E45FB7F5D0C3D272D2C512FA24E0F312A7006A19A*43B0890067686F7374792E64CA8466CAACEF16F920F3740CC7510544");

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(Tyhos_Sig, _T("Virus.Tyhos.A"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], TYHOS_BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);					
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	else if((m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint == 0x1997) && (m_pSectionHeader[0].SizeOfRawData == 0x8000) && (m_pSectionHeader[0].PointerToRawData == 0x1000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[TYHOS_BUFF_SIZE];
		if(GetBuffer((m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + 0x1500), TYHOS_BUFF_SIZE, TYHOS_BUFF_SIZE))
		{
			TCHAR szVirusName[MAX_PATH] = {0};
			TCHAR Tyhos_Sig[] = _T("47686F737479002D2D2D2D5B2047484F5354592E4E4554205D*3648307374792D4768303537792E6E65742D67686F7A74790000000000*0067683035747936486F73743147482A357479002564*4F70656E002D66616B65006C736173732E657865002A2E2A002E657865");

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(Tyhos_Sig, _T("Virus.Tyhos.A"), FALSE);

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], TYHOS_BUFF_SIZE, szVirusName) >= 0)
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
	Function		: CPolySpit
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySpit::CPolySpit(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolySpit
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySpit::~CPolySpit(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Spit Family
--------------------------------------------------------------------------------------*/
int CPolySpit::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	// Checking if the Last Section PRD+SRD=1600h||1800h||1A00h + No. of sections=4 + Checksum=0 + PE Header Characteristics=818E
	// These are entry level checks to detect the presence of an infected file
	if(((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData)== 0x1600 || 0x1800 || 0x1A00) && 
		(m_wNoOfSections == 4) &&
		(m_pMaxPEFile->m_stPEHeader.CheckSum==0x0000) && (m_pMaxPEFile->m_stPEHeader.Characteristics==0x818E))
	{	
		// At offset 12 in infected file virus coder puts his signature.This offset is from beginnning of file in RESERVED section in DOS stub
		// Spit Signature:-SPIT.Win32 is a Bumblebee Win32 Virus....Feel the power of Spain and die by the SpiT
		const TCHAR Spit_Sig[] = {_T("535049542E57696E333220697320612042756D626C656265652057696E33322056697275730A0D0A0D46*65656C2074686520706F776572206F6620537061696E20616E6420646965206279207468652053706954")};		

		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(Spit_Sig, _T("Virus.Spit"), FALSE);


		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int SPIT_BUFF_SIZE = 0x300;
		m_pbyBuff = new BYTE[SPIT_BUFF_SIZE];
		TCHAR szVirusName[MAX_PATH] = {0};

		//In variants a and c the offset from where the virus signature is found=FBFh
		//In variant b the offset is FB9h
		//In variant d the offset is 11BFh
		//So a large buffer has been taken and the starting offset has been kept at FB9h to incorporate all
		if(GetBuffer(0xFB9, SPIT_BUFF_SIZE, SPIT_BUFF_SIZE))
		{
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], SPIT_BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					//This check will not work because the virus stub does not have a 'hk' at offset 12.
					//But left here incase the sample got was corrupt
					if((m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0xA00) == m_pMaxPEFile->m_dwFileSize ||
						(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0x800) == m_pMaxPEFile->m_dwFileSize ||
						(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + 0x600) == m_pMaxPEFile->m_dwFileSize ||
						(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData) == m_pMaxPEFile->m_dwFileSize)
					{
						iRetStatus = VIRUS_FILE_DELETE;
					}
					else
					{
						if(ORIGINAL_FILE_OFFSET < m_pMaxPEFile->m_dwFileSize)
						{
							WORD wMZ = 0;						
							if(m_pMaxPEFile->ReadBuffer(&wMZ, ORIGINAL_FILE_OFFSET, sizeof(WORD), sizeof(WORD)))
							{
								if(wMZ == IMAGE_DOS_SIGNATURE)
								{
									iRetStatus = VIRUS_FILE_REPAIR;
								}
								else
								{
									iRetStatus = VIRUS_FILE_DELETE;
								}
							}
						}
					}
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of spit Family
--------------------------------------------------------------------------------------*/
int CPolySpit::CleanVirus(void)
{
	// Data to be copied from offset 2000h and written at offset 0.Size to be written is Infected File Size - Virus Stub Size==Original File Size
	if(m_pMaxPEFile->CopyData(ORIGINAL_FILE_OFFSET, 0x00, m_pMaxPEFile->m_dwFileSize - ORIGINAL_FILE_OFFSET))
	{
		//Truncate file applied after copy data.Set File End=Original File Size
		if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - ORIGINAL_FILE_OFFSET))
		{
			return REPAIR_SUCCESS;
		}
	}      			
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyNeshta
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyNeshta::CPolyNeshta(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyNeshta
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyNeshta::~CPolyNeshta(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Neshta Family
--------------------------------------------------------------------------------------*/
int CPolyNeshta::DetectVirus()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	//added START
	if ((m_wNoOfSections == 9 || m_wNoOfSections == 2)&& (m_dwAEPMapped == 0x165A || m_dwAEPMapped == 0x0240) &&  
		(m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5D2D || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x55CB)&& 
		!memcmp(m_pSectionHeader[8].Name, ".RLICKY4", 8) || !memcmp(m_pSectionHeader[0].Name, ".PEDATA", 7))
	{

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		int OTWYCAL_BUFF_SIZE = 0x400;
		m_pbyBuff = new BYTE[OTWYCAL_BUFF_SIZE];

		DWORD dwStartBuff = 0x00;

		if(m_wNoOfSections == 9 && m_dwAEPMapped == 0x165A)
		{
			dwStartBuff = m_pSectionHeader[8].PointerToRawData + 0x17C5;
		}
		else 
		{
			dwStartBuff = m_pSectionHeader[1].PointerToRawData + 0x523;
		}


		if(GetBuffer(dwStartBuff, OTWYCAL_BUFF_SIZE, OTWYCAL_BUFF_SIZE))
		{

			TCHAR OTWYCAL_CZ_Sig[] = {_T("C1E0088953F409C88943F88B4BFC8B1689C8C1E80B*B8000800008B1629D0C1E805")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(OTWYCAL_CZ_Sig, _T("Virus.Win32.Otwycal.a"), TRUE);


			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], OTWYCAL_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{

					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					return DisinfectNeshta(true);	
				}
			}

		}

		return iRetStatus;

	}
	//END
	//Changed Aniket
	//else if(m_wNoOfSections >= 0x8 || !memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, "DexCrypt", 8) ||   //for delf & dexcrypt files
	//	(m_wNoOfSections == 0x3 && !memcmp(m_pSectionHeader[0].Name, "UPX0", 4)) ||                      //for upx files
	//	(m_wNoOfSections == 0x2 && m_pSectionHeader[0].Characteristics == 0xC00000E0) ||                 //for already fsg & mew files                          
	//	(!memcmp(m_pSectionHeader[0].Name, ".maxs01", 7) ||                                             //for fsg & mew unpacked by max
	//	((m_wNoOfSections == 0x6 || m_wNoOfSections == 0x8) && (m_dwAEPMapped == 0x74E4 || m_dwAEPMapped == 0x2CAF || m_dwAEPMapped == 0x7578) && m_pSectionHeader[0].SizeOfRawData == 0x7400))) //added
	else if(m_wNoOfSections >= 0x8 || !memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, "DexCrypt", 8) || //for delf & dexcrypt files
		(m_wNoOfSections == 0x3 && !memcmp(m_pSectionHeader[0].Name, "UPX0", 4)) ||  //for upx files
		(m_wNoOfSections == 0x3 || m_wNoOfSections == 0x4 && m_pSectionHeader[0].Characteristics == 0x60000020) ||
		(m_wNoOfSections == 0x2 && m_pSectionHeader[0].Characteristics == 0xC00000E0) || 
		(m_wNoOfSections == 0x2 && m_pSectionHeader[0].Characteristics == 0xE2000020) ||  //for already fsg & mew files                          
		(!memcmp(m_pSectionHeader[0].Name, ".maxs01", 7) ||  //for fsg & mew unpacked by max
		((m_wNoOfSections == 0x6 || m_wNoOfSections == 0x8) && (m_dwAEPMapped == 0x74E4 || m_dwAEPMapped == 0x2CAF || m_dwAEPMapped == 0x7578) && m_pSectionHeader[0].SizeOfRawData == 0x7400))) //added
	{
		if(m_pSectionHeader[0].SizeOfRawData > 0x17000)
		{
			return iRetStatus;
		}

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		m_pbyBuff = new BYTE[m_pSectionHeader[0].SizeOfRawData];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		CSemiPolyDBScn polydbObj;		

		//handling corrupt files having filesize less than size of raw data
		DWORD  dwMinimumBytes = m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[0].PointerToRawData < m_pSectionHeader[0].SizeOfRawData ? m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[0].PointerToRawData : m_pSectionHeader[0].SizeOfRawData;

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData, m_pSectionHeader[0].SizeOfRawData, dwMinimumBytes))
		{
			if(!memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, "DexCrypt", 8))
			{
				const TCHAR NEASHTAD_SIG[] = _T("566838304000FF15382040008BF085F6741E684430400056*FF153420400085C0740EFF74240CFF74240CFFD085C07404");
				polydbObj.LoadSigDBEx(NEASHTAD_SIG, _T("Virus.Neshta.D"), TRUE);
			}
			//varientA normal
			const TCHAR NEASHTAA_SIG[] = _T("558BEC83C4E033C08945E08945E88945E48945ECB854804000E812BEFFFF33C0*55682082400064FF30648920B8A8914000B90B000000BA0B000000E85CEFFFFF*B8B4914000B909000000BA09000000E848EFFFFFB8C0914000B903000000BA03*000000E834EFFFFFB8DC914000B903000000BA03000000E820EFFFFFA1109240*00B90B000000BA0B000000E80CEFFFFFE863EFFFFF8D55EC33C0E84DC8FFFF8B");
			//As we do not resolve the calls of aspack files , new signature is added for aspack files.
			const TCHAR NEASHTAAS_SIG[] = _T("558BEC83C4E033C08945E08945E88945E48945ECB854804000E8010F2F0033C0*55682082400064FF30648920B8A8914000B90B000000BA0B000000E8017B6000*B8B4914000B909000000BA09000000E8017B6000B8C0914000B903000000BA03*000000E8017B6000B8DC914000B903000000BA03000000E8017B6000A1109240*00B90B000000BA0B000000E8017B6000E801D760008D55EC33C0E801CB39008B");
			//varientB normal
			const TCHAR NEASHTAB_SIG[] = _T("84C00F84FB0000008B45FCE80BB7FFFF8BD853E867C3FFFF8945F8F745F80100*000076086A0053E8BBC3FFFF8B45FCE85FDEFFFF8945F433C05568D27D400064*FF306489208B45F4E83EDCFFFF8BD081EA00A200008B45F4E826DCFFFF8D95EC*5DFFFF8B45F4B900A20000E827DCFFFF8D55F08D85BE62FFFFB904000000E8D8*A7FFFF8D85EC5DFFFF8B4DF0BAE8030000E849F3FFFF8B45F433D2E8E3DBFFFF");
			//varientA rsrc file trojan keylogger
			const TCHAR NEASHTAAR_SIG[] = _T("BA38BF4100E8A984FEFF0F84EB0000008D45EC508D55E8B84CBF4100E816FCFF*FF8B4DE8BA60BF4100A1A02A4200E89CFCFFFF8B55ECB8A02A4200E8DF80FEFF*8D45E4508D55DCB84CBF4100E8E6FBFFFF8B45DC8D55E0E8D3F5FFFF8D45E0BA*74BF4100E80683FEFF8B4DE0BA88BF4100A1A02A4200E854FCFFFF8B55E4B8A0");

			const TCHAR INFECTORGEN9_SIG[] = _T("69930890400005840808428993089040*B8FF000000E8E5B5FFFF3006464B75F0*B8A8914000B90B000000BA0B000000*B8B4914000B909000000BA09000000");

			polydbObj.LoadSigDBEx(NEASHTAA_SIG, _T("Virus.Neshta.A"), TRUE);
			polydbObj.LoadSigDBEx(NEASHTAB_SIG, _T("Virus.Neshta.B"), TRUE);
			polydbObj.LoadSigDBEx(NEASHTAAR_SIG, _T("Virus.Neshta.AR"), TRUE);
			polydbObj.LoadSigDBEx(NEASHTAAS_SIG, _T("Virus.Neshta.AS"), TRUE);
			polydbObj.LoadSigDBEx(INFECTORGEN9_SIG, _T("Virus.Infector.Gen9"), FALSE); 
		}
		TCHAR szVirusName[MAX_PATH] = {0};
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			if(m_pMaxPEFile->m_dwFileSize <= 0xA200 || m_dwAEPMapped > m_pMaxPEFile->m_dwFileSize)
			{
				return VIRUS_FILE_DELETE;
			}
			return DisinfectNeshta(true);			
		}
	}
	else if(m_wNoOfSections == 2 && m_dwAEPMapped == 0x727)  //stub file
	{
		DWORD dwStartOffset = 0;
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress, &dwStartOffset))
		{
			return iRetStatus;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x200];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(GetBuffer(dwStartOffset, 0x200, 0x200))
		{
			const TCHAR NEASHTAC_SIG[] = _T("47657446696C6553697A65003C0147657453797374656D4469726563746F7279*41004A0147657454656D7050617468410000620147657457696E646F77734469*726563746F72794100006701476C6F62616C416C6C6F6300F701526561644669*6C650000340253657446696C6541747472696275746573410000360253657446*696C65506F696E74657200009E02577269746546696C6500B5026C7374726361*646C6C000067005368656C6C4578656375746541007368656C6C33322E646C6C");
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(NEASHTAC_SIG, _T("Virus.Neshta.C"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	//files having large overlay & aep in second section
	else if(m_wNoOfSections == 5 && m_wAEPSec == 2)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x20];
		if(GetBuffer(m_dwAEPMapped, 0x20, 0x20))
		{
			const TCHAR NEASHTAAT_SIG[] = _T("558BEC8B4510508B450C508B450850E8*8BE55DC38BE55DC3CCCC");

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(NEASHTAAT_SIG, _T("Virus.Neshta.AT"), FALSE);    //two

			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	//Added START
	else if ((m_wNoOfSections == 0x6 && m_dwAEPMapped == 0x327E00 && m_pMaxPEFile->m_stPEHeader.CheckSum == 0x32D3DD && 
		memcmp(m_pSectionHeader[m_wAEPSec].Name, "xysgficx", 8) == 0 && memcmp(m_pSectionHeader[4].Name, "wrvyvdkw", 8) == 0 &&
		m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x0200) ||
		(m_wNoOfSections == 0x3 && ((m_dwAEPMapped & 0xFFFF000) == 0x147F000) == ((m_pSectionHeader[m_wAEPSec].SizeOfRawData & 0xFFFF000) == 0x147F000)))
	{
		int iCnt = 0;
		DWORD m_dwOffset = 0;
		int NESHTA_BUFF_SIZE = 0;

		while(m_pSectionHeader[m_wAEPSec].Name[iCnt])
		{
			iCnt++;
		}
		if(iCnt==8)
		{
			m_dwOffset = m_dwAEPMapped;
			NESHTA_BUFF_SIZE = 0x6A;
		}
		else
		{
			m_dwOffset = 0xC69D;
			NESHTA_BUFF_SIZE = 0x550;
		}
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		m_pbyBuff = new BYTE[NESHTA_BUFF_SIZE];

		if(GetBuffer(m_dwOffset, NESHTA_BUFF_SIZE, NESHTA_BUFF_SIZE))
		{
			const TCHAR NEASHTAAT_SIG[] = _T("83EC045053E801000000CC5889C3402D00C014002D1C8A091005118A0910803B*0083C000894424085B58C35589E5505351568B75088B4D0CC1E9028B45108B5D14*85C9740A3106011E83C60449EBF2");
			const TCHAR NEASHTAAT_SIG1[] = _T("2120426573742072656761726473203220546F6D6D792053616C6F2E*205B4E6F762D323030355D20796F757273205B447A696164756C6A61204170616E61735D*371F371F3728B600000AA42D0000016FDA00000A00027B");
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(NEASHTAAT_SIG, _T("Virus.Neshta.GEN"), TRUE); 
			polydbObj.LoadSigDBEx(NEASHTAAT_SIG1, _T("Virus.Neshta.GEN"), FALSE); 
			//two

			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	//END
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Neshta Family
--------------------------------------------------------------------------------------*/
int CPolyNeshta::CleanVirus(void)
{	
	return DisinfectNeshta();
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: bool bDetectOnly
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Neshta Family
--------------------------------------------------------------------------------------*/
int CPolyNeshta::DisinfectNeshta(bool bDetectOnly /*= false*/)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int NESHTA_BUFF_SIZE = 0xA200;
	m_pbyBuff = new BYTE[NESHTA_BUFF_SIZE];
	if(GetBuffer((m_pMaxPEFile->m_dwFileSize - 0xA200), NESHTA_BUFF_SIZE, NESHTA_BUFF_SIZE))
	{	
		DWORD dwDecryptionKey =(*((DWORD *)&m_pbyBuff[0x4D2]));
		__int64 i64Result = 0;
		DWORD dwVar = 0;
		for(DWORD i = 0; i < 0x3E8; i++)
		{
			dwVar = dwDecryptionKey * 0x8088405;
			dwVar++;
			dwDecryptionKey = dwVar;
			i64Result = (__int64)dwVar * 0xFF;
			dwVar = (DWORD)(i64Result / 0x100000000);
			m_pbyBuff[i] ^= (BYTE)dwVar;
			
			if(bDetectOnly == 1)
			{
				return (m_pbyBuff[0] == 0x4D) ? VIRUS_FILE_REPAIR : VIRUS_FILE_DELETE;				
			}
		}
		if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, 0, 0xA200))
		{	
			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - 0xA200))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyInitx
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyInitx::CPolyInitx(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0;
	m_dwFillZeroOff = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyInitx
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyInitx::~CPolyInitx(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Initx Family
--------------------------------------------------------------------------------------*/
int CPolyInitx::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec != m_wNoOfSections - 1  && ((m_pSectionHeader[m_wAEPSec].Characteristics & 0x80000000) ==  0x80000000
		|| (m_pSectionHeader[m_wAEPSec].Characteristics & 0x60000020) ==  0x60000020))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int INITX_BUFF_SIZE = 0x10;
		m_pbyBuff = new BYTE[INITX_BUFF_SIZE];
		if(!GetBuffer(m_dwAEPMapped ,INITX_BUFF_SIZE))
		{
			return iRetStatus;
		}
		if(m_pbyBuff[0] == 0x68 && m_pbyBuff[5] == 0xFF && m_pbyBuff[6] == 0x15 && m_pbyBuff[0xB] == 0xE9)
		{
			m_dwOriginalAEP = (*(DWORD *)&m_pbyBuff[0xC] + m_dwAEPUnmapped + 0x10);
			
			m_dwFillZeroOff = *(DWORD *)&m_pbyBuff[1] - m_dwImageBase;
			if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwFillZeroOff, &m_dwFillZeroOff))
			{
				if(GetBuffer(m_dwFillZeroOff, INITX_BUFF_SIZE))
				{
					TCHAR szVirusName[MAX_PATH] = {0};
					CSemiPolyDBScn polydbObj;
					TCHAR Initx[] = _T("696E697478*2E646174000000");
					polydbObj.LoadSigDBEx(Initx, _T("Virus.Initx"), FALSE);	
					if(polydbObj.ScanBuffer(&m_pbyBuff[0], INITX_BUFF_SIZE, szVirusName) >= 0)
					{ 
						if(_tcslen(szVirusName) > 0)
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							return VIRUS_FILE_REPAIR;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Initx Family
--------------------------------------------------------------------------------------*/
int CPolyInitx::CleanVirus(void)
{	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwFillZeroOff, 0x1C))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyWide
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyWide::CPolyWide(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwCalloffset = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyWide
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyWide::~CPolyWide(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Wide Family
--------------------------------------------------------------------------------------*/
int CPolyWide::DetectVirus(void)
{
	if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xA0000020) == 0xA0000020) && 
		((m_wAEPSec == m_wNoOfSections - 1) || (m_wAEPSec == m_wNoOfSections - 2)) && 
		((m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x64656957) || (m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x41574941)) && 
		(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData != m_dwAEPMapped) &&
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{	 

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int WIDE_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[WIDE_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, WIDE_BUFF_SIZE, WIDE_BUFF_SIZE))
		{
			BYTE bySig[] = {0x60, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x81, 0xED};
			for(DWORD dwOffset = 0; dwOffset < m_dwNoOfBytes - sizeof(bySig); dwOffset++)
			{
				if(memcmp(&m_pbyBuff[dwOffset], bySig, sizeof(bySig)) == 0)
				{
					const TCHAR WIDE_8135_A_SIG[] = {_T("83FD0074418D95*B9CE170000300242E2FB81FF59555021")};
					const TCHAR WIDE_7910_SIG[] = {_T("83FD0074498D95*B9E01600003002425058E2F981FF41495741")};

					CSemiPolyDBScn polydbObj;
					polydbObj.LoadSigDBEx(WIDE_8135_A_SIG, _T("Virus.Wide.8135.A"), TRUE);
					polydbObj.LoadSigDBEx(WIDE_7910_SIG, _T("Virus.Wide.7910"), FALSE);

					TCHAR szVirusName[MAX_PATH] = {0};
					if(polydbObj.ScanBuffer(m_pbyBuff + dwOffset, m_dwNoOfBytes - dwOffset, szVirusName) >= 0)
					{
						if(_tcslen(szVirusName) > 0)
						{
							if(_tcsstr(szVirusName,_T("Virus.Wide.8135.A")))
							{
								m_eInfectionType = WIDE_8135_A;
							}
							else if(_tcsstr(szVirusName,_T("Virus.Wide.7910")))
							{
								m_eInfectionType = WIDE_7910;
							}
							m_dwCalloffset = dwOffset;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							return VIRUS_FILE_REPAIR;
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Wide Family
--------------------------------------------------------------------------------------*/
int CPolyWide::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;  
	
	DWORD dwOffset = m_dwAEPMapped + m_dwCalloffset;
	DWORD dwXORKeyOffset = 0, dwTxtCodeXORkeyOffset = 0, dwAEPOffset = 0;

	if(m_eInfectionType == WIDE_7910)
	{
		dwXORKeyOffset = dwOffset + 0x1729;
		dwTxtCodeXORkeyOffset = dwOffset + 0x1655;
		dwAEPOffset += dwOffset + 0xD5C;
	}
	else if(m_eInfectionType == WIDE_8135_A)
	{
		dwXORKeyOffset = dwOffset + 0x1813;
		dwTxtCodeXORkeyOffset = dwOffset + 0x1596;
		dwAEPOffset += dwOffset + 0xCAD;
	}

	BYTE byXORKey = 0;
	if(!m_pMaxPEFile->ReadBuffer(&byXORKey, dwXORKeyOffset, 1, 1))
	{
		return iRetStatus;
	}

	BYTE byTxtCodeXORkey = 0;
	if(!m_pMaxPEFile->ReadBuffer(&byTxtCodeXORkey, dwTxtCodeXORkeyOffset, 1, 1))
	{
		return iRetStatus;
	}

	byTxtCodeXORkey ^= byXORKey;
	byTxtCodeXORkey = byXORKey - byTxtCodeXORkey;
	
	if(!GetBuffer(dwAEPOffset, 0x04, 0x04))
	{
		return iRetStatus;
	}

	for(int i = 0; i < 4; i++)
	{
		m_pbyBuff[i] ^= byXORKey;
	}

	DWORD dwOriginalAEPMapped = 0, dwOriginalAEPUnmapped = *(DWORD *)&m_pbyBuff[0];
	WORD wSec = m_pMaxPEFile->Rva2FileOffset(dwOriginalAEPUnmapped, &dwOriginalAEPMapped);
	if(wSec == OUT_OF_FILE)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}	
	DWORD dwBuffSize = m_pSectionHeader[wSec].SizeOfRawData;
	if(m_pMaxPEFile->m_dwFileSize - dwOriginalAEPMapped < m_pSectionHeader[wSec].SizeOfRawData)
	{
		dwBuffSize = m_pMaxPEFile->m_dwFileSize - dwOriginalAEPMapped;
	}	
	m_pbyBuff = new BYTE[dwBuffSize];					
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}
	memset(m_pbyBuff, 0x00, dwBuffSize);

	DWORD dwChunk = 0x10000;

	DWORD dwCaseChunks = (dwBuffSize/dwChunk) + 1, dwNumberofBytestoXOR = 0;
	for(DWORD i = 0; i < dwCaseChunks; i++)
	{
		if((dwBuffSize - (i * 0x10000)) <= dwChunk)
		{
			dwChunk = dwBuffSize % dwChunk;
		}

		if(!GetBuffer(dwOriginalAEPMapped, dwChunk, dwChunk))
		{
			return iRetStatus;
		}
		bool bFlag = false;
		for(DWORD byteCount = 0x00; byteCount < (dwChunk - 4); byteCount++)
		{
			if(m_pbyBuff[byteCount] == 0 && *(DWORD *)&m_pbyBuff[byteCount + 1] == 0)
			{
				dwNumberofBytestoXOR = byteCount;
				bFlag = true;
				break;
			}
		}
		if(dwNumberofBytestoXOR)
		{   
			if(!bFlag)
			{
				dwNumberofBytestoXOR = dwChunk;
			}

			for(DWORD i = 0; i < dwNumberofBytestoXOR; i++)
			{
				m_pbyBuff[i] ^= byTxtCodeXORkey;
			}

			if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwOriginalAEPMapped, dwNumberofBytestoXOR, dwNumberofBytestoXOR))
			{
				return iRetStatus;
			}

			if(m_pMaxPEFile->WriteAEP(dwOriginalAEPUnmapped))
			{
				if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
				{	
					if(m_pMaxPEFile->RepairOptionalHeader(0x13,0x00,0x00))
					{
						iRetStatus = REPAIR_SUCCESS;
					}
				}
			}			
			break;
		}
	}	
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyGypet
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGypet::CPolyGypet(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGypet
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGypet::~CPolyGypet(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Gypet Family
--------------------------------------------------------------------------------------*/
int CPolyGypet::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020) == 0xA0000020) && 
		(m_wAEPSec == m_wNoOfSections -1) && 
		(m_pMaxPEFile->m_stPEHeader.Win32VersionValue == 0x12345678) && 
		(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData != m_dwAEPMapped) &&
		(m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{	         

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int GYPET_BUFF_SIZE = 0x35;
		m_pbyBuff = new BYTE[GYPET_BUFF_SIZE];					
		if(GetBuffer(m_dwAEPMapped, 0x07, 0x07))
		{
			//Checking the first 7 bytes from AEP
			const BYTE bySignature[] = {0x60, 0x9C, 0xE8, 0xC4, 0x18, 0x00, 0x00};
			if(memcmp(m_pbyBuff, bySignature, sizeof(bySignature))==0)
			{
				if(GetBuffer(m_dwAEPMapped + 0x18D8, GYPET_BUFF_SIZE, GYPET_BUFF_SIZE))
				{
					//Gypet Signature-->Contains the decryption loop
					TCHAR Gypet_6340_Sig[] = {_T("33DB64FF335B32C3*32E73006F61EF616D006F61E0026464181F9C4180000")};
					
					CSemiPolyDBScn polydbObj;
					polydbObj.LoadSigDBEx(Gypet_6340_Sig, _T("Virus.Gypet.6340"), FALSE);

					TCHAR szVirusName[MAX_PATH] = {0};				
					if(polydbObj.ScanBuffer(&m_pbyBuff[0], GYPET_BUFF_SIZE, szVirusName) >= 0)
					{
						if(_tcslen(szVirusName) > 0)
						{
							iRetStatus = (m_pMaxPEFile->m_dwFileSize == 0x3000) ? VIRUS_FILE_DELETE : VIRUS_FILE_REPAIR;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							return iRetStatus;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Gypet Family
--------------------------------------------------------------------------------------*/
int CPolyGypet::CleanVirus(void)
{
	//Two keys are found at offset 18DA and 18D8
	BYTE byKey1 = m_pbyBuff[0] ^ 0x68;
    BYTE byKey2 = m_pbyBuff[2] ^ 0xFF;

	//The encrypted AEP is found at offset D7
    if(GetBuffer(m_dwAEPMapped + 0xD7, 0x04,0x04))
	{
		signed char DecryptedValue = 0;
		for(int i = 0; i < 4; i++)
		{
			DecryptedValue = m_pbyBuff[i];
            DecryptedValue ^= byKey1;
			DecryptedValue -= 0x1;
			DecryptedValue = _rotl(DecryptedValue, 1);
            DecryptedValue -= 0x1;
			DecryptedValue =~ DecryptedValue;
			DecryptedValue -= byKey2;
			*(signed char *)&m_pbyBuff[i] = DecryptedValue;
		}
		if(*(DWORD *)&m_pbyBuff[0] < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize)
		{
			if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[0]))
			{			
				if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
				{	
					return REPAIR_SUCCESS;
				}		   
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyInta
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyInta::CPolyInta(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyInta
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyInta::~CPolyInta(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Inta Family
--------------------------------------------------------------------------------------*/
int CPolyInta::DetectVirus(void)
{
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		(m_pSectionHeader[0].Characteristics && 0x80000000 == 0x80000000) && 
		(m_pSectionHeader[0].Misc.VirtualSize >= 0xA17) && 
		(m_pMaxPEFile->m_stPEHeader.MinorLinkerVersion == 0x29))
	{		
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int INTA_BUFF_SIZE = 0x40;
		m_pbyBuff = new BYTE[INTA_BUFF_SIZE];							
		if(GetBuffer(m_dwAEPMapped, 0x05, 0x05))
		{
			if(m_pbyBuff[0] == 0xE9)
			{
				m_dwCallAddr = m_dwAEPUnmapped + (*(DWORD*)&m_pbyBuff[1]) + 0x05;			
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwCallAddr, &m_dwCallAddr))
				{
					if(GetBuffer(m_dwCallAddr + 0x1F6, INTA_BUFF_SIZE, INTA_BUFF_SIZE))
					{
						TCHAR Inta1676_Sig[] ={_T("496E7374616C6C65725D2062*792042656E6E792F3239412026*204461726B6D616E2F323941")};
						CSemiPolyDBScn polydbObj;
						polydbObj.LoadSigDBEx(Inta1676_Sig, _T("Virus.Inta"), FALSE);
						
						TCHAR szVirusName[MAX_PATH] = {0};
						if(polydbObj.ScanBuffer(&m_pbyBuff[0], INTA_BUFF_SIZE, szVirusName) >= 0)
						{
							if(_tcslen(szVirusName) > 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
								return VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Inta Family
--------------------------------------------------------------------------------------*/
int CPolyInta::CleanVirus(void)
{
	DWORD SizeOfBuffer = 0x00;
	if(m_pMaxPEFile->ReadBuffer(&SizeOfBuffer, m_dwCallAddr + 0x3DA, 0x04, 0x04))
	{
		if(SizeOfBuffer != 0x0A17)
		{
			SizeOfBuffer = 0x0A23;
		}
		if(GetBuffer(m_dwCallAddr + 0x1C6, 0x05, 0x05))
		{
			if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped, 0x05, 0x05))
			{
				if(m_pMaxPEFile->FillWithZeros(m_dwCallAddr, SizeOfBuffer))
				{ 	
					return REPAIR_SUCCESS;
				}
			}
		}
	}	
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyBluback
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyBluback::CPolyBluback(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBluback
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBluback::~CPolyBluback(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Bluback Family
--------------------------------------------------------------------------------------*/
int CPolyBluback::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020)== 0xA0000020) &&  
		(m_pSectionHeader[m_wNoOfSections-1].PointerToRelocations == 0x6e526f4b) &&
		(m_pSectionHeader[m_wNoOfSections -1].PointerToRawData != m_dwAEPMapped) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) )
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int BUFF_SIZE = 0x16;
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped, 0x06,0x06))
		{
			if(m_pbyBuff[0] == 0x68 && m_pbyBuff[5] == 0xC3)
			{
				if((m_pMaxPEFile->Rva2FileOffset(m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].Misc.VirtualSize - 0x560, &m_dwPatchAEPMapped) == m_wNoOfSections - 1))
				{
					if(GetBuffer(m_dwPatchAEPMapped + 0x42F, BUFF_SIZE, BUFF_SIZE))
					{
						TCHAR Blueback_1376_Sig[] = {_T("817E184B6F526E0F84*FD000000C746184B6F526E")};
						CSemiPolyDBScn polydbObj;
						polydbObj.LoadSigDBEx(Blueback_1376_Sig, _T("Virus.Bluback.1376"), FALSE);

						TCHAR szVirusName[MAX_PATH] = {0};
						if(polydbObj.ScanBuffer(&m_pbyBuff[0], BUFF_SIZE, szVirusName) >= 0)
						{
							if(_tcslen(szVirusName) > 0)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
								iRetStatus = VIRUS_FILE_REPAIR;
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
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Bluback Family
--------------------------------------------------------------------------------------*/
int CPolyBluback::CleanVirus(void)
{
	if(GetBuffer(m_dwPatchAEPMapped + 0x20, 0x04,0x04))
	{
		BYTE  bXORKey = 0xD5;
		for(int i = 0; i < 4; i++, bXORKey--)
		{
			m_pbyBuff[i] ^= bXORKey;
		}
		if(OUT_OF_FILE != *(DWORD*)&m_pbyBuff[0])
		{
			DWORD  dwOriginalAEPUnMapped = *(DWORD*)&m_pbyBuff[0];
			if(m_pMaxPEFile->WriteAEP(dwOriginalAEPUnMapped))
			{
				if(GetBuffer(m_dwPatchAEPMapped + 0x554, 6, 6))
				{   
					DWORD dwOriginalAEPMapped = 0;
					if(m_pMaxPEFile->Rva2FileOffset(dwOriginalAEPUnMapped, &dwOriginalAEPMapped) >= 0x0)
					{
						if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, dwOriginalAEPMapped, 0x06, 0x06))
						{
							//Since it overwrites the Certificate Table so the only option is to fill with zeroes for all the files
							if(m_pMaxPEFile->FillWithZeros(m_dwPatchAEPMapped, m_pMaxPEFile->m_dwFileSize - m_dwPatchAEPMapped))
							{	
								return REPAIR_SUCCESS;
							}
						}
					}
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyUndertaker
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyUndertaker::CPolyUndertaker(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyUndertaker
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyUndertaker::~CPolyUndertaker(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of UnderTaker Family
--------------------------------------------------------------------------------------*/
int CPolyUndertaker::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if( ((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xA0000020) == 0xA0000020) && 
		(m_wAEPSec == m_wNoOfSections -1) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) )
	{  
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int UNDERTAKER_BUFF_SIZE = 0x2B;
		m_pbyBuff = new BYTE[UNDERTAKER_BUFF_SIZE];
		if(!GetBuffer(0x38, 0x02, 0x02))
		{
			return iRetStatus;
		}
		//Checking the first 2 bytes from 38th offset
		if(*(WORD*)&m_pbyBuff[0] != 0x5554)
		{
			return iRetStatus;
		}
		
		DWORD dwDetectType4xxx = 0x04, dwDetectType5xxx = 0x08;				
		if(!GetBuffer(m_dwAEPMapped + 0xC, 0x05, 0x05))
		{
			return iRetStatus;
		}
		if(m_pbyBuff[0]==0xB9 && ((*(DWORD*)&m_pbyBuff[1] == 0x04B4) || (*(DWORD*)&m_pbyBuff[1] == 0x04B5) || (*(DWORD*)&m_pbyBuff[1] == 0x04D9)))
		{
            dwDetectType4xxx &= m_pbyBuff[1];
			dwDetectType5xxx &= m_pbyBuff[1];
			
			DWORD CounterLoop = *(DWORD*)&m_pbyBuff[1];
			memset(m_pbyBuff, 0, UNDERTAKER_BUFF_SIZE);
			if(GetBuffer(m_dwAEPMapped + (CounterLoop * 4) + (0x1D + (dwDetectType5xxx / 0x08)), UNDERTAKER_BUFF_SIZE - dwDetectType4xxx, UNDERTAKER_BUFF_SIZE - dwDetectType4xxx))
			{							
				TCHAR Undertaker_Sig[] = {_T("83FD0074*8B85*8B1733D00501010101891783C704E2F0E8*FFFFFFC3")};

				CSemiPolyDBScn polydbObj;
				polydbObj.LoadSigDBEx(Undertaker_Sig, _T("Virus.Undertaker"), FALSE);

				TCHAR szVirusName[MAX_PATH] = {0};				
				if(polydbObj.ScanBuffer(&m_pbyBuff[0], UNDERTAKER_BUFF_SIZE, szVirusName) >= 0)
				{
					DWORD dwFirstXORKey = *(DWORD *)&m_pbyBuff[0x22 + (dwDetectType5xxx / 0x02)];
					BYTE  bySecondXORKey = m_pbyBuff[0] + BYTE(0xA7 * 0x03);
					
					if(GetBuffer(m_dwAEPMapped + 0xC0, 0x08,0x08))
					{
						dwFirstXORKey += 0x29 * 0x1010101;
						*(DWORD*)&m_pbyBuff[0] ^= dwFirstXORKey;

						dwFirstXORKey += 0x1010101;
						*(DWORD*)&m_pbyBuff[4] ^= dwFirstXORKey;

						const DWORD dwAddValues[4] = {0x7, 0x14, 0x37, 0x94};		
						for(DWORD dwCounter = 0; dwCounter < 4; dwCounter++, bySecondXORKey += 3)
						{
							m_pbyBuff[0x3 + dwCounter] ^= (dwAddValues[dwCounter] + bySecondXORKey);
						}
						if(*(DWORD*)&m_pbyBuff[0x03] <  m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress +  m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize)
						{
							m_dwOriginalAEP = *(DWORD*)&m_pbyBuff[0x03];
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							return VIRUS_FILE_REPAIR;
						}
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Undertaker Family
--------------------------------------------------------------------------------------*/
int CPolyUndertaker::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{			
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{	
			return REPAIR_SUCCESS;
		}		   
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMimix
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMimix::CPolyMimix(CMaxPEFile *pMaxPEFile)
:CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMimix
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMimix::~CPolyMimix(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Mimix Family
--------------------------------------------------------------------------------------*/
int CPolyMimix::DetectVirus(void)
{	
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(((m_pSectionHeader[m_wNoOfSections - 1].Characteristics & 0xA0000000) == 0xA0000000) &&
		(m_wAEPSec == m_wNoOfSections - 1) &&
		(m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize == m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int MIMIX_BUFF_SIZE = 0xA8;
		m_pbyBuff = new BYTE[MIMIX_BUFF_SIZE];
		if(GetBuffer(m_dwAEPMapped - 0x7, 0x12, 0x12))
		{
			if(*(WORD *)&m_pbyBuff[0] == 0xAE0F && (*(DWORD *)&m_pbyBuff[3] == *(DWORD*)&m_pbyBuff[8]))
			{
				memset(m_pbyBuff, 0, MIMIX_BUFF_SIZE);
				if(GetBuffer(m_dwAEPMapped - 0x9F, 0x28, 0x28))
				{
					TCHAR Mimix_Sig[] = {_T("F30F6F*F30F6F*F30F6F*F30F6F*F30F6F*F30F6F*F30F6F*F30F6F")};

					CSemiPolyDBScn polydbObj;
					polydbObj.LoadSigDBEx(Mimix_Sig, _T("Virus.Mimix.A"), FALSE);

					TCHAR szVirusName[MAX_PATH] = {0};				
					if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
					{
						iRetStatus = VIRUS_FILE_REPAIR;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
						return iRetStatus;
					}
				}
			}
		}	
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Mimix Family
--------------------------------------------------------------------------------------*/
int CPolyMimix::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x28], m_dwAEPMapped + 0x05, 0x80, 0x80))
	{
		BYTE XMMArray[8][16] = {0};
		memset(&XMMArray[0][0], 0, 16*8);
		for(int i = 0; i < 8; i++)
		{
			memcpy(XMMArray[((HINIBBLE(m_pbyBuff[(i * 5) + 3]) % 4) * 2) + (1 * ((m_pbyBuff[(i * 5) + 3] & 0x08) && 0x08))], 
				&m_pbyBuff[0x28 + 0x10 * (HINIBBLE(m_pbyBuff[(i * 0x5) + 0x4]))], 0x10);
		}
		
		WaitForSingleObject(CPolymorphicVirus::m_hEvent, INFINITE);
		{
			CEmulate objEmulate(m_pMaxPEFile);
			if(objEmulate.IntializeProcess())
			{
				objEmulate.SetNoOfIteration(2);
				if(0 == objEmulate.EmulateFile())
				{			 
					objEmulate.SetEip(m_dwImageBase + m_dwAEPUnmapped);
					objEmulate.SetNoOfIteration(0x100000);

					if(objEmulate.WriteBuffer(&XMMArray[0][0], 16*8, m_dwImageBase + m_dwAEPUnmapped))
					{			
						objEmulate.SetBreakPoint("__isinstruction('jmp')");
						
						if(objEmulate.EmulateFile()==7)
						{					
							BYTE BufferAEPToWrite[4];
							DWORD dwAEPToWrite;
							memset(BufferAEPToWrite,0,4);
							objEmulate.ReadEmulateBuffer(BufferAEPToWrite,4, objEmulate.GetEip()+0x8);

							dwAEPToWrite=*(DWORD *)&BufferAEPToWrite[0]-m_dwImageBase;
							if(dwAEPToWrite < m_pSectionHeader[m_wNoOfSections - 1].VirtualAddress + m_pSectionHeader[m_wNoOfSections - 1].Misc.VirtualSize)
							{
								if(m_pMaxPEFile->WriteAEP(dwAEPToWrite))
								{
									if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped - 0xA0, true))
									{	
										iRetStatus = REPAIR_SUCCESS;
									}
								}
							}
						}
					}
				}
			}
		}
		SetEvent(CPolymorphicVirus::m_hEvent);
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyPadania
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPadania::CPolyPadania(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwFileEndOff = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPadania
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPadania::~CPolyPadania(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Padania Family
--------------------------------------------------------------------------------------*/
int CPolyPadania::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if (m_pMaxPEFile->m_stPEHeader.MajorImageVersion == 0x3062 && 
		m_pMaxPEFile->m_stPEHeader.MinorImageVersion == 0x307A && 
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000040) == 0xC0000040) && 
		(memcmp(m_pSectionHeader[m_wNoOfSections-1].Name, "Padania", 7) == 0) && 
		m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData >= 0x537) 
	{
		const int BUFF_SIZE = 0x530;

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[BUFF_SIZE];
		if(!GetBuffer(m_pSectionHeader[m_wNoOfSections-1].PointerToRawData, BUFF_SIZE))
		{
			return iRetStatus;
		}

		TCHAR			szVirusName[MAX_PATH] = {0};
		TCHAR			Padania_1335_Sig[] = {_T("506164616E69615F4C6962657261*6279202D62307A302F694B582D*506164616E6961")};
		CSemiPolyDBScn	polydbObj;

		polydbObj.LoadSigDBEx(Padania_1335_Sig, _T("Virus.Padania.1335"), FALSE);
		
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			
			DWORD dwSetOff = m_pSectionHeader[m_wNoOfSections - 2].SizeOfRawData + m_pSectionHeader[m_wNoOfSections - 2].PointerToRawData;
			if(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData != dwSetOff)
			{
				int CHECK_BUFF_SIZE = 0x0;
				if(dwSetOff > m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData)
				{
					CHECK_BUFF_SIZE = dwSetOff - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
					dwSetOff = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData - CHECK_BUFF_SIZE;
				}
				else 
					CHECK_BUFF_SIZE = m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData - dwSetOff;
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				m_pbyBuff = new BYTE[CHECK_BUFF_SIZE];
				if(GetBuffer(dwSetOff, CHECK_BUFF_SIZE, CHECK_BUFF_SIZE))
				{
					const BYTE byChk[] = {0xB8,0x00,0x10,0x00,0xC0,0xB9,0x00,0x10,0x00,0x00,0x8B,0x18,0x81,0xFB,0x00,0x20,0x00,0xC0,0x72,0x11,0x81,0xFB};
					for(int i = 0; i < CHECK_BUFF_SIZE; i++)
					{
						if(memcmp(&m_pbyBuff[i], byChk, sizeof(byChk)) == 0x00)
						{
							m_dwFileEndOff = dwSetOff + i;
							break;
						}
					}
				}
			}
			iRetStatus = VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Padania Family
--------------------------------------------------------------------------------------*/
int CPolyPadania::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x100];
	if(!GetBuffer(m_dwAEPMapped, 0x100))
	{
		return REPAIR_FAILED;
	}
	DWORD dwCavityStart = m_pMaxPEFile->m_stPEOffsets.NoOfDataDirs + (m_pMaxPEFile->m_stPEHeader.NumberOfRvaAndSizes * 0x8)+ (m_pMaxPEFile->m_stPEHeader.NumberOfSections * 0x28) + 0x4;
	if(m_dwAEPMapped == dwCavityStart)
	{
		m_pMaxPEFile->WriteAEP((*(DWORD *)&m_pbyBuff[0x2C]) - m_dwImageBase);
	}
	else
	{
		for(DWORD dwOff = 0; dwOff < m_dwNoOfBytes; dwOff++)
		{
			if(m_pbyBuff[dwOff] == 0xE9)
			{
				DWORD dwJmpOffset = m_dwAEPUnmapped + dwOff + 0x5 + *(DWORD *)&m_pbyBuff[dwOff + 1];
				m_pMaxPEFile->Rva2FileOffset(dwJmpOffset, &dwJmpOffset);
				if(dwJmpOffset == dwCavityStart)
				{ 					
					if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwJmpOffset + 0x32, 0x10))
					{
						m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x0], m_dwAEPMapped + dwOff, 0x6);
					}
				}
				break;
			}
		}
	}
	if(m_pMaxPEFile->FillWithZeros(dwCavityStart, 0x3D))
	{
		if(m_pMaxPEFile->RemoveLastSections())
		{ 
			if(m_dwFileEndOff)
			{
				m_pMaxPEFile->TruncateFile(m_dwFileEndOff, true);
			}
			return REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyHighway
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHighway::CPolyHighway(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwType = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHighway
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHighway::~CPolyHighway(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Highway Family
--------------------------------------------------------------------------------------*/
int CPolyHighway::DetectVirus(void)
{
	if( (m_wAEPSec == m_wNoOfSections - 1) &&
		(m_pSectionHeader[m_wNoOfSections-1].Characteristics  == 0xC0000040) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL))
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int HIGHWAY_BUFF_SIZE_Sig = 0x24;
		m_pbyBuff = new BYTE[HIGHWAY_BUFF_SIZE_Sig];
		if(GetBuffer(m_dwAEPMapped - 0x600, 0x02,0x02))
		{
			if(*(WORD*)&m_pbyBuff[0] == 0x5A4D)
			{
				BYTE bHighway[] = {0x5C, 0x48, 0x49, 0x47, 0x48, 0x57, 0x41, 0x59, 0x2E, 0x44, 0x4C, 0x4C};
				if(GetBuffer(m_dwAEPMapped + 0x58, sizeof(bHighway)+0x08, sizeof(bHighway)+0x08))
				{   					 
					if(memcmp(&m_pbyBuff[0], bHighway, sizeof(bHighway)) == 0 || (memcmp(&m_pbyBuff[8],bHighway,sizeof(bHighway))==0 && (m_dwType=0x01)))
					{
						if(GetBuffer(m_dwAEPMapped + 0xA00, 0x18, 0x18))
						{
							/*TCHAR HighwayB_Sig[] = {_T("43616E206120726F616420*626520612070726973696F6E3F")};							
							CSemiPolyDBScn polydbObj;
							polydbObj.LoadSigDBEx(HighwayB_Sig, _T("Virus.Highway.B"), FALSE);
							
							TCHAR szVirusName[MAX_PATH] = {0};							
							if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)*/
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Highway.B"));
								return VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
		}
	}
	else if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x05 && m_dwAEPUnmapped == 0x1200 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xA00 && 
		m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData == 0x1A00 && ((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL))
	{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int HIGHWAY_BUFF_SIZE = 0x800;
			m_pbyBuff = new BYTE[HIGHWAY_BUFF_SIZE];
			
			if(GetBuffer(m_dwAEPMapped + 0x40, HIGHWAY_BUFF_SIZE, HIGHWAY_BUFF_SIZE))
			{
				CSemiPolyDBScn polydbObj;
				TCHAR szHighwayA[] = {_T("5C484947485741592E444C4C*465245450068*43616E206120726F616420626520612070726973696F6E3F")};
				polydbObj.LoadSigDBEx(szHighwayA, _T("Virus.W32.Highway.A"), FALSE);
				TCHAR szVirusName[MAX_PATH] = {0};
				if(polydbObj.ScanBuffer(&m_pbyBuff[0], HIGHWAY_BUFF_SIZE, szVirusName) >= 0)
				{
					if(_tcslen(szVirusName)>0)
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
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Highway Family
--------------------------------------------------------------------------------------*/
int CPolyHighway::CleanVirus(void)
{
	if(FixImportTable())
	{
		if(GetBuffer(m_dwAEPMapped + 0xD6+(m_dwType*0xB6), 0x04, 0x04))
		{
			if(m_pMaxPEFile->WriteAEP(m_dwAEPUnmapped + 0xD6+0x04+(m_dwType*0xB6) + (*(DWORD *)&m_pbyBuff[0])))
			{
				if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped - 0x600))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: FixImportTable
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: This function repairs the entries in Import Table 
--------------------------------------------------------------------------------------*/
bool CPolyHighway::FixImportTable()
{	
	IMAGE_IMPORT_DESCRIPTOR objImportDescriptor = {0};
    if(m_pMaxPEFile->GetImportAndNameTableRVA("kernel32.dll", objImportDescriptor))
	{
		if(objImportDescriptor.FirstThunk > 0 && objImportDescriptor.OriginalFirstThunk >= 0)
		{
			DWORD dwKernel32_AddressTable_Offset = 0x0;
			m_pMaxPEFile->Rva2FileOffset(objImportDescriptor.FirstThunk, &dwKernel32_AddressTable_Offset);			
			if(dwKernel32_AddressTable_Offset <= m_pMaxPEFile->m_dwFileSize)
			{
				if(GetBuffer(m_dwAEPMapped + 0x79A +(m_dwType*0x13F), 8, 8))
				{
					if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0], dwKernel32_AddressTable_Offset, 0x08, 0x08))
					{
						return true;
					}
				}
			}
		}
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyFujack
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyFujack::CPolyFujack(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwStratOFfile = 0;
	m_dwOrifileSize = 0;	
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyFujack
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyFujack::~CPolyFujack(void)
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
	Author			: Tushar Kadam + Ravi Bisht + Parjakta + Sandeep Vosaya + Virus Analysis Team
	Description		: Detection routine for different varients of Fujack Family
--------------------------------------------------------------------------------------*/
int CPolyFujack::DetectVirus(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;	

	if((m_wAEPSec == 0x0 && m_wNoOfSections == 0x2 && memcmp(m_pSectionHeader[0].Name,".RC",3) == 0 && memcmp(m_pSectionHeader[1].Name,".RC",3) == 0) ||
		(m_wNoOfSections >= 0x2 && m_pSectionHeader[0].SizeOfRawData != 0x0 && memcmp(m_pSectionHeader[0].Name,"UPX0",5) == 0 && memcmp(m_pSectionHeader[1].Name,"UPX1",5) == 0) ||
		(m_wNoOfSections >= 0x2 && m_pSectionHeader[0].SizeOfRawData == 0x0 && m_pSectionHeader[0].PointerToRawData == 0x0 && 
		m_dwAEPMapped < m_pSectionHeader[1].PointerToRawData && m_pSectionHeader[0].Characteristics  == 0xC00000E0) ||
		(m_pSectionHeader[1].Characteristics  == 0xE0000060 && m_pSectionHeader[2].Characteristics  == 0xE0000060 &&
		memcmp(m_pSectionHeader[0].Name,".nsp0",5) == 0 && memcmp(m_pSectionHeader[1].Name,".nsp1",5) == 0 &&
		(memcmp(m_pSectionHeader[2].Name,".nsp2",5) == 0 || memcmp(m_pSectionHeader[2].Name,".rsrc",5) == 0)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int FUJACK_BUFF_SIZE = 0x1100;
		m_pbyBuff = new BYTE[FUJACK_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwCallOffset = 0;
		if(m_wNoOfSections == 0x3 && memcmp(m_pSectionHeader[0].Name, ".nsp0", 5) == 0)
		{
			if(!GetBuffer(m_dwAEPMapped ,0x22, 0x22))
			{
				return iRetStatus;
			}
			DWORD dwLength = 0, dwInstructionCnt = 0, dwOffset = 0;
			t_disasm	da;

			while(dwOffset < m_dwNoOfBytes - 5 && dwInstructionCnt < 0x4)
			{
				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);

				if(dwLength == 3 && dwInstructionCnt == 0 && strstr(da.result, "LEA EDI"))
				{
					dwInstructionCnt++;
				}
				else if(dwLength == 2 && dwInstructionCnt == 1 && strstr(da.result, "CMP AL,8"))
				{
					dwInstructionCnt++;
				}
				else if(dwLength == 3 && dwInstructionCnt == 2 && strstr(da.result, "MOV EAX"))
				{
					dwInstructionCnt++;
				}
				else if(dwLength == 5 && dwInstructionCnt == 3 && strstr(da.result, "PUSH"))
				{
					dwCallOffset = *(DWORD *)&m_pbyBuff[dwOffset + 1]- m_dwImageBase;

					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwCallOffset, &dwCallOffset)) 
					{
						return iRetStatus;
					}
					dwInstructionCnt++;
				}
				dwOffset += dwLength; 
			}
		}
		m_dwNoOfBytes = 0;
		if(dwCallOffset != 0x0 )
		{
			DWORD dwSize2Read = FUJACK_BUFF_SIZE;
			if((m_pMaxPEFile->m_dwFileSize - dwCallOffset) < 0x500)
			{
				dwSize2Read = m_pMaxPEFile->m_dwFileSize - dwCallOffset;
			}
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[m_dwNoOfBytes], dwCallOffset, dwSize2Read, dwSize2Read))
			{
				return iRetStatus;
			}
			m_dwNoOfBytes += dwSize2Read;
		}
		if(m_pMaxPEFile->m_dwFileSize > m_dwAEPMapped)
		{
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[m_dwNoOfBytes], m_dwAEPMapped, 0x500, 0x500))
			{
				return iRetStatus;
			}
			m_dwNoOfBytes += 0x500;
		}
		if(m_pMaxPEFile->m_dwFileSize > 0x100)
		{
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[m_dwNoOfBytes], m_pMaxPEFile->m_dwFileSize - 0x100, 0x100, 0x100))
			{
				return iRetStatus;
			}
			m_dwNoOfBytes += 0x100;
		}

		const TCHAR FUJACK_SIG[] = _T("5789E58D9C2480C1FFFF31C05039DC75FB46465368741105005783EBFC5368DFF500005683EBFC5350C7*5557565383C4848B942490000000C744247400000000C6442473008BAC249C0000008D420489442478B8010000000FB64A0289*D3E389D949894C246C0FB64A01D3E048894424688B8424A80000000FB632C745*394C2474730E8B44247866C700000483C002E2F68B9C2494");
		const TCHAR FUJACK1_SIG[] = _T("722E679BE84B7535BDAB65F6A29E400D454D5D24*9DB31FF198AB5EB77D3316313137333805");
		const TCHAR FUJACK5_SIG[] = _T("5D83ED078D9D81FCFFFF8A033C0074108D9DA9FCFFFF8A033C010F844202*7B0457515253*2A0A8E77EC101C413091D25D47C6BCC578*4F5290CB82C4FCBC3816A45E434B4FB267");
		const TCHAR FUJACK4_SIG[] = _T("2A2D2E2D2A*2E6578652E65786502");
		const TCHAR FUJACK2_SIG[] = _T("424D572121*2E6578652E65786502");
		const TCHAR FUJACK3_SIG[] = _T("5768426F79*2E6578652E65786502");
		const TCHAR FUJACK6_SIG[] = _T("424D572121*2E4558452E65786502");
		const TCHAR FUJACK7_SIG[] = _T("5748424F59*2E4558452E65786502");
		const TCHAR FUJACK8_SIG[] = _T("5748424F59*2E6578652E65786502");
		const TCHAR FUJACK9_SIG[] = _T("2A2D2E2D2A*2E4558452E65786502");
		const TCHAR FUJACKA_SIG[] = _T("5768426F79*2E4558452E65786502");

		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(FUJACK_SIG, _T("Virus.Fujack.CW"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK1_SIG, _T("Virus.Fujack.CW"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK2_SIG, _T("Virus.Fujack.Gen"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK3_SIG, _T("Virus.Fujack.Gen"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK4_SIG, _T("Virus.Fujack.Gen"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK5_SIG, _T("Virus.Fujack.DF"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK7_SIG, _T("Virus.Fujack.DF"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK6_SIG, _T("Virus.Fujack.Gen"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK8_SIG, _T("Virus.Fujack.Gen"), TRUE);
		polydbObj.LoadSigDBEx(FUJACK9_SIG, _T("Virus.Fujack.Gen"), TRUE);
		polydbObj.LoadSigDBEx(FUJACKA_SIG, _T("Virus.Fujack.Gen"), FALSE);

		TCHAR szVirusName[MAX_PATH] = {0};
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			if(FujackParam())
			{				
				iRetStatus= VIRUS_FILE_REPAIR;
			}
			else
			{
				iRetStatus= VIRUS_FILE_DELETE;
			}
		}	
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: FujackParam
	In Parameters	: 
	Out Parameters	: true if success esle false
	Purpose			: 
	Author			: Tushar Kadam + Ravi Bisht + Parjakta + Sandeep Vosaya + Virus Analysis Team
	Description		: This function retrieves all the ncessary info repair routine
--------------------------------------------------------------------------------------*/
bool CPolyFujack::FujackParam()
{ 
	const BYTE bySig[] = {0x42,0x4D,0x57,0x21,0x21};
	const BYTE bySig1[] = {0x57,0x68,0x42,0x6F,0x79};
	const BYTE bySig2[] = {0x2A,0x2D,0x2E,0x2D,0x2A};
	const BYTE bySigEXE[] = {0x2E,0x65,0x78,0x65,0x02};
	const BYTE bySig3[] = {0x57,0x48,0x42,0x4F,0x59};

	for(DWORD i = m_dwNoOfBytes - 0x100; i <= m_dwNoOfBytes - sizeof(bySig); i++)
	{			
		if(memcmp(&m_pbyBuff[i], bySig, sizeof(bySig)) == 0  || memcmp(&m_pbyBuff[i], bySig1, sizeof(bySig1)) == 0 || 
			memcmp(&m_pbyBuff[i], bySig2, sizeof(bySig2)) == 0 || memcmp(&m_pbyBuff[i], bySig3, sizeof(bySig3)) == 0)
		{
			for(DWORD j = i + sizeof(bySig); j < m_dwNoOfBytes - sizeof(bySigEXE); j++)
			{
				if((memcmp(&m_pbyBuff[j], bySigEXE, sizeof(bySigEXE)) == 0) )
				{ 
					DWORD k = j + sizeof(bySigEXE);
					while(m_pbyBuff[k] >= 0x30 && m_pbyBuff[k] <= 0x39 && k < m_dwNoOfBytes)
					{
						k++;
					}
					if(k > (j + sizeof(bySigEXE)))
					{
						char szNumberBuff[MAX_PATH] = {0};
						strncpy_s(szNumberBuff, MAX_PATH, (char *)&m_pbyBuff[(j + sizeof(bySigEXE))], k - (j + sizeof(bySigEXE)));
						m_dwOrifileSize = atoi(szNumberBuff);
						if((m_dwNoOfBytes + 1 -i)+ m_dwOrifileSize < m_pMaxPEFile->m_dwFileSize)
						{
							m_dwStratOFfile = m_pMaxPEFile->m_dwFileSize - ((m_dwNoOfBytes + 1 - i) + m_dwOrifileSize);
							return true;
						}
						return false;
					}
				}
			}
			return false;
		}
	}
	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ravi Bisht + Parjakta + Sandeep Vosaya + Virus Analysis Team
	Description		: Repair routine for different varients of Fujack Family
--------------------------------------------------------------------------------------*/
int CPolyFujack::CleanVirus(void)
{
	if(m_pMaxPEFile->CopyData(m_dwStratOFfile, 0, m_dwOrifileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrifileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyCaw
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyCaw::CPolyCaw(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyCaw
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyCaw::~CPolyCaw(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Caw Family
--------------------------------------------------------------------------------------*/
int CPolyCaw::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if( (m_pSectionHeader[m_wAEPSec].SizeOfRawData==m_pSectionHeader[m_wAEPSec].Misc.VirtualSize) && 
		(m_pSectionHeader[m_wAEPSec].Misc.VirtualSize>0x536) && (m_pSectionHeader[m_wAEPSec].Characteristics==0xE0000040) &&
		((m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-(((0x540/m_pMaxPEFile->m_stPEHeader.FileAlignment)+0x1)*m_pMaxPEFile->m_stPEHeader.FileAlignment)) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-m_pMaxPEFile->m_stPEHeader.FileAlignment) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x5F5) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x58B) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x537) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x615) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x5B1) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x4EE) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x588) ||
		(m_dwAEPUnmapped==m_pSectionHeader[m_wAEPSec].VirtualAddress+m_pSectionHeader[m_wAEPSec].SizeOfRawData-0x5FB) ) &&
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) )
	{
		BYTE byAEPSigbuff[0x40]={0};
		if(m_pMaxPEFile->ReadBuffer(byAEPSigbuff, m_dwAEPMapped, 0x0E, 0x0E))
		{
			if(*(WORD*)&byAEPSigbuff[0] == 0x8B60)
			{
				if(*(DWORD*)&byAEPSigbuff[2] == 0x010F50F0 && *(DWORD*)&byAEPSigbuff[6] == 0x5BFE244C && *(DWORD*)&byAEPSigbuff[0xA] == 0x8B18C383)
				{
					t_disasm da = {0x00};
					DWORD dwOffset=0x00;
					DWORD dwOrigAEP=0x00;
					DWORD dwLength;
					DWORD dwInstructionFound=0x00;

					if(m_pMaxPEFile->ReadBuffer(byAEPSigbuff, m_dwAEPMapped + 0x10, 0x40, 0x40))
					{
						while(dwOffset < (0x40-0xC))
						{
							dwLength = m_objMaxDisassem.Disasm((char*)&byAEPSigbuff[dwOffset], 0x07, 0x400000, &da, DISASM_CODE);

							if(strstr(da.result,"MOV [EBX],AX"))
							{
								if(*(DWORD*)&byAEPSigbuff[dwOffset+0x03]==0x6610E8C1 && *(DWORD*)&byAEPSigbuff[dwOffset+0x07]==0xFB064389)
								{
									dwInstructionFound=0x01;
									dwOffset+=0x08;
								}
							}
							else if(dwInstructionFound==0x01 && (strstr(da.result,"POPAD")||strstr(da.result,"POPFD")))
							{
								if(byAEPSigbuff[dwOffset+0x01]==0xB8 && *(DWORD*)&byAEPSigbuff[dwOffset+0x06]==0xE0FFD0F7)
								{
									m_dwOrigAEP=(~(*(DWORD*)&byAEPSigbuff[dwOffset+0x02]))-m_dwImageBase;
									break;
								}
							}
							dwOffset+=dwLength;
						}

						DWORD dwFlagVirus=0x0;
						if(m_dwOrigAEP>0 && m_dwOrigAEP<=m_pSectionHeader[m_wNoOfSections-0x01].VirtualAddress+m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
						{
							DWORD dwLengthOfVirusCode[0x09]={0x537,0x58B,0x5B1,0x5F5,0x5FB,0x615,0x588,0x4EE,0x5B2};
							if(m_pMaxPEFile->ReadBuffer(byAEPSigbuff,m_dwAEPMapped+dwOffset+0x4C, 0x08, 0x08))
							{
								for(int i=0;i<9;i++)
								{
									if(*(DWORD*)&byAEPSigbuff[0]==dwLengthOfVirusCode[i])
									{
										dwFlagVirus=0x01;
										m_dwSize=*(DWORD*)&byAEPSigbuff[0];
										break;
									}
									else if(*(DWORD*)&byAEPSigbuff[2]==dwLengthOfVirusCode[i])
									{
										dwFlagVirus=0x01;
										m_dwSize=*(DWORD*)&byAEPSigbuff[2];
										break;
									}
									else if(*(DWORD*)&byAEPSigbuff[4]==dwLengthOfVirusCode[i])
									{
										dwFlagVirus=0x01;
										m_dwSize=*(DWORD*)&byAEPSigbuff[4];
										break;
									}
									else if(*(DWORD*)&byAEPSigbuff[1]==dwLengthOfVirusCode[i])
									{
										dwFlagVirus=0x01;
										m_dwSize=*(DWORD*)&byAEPSigbuff[1];
										break;
									}
								}

								if(dwFlagVirus==0x01)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win9x.Caw"));
									return VIRUS_FILE_REPAIR;
								}
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
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of caw Family
--------------------------------------------------------------------------------------*/
int CPolyCaw::CleanVirus(void)
{
	if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, m_dwSize))
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOrigAEP))
		{
			return true;
		}
	}

	return false;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyGinra
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGinra::CPolyGinra(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = m_dwAEPUnmapped;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGinra
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGinra::~CPolyGinra(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Ginra Family
--------------------------------------------------------------------------------------*/
int CPolyGinra::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000000) == 0xC0000000) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) )
	{
		DWORD dwSmily = 0;
		if(!(m_pMaxPEFile->ReadBuffer(&dwSmily, 0x38, 0x4, 0x4)))
		{
			return iRetStatus;
		}
		//Checking the first 4 bytes from 38th offset
		if( dwSmily != 0x0000293B)
		{
			return iRetStatus;
		}
		
		BYTE bGinraArray[0x20] ={0};
		if(!(m_pMaxPEFile->ReadBuffer(bGinraArray, m_dwOriginalAEP, 0x20, 0x20)))
		{
			if(!(m_pMaxPEFile->ReadBuffer(bGinraArray, m_dwAEPMapped, 0x20, 0x20)))
				return iRetStatus;
		}
		// ----------- for repairable samples ---------------
		if((bGinraArray[0x00] == 0xE8) && (bGinraArray[0x05] == 0x5D) && (bGinraArray[0x06] == 0x81) && (bGinraArray[0x07] == 0xED) && 
			(bGinraArray[0x0C] == 0x8B) && (bGinraArray[0x0D] == 0x85) && (bGinraArray[0x12] == 0xFF) && (bGinraArray[0x13] == 0xE0) )
		{
			m_dwOriginalAEP = *(DWORD *)&bGinraArray[0x14];
			if(m_wNoOfSections - 1 != m_pMaxPEFile->Rva2FileOffset(m_dwOriginalAEP - m_dwImageBase, &m_dwOriginalAEP))
			{
				return iRetStatus;
			}
			
			if(m_pbyBuff)
			{
				delete[] m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int GINRA_BUFF_SIZE = 0x700;
			m_pbyBuff = new BYTE[GINRA_BUFF_SIZE];
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}
			memset(m_pbyBuff, 0, GINRA_BUFF_SIZE);
			if(!GetBuffer(m_dwOriginalAEP, GINRA_BUFF_SIZE, GINRA_BUFF_SIZE))
			{
				return iRetStatus;	
			}
			CSemiPolyDBScn polydbObj;	 
			const TCHAR GINRA_SIG[] = {_T("FFFF424A66813A4D5A75*8B493C03CA3BC87FED668139504575E6899560*4000813E4B45524E740583C114EBE88BF18B4E10038D96164000898D8A164000")};
			polydbObj.LoadSigDBEx(GINRA_SIG, _T("Virus.Ginra.3570"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				iRetStatus= VIRUS_FILE_REPAIR;
				return iRetStatus;
			}
		}		
		// ----------- for non repairable samples -------
		else if((m_wNoOfSections - 1 == m_wAEPSec))
		{
			if(m_pbyBuff)
			{
				delete[] m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int GINRA_BUFF_SIZE = 0x700;
			m_pbyBuff = new BYTE[GINRA_BUFF_SIZE];
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}
			memset(m_pbyBuff, 0, GINRA_BUFF_SIZE);
			if(!GetBuffer(m_dwAEPMapped, GINRA_BUFF_SIZE, GINRA_BUFF_SIZE))
			{
				return iRetStatus;	
			}
			const TCHAR GINRA_SIG1[] = {_T("8B1424BB001040002BC38BE88D850C164000FFD08D856A104000FFD08D859A10*4000FFD08D853D114000FFD08D85AB124000FFD08D8561134000FFD08D85B413")};
			const TCHAR GINRA_SIG2[] = {_T("FFFF424A66813A4D5A75*8B493C03CA3BC87FED668139504575E6899560*4000813E4B45524E740583C114EBE88BF18B4E10038D96164000898D8A164000")};
			CSemiPolyDBScn polydbObj;	 
			polydbObj.LoadSigDBEx(GINRA_SIG1, _T("Virus.Ginra.3570"), TRUE);
			polydbObj.LoadSigDBEx(GINRA_SIG2, _T("Virus.Ginra.3570"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Ginra Family
--------------------------------------------------------------------------------------*/
int CPolyGinra::CleanVirus(void)
{
	if(m_pMaxPEFile->CopyData(m_dwOriginalAEP + 0x648, m_dwAEPUnmapped, 0x18))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwOriginalAEP))
		{
			if(m_pMaxPEFile->FillWithZeros(0x38, 0x04))
				return REPAIR_SUCCESS;
		}
	}	
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyDzan
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDzan::CPolyDzan(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOffset= 0x0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDzan
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDzan::~CPolyDzan(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Dzan Family
--------------------------------------------------------------------------------------*/
int CPolyDzan::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections <= 0x5 && (m_wAEPSec == m_wNoOfSections - 0x1 || m_wAEPSec == 0x0)
		&& (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int DZAN_BUFF_SIZE = 0x1000;
		m_pbyBuff = new BYTE[DZAN_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped + 0x7B00, DZAN_BUFF_SIZE))
		{
			return iRetStatus;
		}
		const TCHAR DZANA_SIG[] = {_T("6F70656E000000002F6175746F72756E00000000303100002E72656C6F6300005C6D6D632E657865*536D61727420436172642053757065727669736F720000006D6D63")};
		const TCHAR DZANC_SIG[] = {_T("6F70656E000000002F6175746F72756E00000000636B6173730000005C313032315C73657276696365732E657865*5468656D657320506C756720616E6420506C6179000000007365727669636573")};
		CSemiPolyDBScn polydbObj;	 
		polydbObj.LoadSigDBEx(DZANA_SIG, _T("Virus.Dzan.A"), TRUE);
		polydbObj.LoadSigDBEx(DZANC_SIG, _T("Virus.Dzan.C"), FALSE);
		TCHAR szVirusName[MAX_PATH] = {0};
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			if(!GetBuffer(m_dwAEPMapped + 0xB000, DZAN_BUFF_SIZE, 0x3C))
			{
				return iRetStatus;
			}
			for(DWORD i = 0xD0; i < m_dwNoOfBytes - 0x3C; i++)
			{
				if(m_pbyBuff[i] == 0x4D && m_pbyBuff[i+1] == 0x5A)
				{
					if(*(DWORD *)&m_pbyBuff[i + 0x3C] > m_dwNoOfBytes)
					{
						return iRetStatus;
					}
					if(*(DWORD *)&m_pbyBuff[i + *(DWORD *)&m_pbyBuff[i + 0x3C]] == 0x4550)
					{				
						m_dwOffset = i;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
						return VIRUS_FILE_REPAIR;
					}
				}
			}
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Dzan Family
--------------------------------------------------------------------------------------*/
int CPolyDzan::CleanVirus(void)
{		
	if(m_pMaxPEFile->WriteAEP(*(DWORD *)&m_pbyBuff[m_dwOffset - 0xD0]))
	{
		if(m_pMaxPEFile->RepairOptionalHeader(0x20,*(DWORD *)&m_pbyBuff[m_dwOffset - 0x78], *(DWORD *)&m_pbyBuff[m_dwOffset - 0x74]))
		{
			if(m_pMaxPEFile->RepairOptionalHeader(0x2A,*(DWORD *)&m_pbyBuff[m_dwOffset - 0x28],*(DWORD *)&m_pbyBuff[m_dwOffset - 0x24]))
			{
				DWORD dwFileEndOff = 0;
				if(_tcsstr(m_szVirusName, _T("Virus.Dzan.A")))
				{
					dwFileEndOff = m_pMaxPEFile->m_dwFileSize - 0xF0F0;
				}
				else if(_tcsstr(m_szVirusName, _T("Virus.Dzan.C")))
				{
					dwFileEndOff = m_dwAEPMapped - 0x3500;
				}
				if(m_pMaxPEFile->TruncateFileWithFileAlignment(dwFileEndOff))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyAssill
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAssill::CPolyAssill(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAssill
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAssill::~CPolyAssill(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Assill Family
--------------------------------------------------------------------------------------*/
int CPolyAssill::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL) &&
		((m_wNoOfSections == 4 && m_wAEPSec == 1 && m_dwAEPUnmapped == 0x8A40 && m_pSectionHeader[0].SizeOfRawData == 0) ||
		((m_wNoOfSections == 3 && m_wAEPSec == 0 && m_dwAEPUnmapped == 0x1000 && memcmp(m_pSectionHeader[1].Name, ".Pav", 4) == 0))))
	{
		const BYTE byAssillSig[] = {0x65, 0x6C, 0x6C, 0x69, 0x73, 0x73, 0x61, 0x5F, 0x22, 0x2C, 0x01, 0x04, 0x80, 0xFC, 0xFF, 0x83, 
			0x48, 0x49, 0x44, 0x52, 0x41, 0x47, 0x20, 0x4D, 0x55, 0x53, 0x54, 0x20, 0x44, 0x49, 0x45};
		
		BYTE byBuffer[0x28] = {0};		
		DWORD dwReadOffset = m_wNoOfSections == 4 ? 0x1A48 : 0x8648;
		if(!m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, sizeof(byAssillSig), sizeof(byAssillSig)))
		{
			return iRetStatus;
		}
		if(memcmp(byBuffer, byAssillSig, sizeof(byAssillSig)) == 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, L"Virus.W32.Assill");
			iRetStatus = VIRUS_FILE_DELETE;

			//Virus save information regarding to cleaning of file at the start of overlay of infected file.
			//We read this and extract information.

			if(m_pMaxPEFile->ReadBuffer(byBuffer, m_pSectionHeader[m_wNoOfSections-1].PointerToRawData + m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData + 0x64, 0x28, 0x28))
			{			
				m_dwOriFileSize				= *((DWORD*)&byBuffer[0x0C]);
				m_dwOriRsrcPRD				= *((DWORD*)&byBuffer[4]);
				m_dwOriRsrcSRD				= *((DWORD*)&byBuffer[8]);
				m_dwOriRsrcRVA				= *((DWORD*)&byBuffer[0x18]);
				m_dwOriDataSizeAtFileEnd	= *((DWORD*)&byBuffer[0x10]);
				m_dwNTHeaderStartOffset		= *((DWORD*)&byBuffer[0x14]);

				if(m_dwOriFileSize > m_pMaxPEFile->m_dwFileSize || m_dwOriRsrcPRD > m_pMaxPEFile->m_dwFileSize || 
					m_dwOriRsrcSRD > m_pMaxPEFile->m_dwFileSize || m_dwNTHeaderStartOffset > m_pMaxPEFile->m_dwFileSize ||
					m_dwOriDataSizeAtFileEnd > m_pMaxPEFile->m_dwFileSize)
				{
					return iRetStatus;
				}
				
				if(*((DWORD*)&byBuffer[0x00]) == 0x00)
				{
					m_dwResourcReplacementOffset = m_dwOriRsrcPRD;
					m_dwRewriteAdd = m_dwOriRsrcSRD;
				}
				else if(*((DWORD*)&byBuffer[0x00]) == 0x01)
				{
					m_dwResourcReplacementOffset = m_dwOriFileSize;
					m_dwRewriteAdd = m_dwOriRsrcPRD;
				}
				else
				{
					return iRetStatus;
				}

				if(m_dwNTHeaderStartOffset > 0x1000)
				{
					return iRetStatus;
				}
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Assill Family
--------------------------------------------------------------------------------------*/
int CPolyAssill::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;	
	
	// Copy original File resource at he end of file.
	if(!m_pMaxPEFile->CopyData(m_pSectionHeader[m_wNoOfSections-1].PointerToRawData, m_pMaxPEFile->m_dwFileSize, m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData))
	{
		return iRetStatus;
	}	
	
	const int ASSILL_BUFF_SIZE = m_dwNTHeaderStartOffset + 0x320 + 0x100;
	
	//Here 0x100 is given for safer side. It is not needed. 
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[ASSILL_BUFF_SIZE];	
	if(!GetBuffer(m_dwOriRsrcPRD, ASSILL_BUFF_SIZE, ASSILL_BUFF_SIZE))
	{
		return iRetStatus;
	}
	
	// This function decrypt original file header.
	DecryptAssill();
	
	//After Decryption we write decrypted buffer from we read for decryption
	if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwOriRsrcPRD, ASSILL_BUFF_SIZE, ASSILL_BUFF_SIZE))
	{
		return iRetStatus;
	}

	//Here we copy decrypted bytes from start of resurce to file strt(0x00 offset)
	if(!m_pMaxPEFile->CopyData(m_dwOriRsrcPRD, 0x00, m_dwOriRsrcSRD))
	{
		return iRetStatus;
	}
	//Here we copy 0x232c bytes from the end of file to last write finish.
	if(!m_pMaxPEFile->CopyData(m_dwOriFileSize, m_dwRewriteAdd, m_dwOriDataSizeAtFileEnd))
	{
		return iRetStatus;
	}

	//Now before writing resource back we need to fix RVA in resource.
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	
	//If resource size is less than 0x10000 then we read whole buffer and send it to FixRes
	//otherwise 0x10000 bytes we send to FixRes as it needs only header not data so there is no harm sendin 0x10000 bytes.
	DWORD dwSizeOfRead = (m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData > 0x10000) ?  0x10000 : m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData;
	
	m_pbyBuff = new BYTE[dwSizeOfRead];	
	if(!GetBuffer(m_pMaxPEFile->m_dwFileSize, dwSizeOfRead, dwSizeOfRead))
	{
		return iRetStatus;
	}

	FiXRes((IMAGE_RESOURCE_DIRECTORY *)&m_pbyBuff[0], &m_pbyBuff, (m_dwOriRsrcRVA - m_pSectionHeader[m_wNoOfSections-1].VirtualAddress));

	//Here we write back fixed resource at the end of file and then move it its original place by using CopyData function
	if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_pMaxPEFile->m_dwFileSize, dwSizeOfRead, dwSizeOfRead))
	{		
		DWORD dwBytesRead = 0;
		for(DWORD dwOffset = 0; dwOffset < m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData; dwOffset += dwSizeOfRead)
		{		
			memset(m_pbyBuff, 0, dwSizeOfRead);
			m_pMaxPEFile->SetFilePointer(m_pMaxPEFile->m_dwFileSize + dwOffset);
			if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwSizeOfRead, &dwBytesRead))
			{
				if((dwOffset + dwSizeOfRead) > m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData || dwBytesRead != dwSizeOfRead)
				{
					dwBytesRead = m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData - dwOffset;
				}
				if(!m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwResourcReplacementOffset + dwOffset, dwBytesRead, dwBytesRead))
				{
					return iRetStatus;
				}
			}
		}
		
		//if(m_pMaxPEFile->CopyData(m_pMaxPEFile->m_dwFileSize, m_dwResourcReplacementOffset, m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData))
		{
			//Virus Save original file size so we truncate it from there.
			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - 0x232C))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;	
}
/*-------------------------------------------------------------------------------------
	Function		: DecryptAssill
	In Parameters	: 
	Out Parameters	:
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Decryption routine for Assill Family
--------------------------------------------------------------------------------------*/
void CPolyAssill::DecryptAssill()
{	
	DWORD dwIndex = 0x00;
	for(dwIndex = 0x00; dwIndex < (m_dwNTHeaderStartOffset < 0x96 ? m_dwNTHeaderStartOffset : 0x96); dwIndex++)
	{
		m_pbyBuff[dwIndex] = (0xFF - m_pbyBuff[dwIndex]) ^ 0x0A;
	}
	for(dwIndex = 0; dwIndex < 0x320; dwIndex++)
	{
		m_pbyBuff[dwIndex + m_dwNTHeaderStartOffset] = (0xFF - m_pbyBuff[dwIndex + m_dwNTHeaderStartOffset]) ^ 0x0A;
	}
	DWORD dwCounter = 0x00, dwMoveNoBytes = m_dwNTHeaderStartOffset;
	int i = 0xC8 + m_dwNTHeaderStartOffset;
	BYTE byTemp = 0x00;
	
	for(dwCounter = 0x00; dwCounter < 0x65; dwCounter++, i--)
	{		
		byTemp = m_pbyBuff[i];
		m_pbyBuff[i] = m_pbyBuff[i - 0x64];
		m_pbyBuff[i -0x64]  = byTemp;
	}

	dwMoveNoBytes = m_dwNTHeaderStartOffset;
	i = dwMoveNoBytes - 0x01;
	int j = dwMoveNoBytes + 0x32A;
	byTemp = 0x00;
	
	for(dwCounter = 0x00; dwCounter < 0x4F; dwCounter++)
	{
		i += 0x02;
		j -= 0x0A;

		byTemp = m_pbyBuff[i];
		m_pbyBuff[i] = m_pbyBuff[j];
		m_pbyBuff[j] = byTemp;
	}

	dwMoveNoBytes = m_dwNTHeaderStartOffset;
	i = dwMoveNoBytes + 0x39;
	j = dwMoveNoBytes;
	byTemp = 0x00;
	for(dwCounter = 0x00; dwCounter < 0x27; dwCounter++)
	{
		i += 0x02;
		j += 0x14;

		byTemp = m_pbyBuff[i];
		m_pbyBuff[i] = m_pbyBuff[j];
		m_pbyBuff[j] = byTemp;
	}
	byTemp = m_pbyBuff[m_dwNTHeaderStartOffset + 1];
	m_pbyBuff[m_dwNTHeaderStartOffset + 1] = m_pbyBuff[0];
	m_pbyBuff[0] = m_pbyBuff[j + 0x14];
	m_pbyBuff[j + 0x14] = byTemp;
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: FiXRes
	In Parameters	: IMAGE_RESOURCE_DIRECTORY *dir, BYTE **root, DWORD delta
	Out Parameters	:
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Reapair routine for Resource table
--------------------------------------------------------------------------------------*/
void CPolyAssill::FiXRes(IMAGE_RESOURCE_DIRECTORY *dir, BYTE **root, DWORD delta)
{
	IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
	for(int i = 0; i < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; i++, entry++)
	{
		void *ptr = *root + entry->OffsetToDirectory;
		if (entry->DataIsDirectory) 
		{
			FiXRes( (IMAGE_RESOURCE_DIRECTORY*)ptr, root, delta);
		}
		else
		{
			IMAGE_RESOURCE_DATA_ENTRY *data = (IMAGE_RESOURCE_DATA_ENTRY*)ptr;
			if (data->OffsetToData) 
			{
				data->OffsetToData += delta;
			}
		}
	}
}

/********************************************************************************************************
Analyst     : Prajakta
Type        : Trojan (Downloader) + File Infector
Name        : Trojan.Downloader.Tolsty.A
Description : A. Installation: 
		 1. When executed trojan copies itself as the following files:
		     %System32%\Windows 3D.scr
		     %System32%\CommandPrompt.sysm
		     %System32%\Desktop.sysm
		     C:\Documents and Settings\<USER>\Application Data\Microsoft\[4 RANDOM LETTERS].exe
		     C:\MyImages.exe
		     C:\Palma.exe	

		 2. Also creates following files:
		     %System32%\maxtrox.txt
	             C:\Documents and Settings\<USER>\Application Data\Microsoft\[4 RANDOM LETTERS]
		      
		 3. Then creates the following folders with hidden attributes:
		     C:\Documents and Settings\<USER>\Applications Data
        	     C:\Documents and Settings\<USER>\Applications Data\Microsoft
		     C:\Documents and Settings\<USER>\Applications Data\Media Player
                     C:\Documents and Settings\<USER>\Applications Data\Office
                     C:\Documents and Settings\<USER>\Applications Data\Word
                     C:\Documents and Settings\<USER>\Applications Data\Excel
                     C:\Documents and Settings\<USER>\Applications Data\Windows

	      B. Infects .exe files in the following folder: %ProgramFiles%

	      C. Registry Modifications: Ensures subsequent autorun of installed files when Windows starts & also when
		 computer is started in safe mode,also disables regedit,search option & hides file extension,etc.
	      
********************************************************************************************************/
/*-------------------------------------------------------------------------------------
	Function		: CPolyDownloaderTolstyA
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDownloaderTolstyA::CPolyDownloaderTolstyA(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwDecOffset = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDownloaderTolstyA
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDownloaderTolstyA::~CPolyDownloaderTolstyA(void)
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
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of Downloader.Tolsty.A Family
					  1. When executed trojan copies itself as the following files:
						%System32%\Windows 3D.scr
						%System32%\CommandPrompt.sysm
						%System32%\Desktop.sysm
						C:\Documents and Settings\<USER>\Application Data\Microsoft\[4 RANDOM LETTERS].exe
						C:\MyImages.exe
						C:\Palma.exe	
					2. Also creates following files:
						%System32%\maxtrox.txt
						C:\Documents and Settings\<USER>\Application Data\Microsoft\[4 RANDOM LETTERS]
					 3. Then creates the following folders with hidden attributes:
						C:\Documents and Settings\<USER>\Applications Data
        				C:\Documents and Settings\<USER>\Applications Data\Microsoft
						C:\Documents and Settings\<USER>\Applications Data\Media Player
						C:\Documents and Settings\<USER>\Applications Data\Office
						C:\Documents and Settings\<USER>\Applications Data\Word
						C:\Documents and Settings\<USER>\Applications Data\Excel
						C:\Documents and Settings\<USER>\Applications Data\Windows
			      B. Infects .exe files in the following folder: %ProgramFiles%
			      C. Registry Modifications: Ensures subsequent autorun of installed files when Windows starts & also when
					 computer is started in safe mode,also disables regedit,search option & hides file extension,etc.
--------------------------------------------------------------------------------------*/
int CPolyDownloaderTolstyA::DetectVirus(void)
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections > 0x3 || m_wAEPSec != 0x0 || m_dwAEPUnmapped != 0x11A8 || 
		m_pMaxPEFile->m_stPEHeader.CheckSum != 0x17E34) 
	{
		return iRetStatus;
	}

	if(m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x105A4 && m_pSectionHeader[0x2].Misc.VirtualSize == 0x620
		&& m_pSectionHeader[0x1].SizeOfRawData == 0x0 && m_pSectionHeader[0x1].PointerToRawData == 0x0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int TOLSTYA_BUFF_SIZE = 0x3000;
		m_pbyBuff = new BYTE[TOLSTYA_BUFF_SIZE];
		if(!GetBuffer(m_dwAEPUnmapped, 0x220, 0x220))
		{
			return iRetStatus;
		}
		CSemiPolyDBScn	polydbObj;
		TCHAR	szVirusName[MAX_PATH] = {0};
		TCHAR	szDOWNLOADERTOLSTYA[] = {_T("500000003B6C5B138FDDA74792ED8B98429A6E98*57696E646F77732053797374656D*F4010000E8214000000000002014410030144100")};
		polydbObj.LoadSigDBEx(szDOWNLOADERTOLSTYA, _T("Trojan.Downloader.Tolsty.A"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			const BYTE bSig[] = {0x76,0x61,0x72,0x70}; //varp
			if(!GetBuffer(0x2F38, sizeof(bSig), sizeof(bSig)))
			{
				return iRetStatus;
			}
			if(memcmp(&m_pbyBuff[0x0], bSig, sizeof(bSig)) == 0)
			{
				BYTE bSig[] = {0x08,0x00,0x09,0x00,0xA0,0xA0,0xA0,0x00,0xA0,0x00,0xA0};
				DWORD dwBytesCnt = m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData;
				if(dwBytesCnt < sizeof(bSig))
				{
					return iRetStatus;
				}

				DWORD dwBytes2Read = 0x3000;
				if(dwBytesCnt < 0x3000)
				{
					dwBytes2Read = dwBytesCnt;
				}
				
				if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData, dwBytes2Read, dwBytes2Read))
				{
					return iRetStatus;
				}
				
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				iRetStatus = VIRUS_FILE_DELETE;

				DWORD dwIndex = 0x0;
				if(OffSetBasedSignature(bSig, sizeof(bSig), &dwIndex))
				{
					m_dwDecOffset = dwIndex + sizeof(bSig);
					m_pbyBuff[m_dwDecOffset] = 0x4D;
					m_pbyBuff[m_dwDecOffset + 0x1] = 0x5A;
					for(DWORD i = m_dwDecOffset + 0x2; i < m_dwDecOffset + 0x98; i++)
					{
						m_pbyBuff[i] -= 0x2;
					}
					iRetStatus = VIRUS_FILE_REPAIR;
				}				
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Repair routine for different varients of Downloader.Tolsty.A Family
--------------------------------------------------------------------------------------*/
int CPolyDownloaderTolstyA::CleanVirus(void)
{
	DWORD dwReplaceOffset = m_pSectionHeader[m_wNoOfSections -1].PointerToRawData + m_dwDecOffset;
	DWORD dwOriFileSize = m_pMaxPEFile->m_dwFileSize - dwReplaceOffset;
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwDecOffset], dwReplaceOffset, 0x98))
	{		
		if(m_pMaxPEFile->CopyData(dwReplaceOffset, 0x0, dwOriFileSize))
		{
			if(m_pMaxPEFile->ForceTruncate(dwOriFileSize))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyAlimik
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlimik::CPolyAlimik(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAlimik
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAlimik::~CPolyAlimik(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Alimik Family
--------------------------------------------------------------------------------------*/
int CPolyAlimik::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	// Checking if the Last Section PRD+SRD=1600h||1800h||1A00h + No. of sections=4 + Checksum=0 + PE Header Characteristics=818E
	// These are entry level checks to detect the presence of an infected file
	if(m_wAEPSec==m_wNoOfSections-1 && m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Misc.VirtualSize>0x16EA && m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].SizeOfRawData!=m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Misc.VirtualSize &&
		(m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Characteristics&0xE0000060)==0xE0000060)
	{	
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int ALIMIK_BUFF_SIZE = 0x150;
		m_pbyBuff = new BYTE[ALIMIK_BUFF_SIZE];
		memset(m_pbyBuff,0,ALIMIK_BUFF_SIZE);
		if(GetBuffer(m_pMaxPEFile->m_stPEHeader.e_lfanew+0x0C, 0x04, 0x04))
		{
			if(*(DWORD*)&m_pbyBuff[0]==0x00575249)
			{	
				// Spit Signature:-SPIT.Win32 is a Bumblebee Win32 Virus....Feel the power of Spain and die by the SpiT
				const TCHAR Alimik_5886_Sig[] = {_T("427920306E4C7931202D2053544D494B20414B414B4F4D*2F63617269*EA1600")};		

				CSemiPolyDBScn polydbObj;
				polydbObj.LoadSigDBEx(Alimik_5886_Sig, _T("Virus.Alimik.5886"), FALSE);

				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				m_pbyBuff = new BYTE[ALIMIK_BUFF_SIZE];
				TCHAR szVirusName[MAX_PATH] = {0};

				if(GetBuffer(m_dwAEPMapped+0xD1E, ALIMIK_BUFF_SIZE, ALIMIK_BUFF_SIZE))
				{
					if(polydbObj.ScanBuffer(&m_pbyBuff[0], ALIMIK_BUFF_SIZE, szVirusName) >= 0)
					{
						if(_tcslen(szVirusName) > 0)
						{
							iRetStatus = VIRUS_FILE_REPAIR;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
						}
						
					}
				}					
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Almik Family
--------------------------------------------------------------------------------------*/
int CPolyAlimik::CleanVirus(void)
{
	if(!GetBuffer(m_dwAEPMapped+0x35E,0x04,0x04))
	{
		return false;
	}
	if(!m_pMaxPEFile->WriteAEP(*(DWORD*)&m_pbyBuff[0]-m_dwImageBase))
	{
		return false;
	}
	if(!m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
	{
		return false;
	}
	return true;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyNumrock
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyNumrock::CPolyNumrock(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwVirusCodeOffset=0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyNumrock
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyNumrock::~CPolyNumrock(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Numrock Family
--------------------------------------------------------------------------------------*/
int CPolyNumrock::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_wAEPSec != m_wNoOfSections-1 && (m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Characteristics & 0xA0000020) == 0xA0000020 &&
		*(DWORD *)&m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].PointerToRelocations == 0x6E526F4B))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int NUMROCK_BUFF_SIZE = 0x18;
		m_pbyBuff = new BYTE[NUMROCK_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, NUMROCK_BUFF_SIZE);

		if(GetBuffer(m_dwAEPMapped, 0x06, 0x06))
		{
			if(m_pbyBuff[0] == 0x68 && m_pbyBuff[5] == 0xC3 && 
				*(DWORD *)&m_pbyBuff[1] - m_dwImageBase == m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].Misc.VirtualSize - 0x5C6)
			{
				m_dwVirusCodeOffset = *(DWORD *)&m_pbyBuff[1] - m_dwImageBase;
				if(m_pMaxPEFile->Rva2FileOffset(m_dwVirusCodeOffset, &m_dwVirusCodeOffset) == 0xFF)
				{
					return iRetStatus;					
				}
				if(GetBuffer(m_dwVirusCodeOffset, 0x05, 0x05))
				{
					if(m_pbyBuff[0] == 0xE9 && *(DWORD*)&m_pbyBuff[1] == 0x225)
					{
						BYTE NUMROCK_SIG[]={0xB9,0x25,0x02,0x00,0x00,0x8D,0x9D,0x05,0x10,0x40,0x00,0x30,0x0B,0x83,0xC3,0x01,0xE2,0xF9};
						if(GetBuffer(m_dwVirusCodeOffset+0x225+0x05+0x1DB,sizeof(NUMROCK_SIG),sizeof(NUMROCK_SIG)))
						{
							if(memcmp(m_pbyBuff, NUMROCK_SIG, sizeof(NUMROCK_SIG))==0x00)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Numrock.1478"));
								return VIRUS_FILE_REPAIR;
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
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Numrock Family
--------------------------------------------------------------------------------------*/
int CPolyNumrock::CleanVirus(void)
{
	if(GetBuffer(m_dwVirusCodeOffset + 0x5BA, 0x06, 0x06))
	{
		if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPMapped, 0x06, 0x06))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusCodeOffset))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMiam
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMiam::CPolyMiam(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwAEPFileOffset = 0;
	m_dwVirusCodeOffset = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMiam
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMiam::~CPolyMiam(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Miam Family
--------------------------------------------------------------------------------------*/
int CPolyMiam::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if( (m_wAEPSec != m_wNoOfSections - 1 && m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Characteristics == 0xE0000020))
	{
		for(DWORD i = 0; i < m_wNoOfSections; i++)
		{
			if((m_pMaxPEFile->m_stSectionHeader[i].Characteristics & 0xE0000020) != 0xE0000020)
			{
				return iRetStatus;
			}
		}

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int MIAM_BUFF_SIZE = 0x18;
		m_pbyBuff = new BYTE[MIAM_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff, 0, MIAM_BUFF_SIZE);

		if(GetBuffer(0x38, 0x02, 0x02))
		{
			if(*(WORD *)&m_pbyBuff[0] == 0x293B)
			{
				m_dwAEPFileOffset = m_dwAEPMapped;
				if(m_pMaxPEFile->m_stPEHeader.SectionAlignment != m_pMaxPEFile->m_stPEHeader.FileAlignment)
				{
					m_dwAEPFileOffset = m_dwAEPUnmapped;
				}

				if(GetBuffer(m_dwAEPFileOffset, MIAM_BUFF_SIZE, MIAM_BUFF_SIZE))
				{
					BYTE MIAM_SIG[]={0xE8,0x00,0x00,0x00,0x00,0x5D,0x81,0xED,0x4A,0x17,0x40,0x00,0x8B,0x85,0x59,0x17,0x40,0x00,0xFF,0xE0};
					if(memcmp(m_pbyBuff, MIAM_SIG, sizeof(MIAM_SIG)) == 0x00)
					{
						if(*(DWORD *)&m_pbyBuff[MIAM_BUFF_SIZE - 0x04] - m_dwImageBase == m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections-1].Misc.VirtualSize-0x13F6)
						{
							m_dwVirusCodeOffset = *(DWORD*)&m_pbyBuff[MIAM_BUFF_SIZE-0x04] - m_dwImageBase;
							if(m_pMaxPEFile->Rva2FileOffset(m_dwVirusCodeOffset, &m_dwVirusCodeOffset) != OUT_OF_FILE)
							{
								BYTE MIAM_VIRUS_SIG[]={0x8B,0x14,0x24,0xBB,0x00,0x10,0x40,0x00,0x2B,0xC3,0x8B,0xE8,0x8D,0x85,0x21,0x17,0x40,0x00,0xFF,0xD0,0x8D,0x85,0x72};
								if(GetBuffer(m_dwVirusCodeOffset,sizeof(MIAM_VIRUS_SIG),sizeof(MIAM_VIRUS_SIG)))
								{
									if(memcmp(m_pbyBuff,MIAM_VIRUS_SIG,sizeof(MIAM_VIRUS_SIG))==0x00)
									{
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Miam.5110"));
										return VIRUS_FILE_REPAIR;
									}
								}
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
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Miam Family
--------------------------------------------------------------------------------------*/
int CPolyMiam::CleanVirus(void)
{
	if(GetBuffer(m_dwVirusCodeOffset + 0x75D, 0x18, 0x18))
	{
		if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, m_dwAEPFileOffset, 0x18, 0x18))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwVirusCodeOffset))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolyHllpSemisoft
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHllpSemisoft::CPolyHllpSemisoft(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	dwReplaceOffset = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHllpSemisoft
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHllpSemisoft::~CPolyHllpSemisoft(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Semisoft Family
					  Virus.W32.Hllp.Semisoft (Variants covered A,B,C,D,E,F,H,I,J,K,L,M,N)
--------------------------------------------------------------------------------------*/
int CPolyHllpSemisoft::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x5 && m_wAEPSec == 0x0 && 
		memcmp(m_pSectionHeader[m_wNoOfSections - 0x2].Name,".idata",6) == 0)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int SEMISOFT_BUFF_SIZE = 0x500;
		m_pbyBuff = new BYTE[SEMISOFT_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_pSectionHeader[0x2].PointerToRawData,SEMISOFT_BUFF_SIZE,SEMISOFT_BUFF_SIZE))
		{
			return iRetStatus;
		}
		CSemiPolyDBScn	polydbObj;
		TCHAR	szVirusName[MAX_PATH] = {0};
		TCHAR	szHLLPSEMISOFT[] = {_T("5C53746172744D7E315C50726F6772616D735C537461727455705C4578706C6F72652E657865*57494E4950582E455845*633A5C746573746578652E657865")};
		                           //\StartM~1\Programs\StartUp\Explore.exe*WINIPX.EXE*c:\testexe.exe
		
		polydbObj.LoadSigDBEx(szHLLPSEMISOFT, _T("Virus.W32.Hllp.Semisoft"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
			if(OUT_OF_FILE != dwOverlayStart && dwOverlayStart != m_pMaxPEFile->m_dwFileSize)
			{
				if(!GetBuffer(dwOverlayStart, 0x100, 0x100))
				{
					return iRetStatus;
				}
				const BYTE bSig[] = {0x4D, 0x59, 0x4C, 0x45, 0x4E, 0x3D};//MYLEN=
				if((memcmp(&m_pbyBuff[0x1], bSig, sizeof(bSig)) == 0) && *((DWORD *)&m_pbyBuff[0x7]) == dwOverlayStart)
				{
					for(DWORD i = 0;i < 0x100; i++)
					{
						if(m_pbyBuff[i] == 0x4D && m_pbyBuff[i+1] == 0x5A)
						{
							dwReplaceOffset = dwOverlayStart + i;
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
							return VIRUS_FILE_REPAIR;
						}
					}
				}
			}
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Semisoft Family
--------------------------------------------------------------------------------------*/
int CPolyHllpSemisoft::CleanVirus(void)
{
	DWORD dwOriFileSize = m_pMaxPEFile->m_dwFileSize - dwReplaceOffset;
	if(m_pMaxPEFile->CopyData(dwReplaceOffset, 0x0, dwOriFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(dwOriFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolyGloria
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGloria::CPolyGloria(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{	
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGloria
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGloria::~CPolyGloria(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Gloria Family
					  Covered virus.W32.Gloria.2928 and virus.W32.Gloria.2820
--------------------------------------------------------------------------------------*/
int CPolyGloria::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec != 0x00 || m_pMaxPEFile->m_stSectionHeader[m_wAEPSec].Misc.VirtualSize != 0x3000 ||
		(memcmp(m_pSectionHeader[m_wAEPSec].Name,"CODE", 4) && memcmp(m_pSectionHeader[m_wAEPSec].Name,".CODE", 5)) != 0)
	{
		return iRetStatus;
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x345];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	TCHAR szVirusName[MAX_PATH] = {0};
	CSemiPolyDBScn polydbObj;

	if(m_dwAEPUnmapped == 0x1000)		// checking for Stub
	{
		if(GetBuffer(m_dwAEPMapped + 0x800, 0x344, 0x344)) // Getting  virus name from infected file
		{
			// Sign for virus.Gloria.2928:: Virus Gloria.A*For my sweet Gloria
			const TCHAR szGloria2928Sig[] = {_T("5669727573202020476c6f7269612e41*466f72206d7920737765657420476c6f726961")};
			// Sign for virus.Gloria.2820:: ALucky 2000* from Germany
			const TCHAR szGloria2820Sig[] = {_T("414C75636B792032303030*66726F6D204765726D616E79")};

			polydbObj.LoadSigDBEx(szGloria2928Sig, _T("Virus.W32.Gloria.2928"), TRUE);
			polydbObj.LoadSigDBEx(szGloria2820Sig, _T("Virus.W32.Gloria.2820"), FALSE);
		
			if((polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0) || 
				(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_DELETE;		// for stub
			}
		}
	}

	if(!GetBuffer(m_dwAEPMapped + 0x0E, 0x40, 0x40)) 
	{
		return iRetStatus;
	}

	const TCHAR szGloria2928_Sig1[] = {_T("E98B64240833DB648F0383C404BF*8B07D1C883E819C1C00283C011C1C80240D1C035*F7D0890783C704E2DF")};
	polydbObj.LoadSigDBEx(szGloria2928_Sig1, _T("Virus.W32.Gloria"), FALSE);

	if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
	{
		if(_tcslen(szVirusName) > 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

			if((m_dwAEPMapped + 0x923) > m_pMaxPEFile->m_dwFileSize)  // checking for not properly infected files
			{
				return VIRUS_FILE_DELETE;
			}

			DWORD dwDecrpKey = 0x0, dwDecrpSize = 0x0;
			m_pMaxPEFile->ReadBuffer(&dwDecrpSize, m_dwAEPMapped + 0x22, sizeof(WORD), sizeof(WORD));// to differentiate Gloria.2928 && GLoria.2820 taking size of virus code
			m_pMaxPEFile->ReadBuffer(&dwDecrpKey, m_dwAEPMapped + 0x3A, sizeof(DWORD), sizeof(DWORD));  // Reading Key for decryption

			if(!GetBuffer(m_dwAEPMapped + 0x923, 0x18, 0x18))// Getting buffer for encrypted AEP
			{
				return false;
			}

			for(DWORD i=0x00; i < 0x18; i+=0x04)  // Decryption loop to obtain AEP
			{
				*((DWORD *)&m_pbyBuff[i]) = ~((_lrotl(((_lrotr(((_lrotl(((_lrotr(*(DWORD *)&m_pbyBuff[i],0x1))-0x19),0x02))+0x11),0x02))+1),0x1))^dwDecrpKey);
			}

			if(dwDecrpSize == 0x3B3)  // Size of virus code For gloria.2820
			{
				m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[1];
			}
			else if(dwDecrpSize == 0x3CE) // size of virus code For gloria.2928
			{
				m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0x14];
			}
			else
			{
				return VIRUS_FILE_DELETE;
			}
			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Gloria Family
--------------------------------------------------------------------------------------*/
int CPolyGloria::CleanVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwAEPMapped))
		{
			if(m_pMaxPEFile->CalculateImageSize())
			{ 
				// Code for Deletion of newly added CODE section header which is actually appended at end but the section header order is wrong i.e present at first 
				m_wNoOfSections -= 1;
				DWORD dwHeaderSize = m_wNoOfSections * IMAGE_SIZEOF_SECTION_HEADER;
				m_pMaxPEFile->WriteBuffer(&m_wNoOfSections,m_pMaxPEFile->m_stPEHeader.e_lfanew + 6,0x02,0x02);

				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				m_pbyBuff = new BYTE[dwHeaderSize];

				if(!GetBuffer((m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + sizeof(DWORD) + IMAGE_SIZEOF_SECTION_HEADER),dwHeaderSize,dwHeaderSize))
				{
					return false;
				}
				m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0],(m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + sizeof(DWORD)), dwHeaderSize, dwHeaderSize);
				m_pMaxPEFile->FillWithZeros((m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + sizeof(DWORD) + (IMAGE_SIZEOF_SECTION_HEADER * m_wNoOfSections)),IMAGE_SIZEOF_SECTION_HEADER);

				return REPAIR_SUCCESS;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyVBITL
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVBITL::CPolyVBITL(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwDecOffset = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVBITL
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyVBITL::~CPolyVBITL(void)
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
	Author			: Tushar Kadam + satish + Virus Analysis Team
	Description		: Detection routine for different varients of VBITL Family
					  1. Infects .exe files in the following folder: %ProgramFiles%
		     	      2. Registry Modifications: Ensures subsequent autorun of installed files when Windows starts & also when
						computer is started in safe mode,also disables regedit,search option & hides file extension,etc.
--------------------------------------------------------------------------------------*/
int CPolyVBITL::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;	
	if(m_pMaxPEFile->m_stPEHeader.MinorImageVersion == 0xB54 && m_pMaxPEFile->m_stPEHeader.MajorImageVersion == 0x6 && 
		m_dwAEPUnmapped == 0x11A8 && m_pSectionHeader[0].SizeOfRawData == 0x11000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		m_pbyBuff = new BYTE[0x3000];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		memset(m_pbyBuff,0x00,0x3000);
		BYTE D_sig[] = {0x5B,0x00,0x57,0x00,0x4F,0x00,0x72,0x00,0x2D,0x00,0x68,0x00,0x6D,0x00,0x68};
		/*signature:     [.W.o.r.-.h.m.h*/
		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x2814,0x20,0x20))
		{
			if(memcmp(&m_pbyBuff[0x00],D_sig,sizeof(D_sig)) == 0)
			{
				DWORD dwIndex = 0x0, dwBytes2Read = 0x0;
				BYTE bSig[] = {0x08,0x00,0x09,0x00,0xA0,0xA0,0xA0,0x00,0xA0,0x00,0xA0};
				DWORD dwBytesCnt = m_pMaxPEFile->m_dwFileSize - m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData ;
				if(dwBytesCnt < 0x3000)
				{
					dwBytes2Read = dwBytesCnt;
				}
				else 
				{
					dwBytes2Read = 0x3000;
				}
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Downloader.VB.itl"));
				if(!GetBuffer(m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData , dwBytes2Read, dwBytes2Read))
				{
					return VIRUS_FILE_DELETE;
				}				
				if(OffSetBasedSignature(bSig, sizeof(bSig), &dwIndex))
				{
					m_dwDecOffset = dwIndex + sizeof(bSig);
					m_pbyBuff[m_dwDecOffset] = 0x4D;
					m_pbyBuff[m_dwDecOffset + 0x1] = 0x5A;
					for(DWORD i = m_dwDecOffset + 0x2; i < m_dwDecOffset + 0x98; i++)
					{
						m_pbyBuff[i] -= 0x2;
					}					
					return VIRUS_FILE_REPAIR;
				}				
				return VIRUS_FILE_DELETE;				
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Satish + Virus Analysis Team
	Description		: Repair routine for different varients of VBITL Family
--------------------------------------------------------------------------------------*/
int CPolyVBITL::CleanVirus()
{
	DWORD dwReplaceOffset = m_pSectionHeader[m_wNoOfSections -1].PointerToRawData + m_dwDecOffset;
	DWORD dwOriFileSize = m_pMaxPEFile->m_dwFileSize - dwReplaceOffset;
	if(!m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwDecOffset], dwReplaceOffset, 0x98))
	{
		return REPAIR_FAILED;
	}
	if(m_pMaxPEFile->CopyData(dwReplaceOffset, 0x0, dwOriFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(dwOriFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyGameThiefLmirOA
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGameThiefLmirOA::CPolyGameThiefLmirOA(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwReplaceOff = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGameThiefLmirOA
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGameThiefLmirOA::~CPolyGameThiefLmirOA(void)
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
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of Trojan-GameThief.Lmir.OA Family
					  A. When triggered drops file with name "YZH.exe" in %Windir% with hidden attributes.
				      B. Infect's all files with ".exe" extension & also maintains original copies of few infected file's 
					     by creating ".tmp" file.
				      C. Registry Modifications:
						It adds registry entries to enable automatic execution of "YZH.exe" every time Windows starts.
--------------------------------------------------------------------------------------*/
int CPolyGameThiefLmirOA::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_dwAEPUnmapped == 0x2C5E4 && ((m_wNoOfSections == 0x8 && m_wAEPSec == 0x0 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x2BC60) ||
		(m_wNoOfSections == 0x3 && m_wAEPSec == 0x1 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x14000)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int GAMETHIEFLMIROA_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[GAMETHIEFLMIROA_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!GetBuffer(m_dwAEPMapped + 0x5DC, GAMETHIEFLMIROA_BUFF_SIZE, GAMETHIEFLMIROA_BUFF_SIZE))
		{
			return iRetStatus;
		}

		CSemiPolyDBScn	polydbObj;
		TCHAR	szGameThiefLmirOA[] = {_T("2E746D70*2E73797300000000595A4800474A48*595A4800FFFFFFFF040000002E657865*52756E000000FFFFFFFF090000002E657865202F7A686A")};
		polydbObj.LoadSigDBEx(szGameThiefLmirOA, _T("Trojan-GameThief.Lmir.OA"), FALSE);

		TCHAR	szVirusName[MAX_PATH] = {0};
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			DWORD dwOverlayOff = m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections -1].PointerToRawData;
			
			const BYTE bLmirSig[] = {0x53,0x79,0x70,0x68,0x69,0x6C,0x69,0x73,0x20,0x4E,0x6F,0x2E,0x31};//Syphilis No.1
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwFileSize - 0x13,sizeof(bLmirSig),sizeof(bLmirSig)))
			{
				return iRetStatus;
			}
			if(dwOverlayOff < m_pMaxPEFile->m_dwFileSize &&  dwOverlayOff != 0x0)
			{
				if(memcmp(&m_pbyBuff[0x0],bLmirSig,sizeof(bLmirSig)) == 0)
				{
					if(m_wNoOfSections == 0x8)
					{
						m_dwReplaceOff = dwOverlayOff;
					}
					else 
					{
						DWORD dwOff = 0x0;
						if(!m_pMaxPEFile->ReadBuffer(&dwOff,m_pMaxPEFile->m_dwFileSize - 0x4,sizeof(DWORD),sizeof(DWORD)))
						{
							return iRetStatus;
						}
						if(OUT_OF_FILE == dwOff || dwOff == 0x0)
						{
							return iRetStatus;
						}
						m_dwReplaceOff = dwOff;
					}
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_REPAIR;
				}
			}
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of GameThiefLmir.OA Family
--------------------------------------------------------------------------------------*/
int CPolyGameThiefLmirOA::CleanVirus(void)
{
	if(m_pMaxPEFile->CopyData(m_dwReplaceOff, 0x0, m_pMaxPEFile->m_dwFileSize - m_dwReplaceOff))
	{
		if(m_pMaxPEFile->ForceTruncate((m_pMaxPEFile->m_dwFileSize - m_dwReplaceOff) - 0x14))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyKurgan
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKurgan::CPolyKurgan(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x0, m_dwBuffStart = 0x0, m_dwWriteSize = 0x0, m_dwImageSize = 0x0,m_dwTruncateOff=0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKurgan
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKurgan::~CPolyKurgan(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Kurgan Family
--------------------------------------------------------------------------------------*/
int CPolyKurgan::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->m_stPEHeader.CheckSum == 0xFFFFFFFF)
	{
		DWORD dwMaxRVA = m_pSectionHeader[0].VirtualAddress;
		DWORD dwReadOff = 0x0;
		for(int i = 0; i < m_wNoOfSections; i++)
		{
			if(m_pSectionHeader[i].VirtualAddress > dwMaxRVA)
			{
				dwMaxRVA = m_pSectionHeader[i].VirtualAddress;
			}
		}
		if(m_dwAEPUnmapped == dwMaxRVA)
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_dwBuffStart = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader;
			DWORD dwBuffSize = m_dwWriteSize = m_wNoOfSections * IMAGE_SIZEOF_SECTION_HEADER;
			m_pbyBuff = new BYTE[dwBuffSize * 2];
			DWORD dwTemp[0x50] = {0x0};
			if(!m_pbyBuff)
			{
				return iRetStatus;
			}
			if(!GetBuffer(m_dwBuffStart,(dwBuffSize * 2),(dwBuffSize * 2)))
			{
				return iRetStatus;
			}
			DWORD i = 0x0;
			//copying all section PRD's into temp array
			for(i = 0; i < m_wNoOfSections; i++)
			{
				dwTemp[i] = *(DWORD *)&m_pbyBuff[i * 0x28 + 0x14];
			}
			//sorting temp array
			for (int x = 0; x < m_wNoOfSections; x++)
			{
				for(int y = 0; y < m_wNoOfSections; y++)
				{
					if(dwTemp[y] > dwTemp[y+1] && y!= m_wNoOfSections - 1)
					{
						DWORD temp = dwTemp[y+1];
						dwTemp[y+1] =dwTemp[y];
						dwTemp[y] = temp;
					}
				}
			}
			m_dwTruncateOff = dwReadOff = dwTemp[m_wNoOfSections - 1];
			//section header sorting
			DWORD dwCnt = 0;
			for(int i = 0; i < m_wNoOfSections; i++)
			{
				for(int j = 0; j < m_wNoOfSections;j++)
				{
					if(*(DWORD *)&m_pbyBuff[j * 0x28 + 0x14] == dwTemp[dwCnt])
					{
						int k = 0x0;
						while(k < 0x28)
						{	
							//last section header fill with 0x0
							if(dwReadOff == dwTemp[dwCnt])
							{
								m_pbyBuff[dwBuffSize++] = 0x0;
							}
							else
								m_pbyBuff[dwBuffSize++] = m_pbyBuff[j * 0x28 + k];
							k++;
						}
						*(DWORD *)&m_pbyBuff[j * 0x28 + 0x14] = 0x0;
						//Calculate ImageSize
						if(dwTemp[m_wNoOfSections - 2] == dwTemp[dwCnt])
						{
							DWORD dwSecAlignment = m_pMaxPEFile->m_stPEHeader.FileAlignment;
							DWORD dwLastSecVS = *(DWORD *)&m_pbyBuff[j * 0x28 + 0x08];	
							DWORD dwLastSecRVA= *(DWORD *)&m_pbyBuff[j * 0x28 + 0x0C];	
					
							if( dwLastSecVS % dwSecAlignment )
							{
								m_dwImageSize = dwLastSecVS - (dwLastSecVS % dwSecAlignment) + dwSecAlignment;
							}
							else
							{
								m_dwImageSize = dwLastSecVS;     
							}
							m_dwImageSize += dwLastSecRVA;
						}
						dwCnt++;
					}
					if(dwCnt >= m_wNoOfSections)
						break;
				}
				if(dwCnt >= m_wNoOfSections)
					break;
			}
		}
		
		//detection
		const int KURGAN_BUFF_SIZE = 0x50;
		if(!GetBuffer(dwReadOff,KURGAN_BUFF_SIZE,KURGAN_BUFF_SIZE))
		{
			return iRetStatus;
		}
		if(m_pbyBuff[0] == 0x53 && m_pbyBuff[1] == 0x8B && m_pbyBuff[2] == 0xD8 && m_pbyBuff[3] == 0x81)
		{
			CSemiPolyDBScn	polydbObj;
			TCHAR	szVirusName[MAX_PATH] = {0};
			TCHAR	szKurgan[] = {_T("5360EB0561585BFFE066C7401190908BF081C63900*0000B90028000081E939000000000E8036")};

			polydbObj.LoadSigDBEx(szKurgan, _T("Virus.W9X.Kurgan.10240"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0x5] - m_dwImageBase;
				return VIRUS_FILE_REPAIR;
			}
		}	
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Kurgan Family
--------------------------------------------------------------------------------------*/
int CPolyKurgan::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[m_dwWriteSize],m_dwBuffStart,m_dwWriteSize,m_dwWriteSize))
		{
			if(m_pMaxPEFile->ForceTruncate(m_dwTruncateOff))
			{
				DWORD dwSecNoOff = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + 0x2;
				DWORD dwImageSizeOff = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0x38;
				WORD wSec = m_wNoOfSections - 1;

				if(m_pMaxPEFile->WriteBuffer(&wSec,dwSecNoOff,sizeof(WORD),sizeof(WORD)))
				{
					if(m_pMaxPEFile->WriteBuffer(&m_dwImageSize,dwImageSizeOff,sizeof(DWORD),sizeof(DWORD)))
					{
						if(m_pMaxPEFile->CalculateChecksum())
						{
							return REPAIR_SUCCESS;
						}
					}
				}
			}
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyTabeci
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTabeci::CPolyTabeci(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTabeci
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTabeci::~CPolyTabeci(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Tabeci Family
--------------------------------------------------------------------------------------*/
int CPolyTabeci::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections - 1 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x2000 &&
		m_dwAEPUnmapped	== m_pSectionHeader[m_wAEPSec].VirtualAddress)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int TABECI7712_BUFF_SIZE = 0x60;
		m_pbyBuff = new BYTE[TABECI7712_BUFF_SIZE];
		if(!m_pMaxPEFile ->ReadBuffer(&m_pbyBuff[0x0],m_dwAEPMapped + 0x5E,0x5,0x5))
		{
			return iRetStatus;
		}
		DWORD dwDecOff = *(DWORD *)&m_pbyBuff[0x0] - m_dwImageBase;
		BYTE byKey = m_pbyBuff[0x4];
		if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDecOff,&dwDecOff) || dwDecOff == 0x0)
		{
			return iRetStatus;
		}
		if(!GetBuffer(dwDecOff,TABECI7712_BUFF_SIZE,TABECI7712_BUFF_SIZE))
		{
			return iRetStatus;
		}
		for(int i = 0; i < TABECI7712_BUFF_SIZE; i++)
		{
			m_pbyBuff[i] ^= byKey;
		}
		m_dwOriginalAEP = *(DWORD  *)&m_pbyBuff[0x58] - m_dwImageBase;
		CSemiPolyDBScn	polydbObj;
		TCHAR	szVirusName[MAX_PATH] = {0};
		TCHAR	szTabeci7712[] = {_T("03D88A63078A4304C1E010668B430283C008E8000000005D*81ED24304000BE6530400003F59366893366C74302280066C7430400ECC1EE10668973068D855F30400053")};

		polydbObj.LoadSigDBEx(szTabeci7712, _T("Virus.W9X.Tabeci.7712"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Tabeci Family
--------------------------------------------------------------------------------------*/
int CPolyTabeci::CleanVirus(void)
{
	int iRetStatus=VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->RemoveLastSections())
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyKuto
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyKuto::CPolyKuto(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x0 , m_dwImportOffset = 0x0 ;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyKuto
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyKuto::~CPolyKuto(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Kuto Family
--------------------------------------------------------------------------------------*/
int CPolyKuto::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((memcmp(m_pSectionHeader[0x0].Name,".kuto",5)==0) && 
		m_pSectionHeader[0x0].VirtualAddress == m_dwAEPUnmapped && 
		m_pSectionHeader[0x0].Characteristics == 0xE0000020)
	{
		const int KUTO_BUFF_SIZE = 0x145;
		m_pbyBuff= new BYTE[KUTO_BUFF_SIZE];
		if(!GetBuffer(m_pSectionHeader[0x0].PointerToRawData,KUTO_BUFF_SIZE,KUTO_BUFF_SIZE))
		{
			return iRetStatus;
		}
		if(m_pbyBuff[0] == 0x60 && m_pbyBuff[1] == 0xE8 && m_pbyBuff[2] == 0x00 && m_pbyBuff[6] == 0x5D)
		{
			CSemiPolyDBScn	polydbObj;
			TCHAR	szVirusName[MAX_PATH] = {0};
			TCHAR	szKuto[] = {_T("81ED062040008B858E24400003858A2440008944241C8B8576264000898519214000*FF956A26400089858A2440008DBD9F244000E805040000E86E000000E8AB0000*2640005350FF950F25400083F8FF7502EB44898576244000C7859A2440")};

			polydbObj.LoadSigDBEx(szKuto, _T("Virus.W32.Kuto.2058"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				m_pbyBuff= new BYTE[0x8];
				if(!GetBuffer(m_dwAEPMapped + 0x48E,0x8,0x8))
				{
					return iRetStatus;
				}
				m_dwOriginalAEP = *(DWORD *) &m_pbyBuff[0x0];
				m_dwImportOffset = *(DWORD *) &m_pbyBuff[0x4];
				return VIRUS_FILE_REPAIR;
			}
		}	
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Kuto Family
--------------------------------------------------------------------------------------*/
int CPolyKuto::CleanVirus(void)
{
	int iRetStatus=VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->ForceTruncate(m_pSectionHeader[0x0].PointerToRawData))
		{
			DWORD dwSecNoOff = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + 0x2;
			WORD wSec = m_wNoOfSections - 1;
			if(m_pMaxPEFile->WriteBuffer(&wSec,dwSecNoOff,sizeof(WORD),sizeof(WORD)))
			{
				DWORD dwTempOff = m_wNoOfSections * IMAGE_SIZEOF_SECTION_HEADER-(2*IMAGE_SIZEOF_SECTION_HEADER);
				DWORD dwBaseOff = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);

				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}

				m_pbyBuff = new BYTE[2*IMAGE_SIZEOF_SECTION_HEADER];
				if(!GetBuffer((dwBaseOff + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + dwTempOff),2*IMAGE_SIZEOF_SECTION_HEADER,2*IMAGE_SIZEOF_SECTION_HEADER))
				{
					return iRetStatus;
				}
				m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x28],dwBaseOff + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader,IMAGE_SIZEOF_SECTION_HEADER , IMAGE_SIZEOF_SECTION_HEADER);
				//Calculating ImageSize	
				DWORD dwImageSize = 0x0;
				DWORD dwFileAlignment = m_pMaxPEFile->m_stPEHeader.FileAlignment;
				DWORD dwVirtualSize = *(DWORD *)&m_pbyBuff[0x8];
				DWORD dwRVA = *(DWORD *)&m_pbyBuff[0xC];
				if (dwVirtualSize % dwFileAlignment)
				{
					dwImageSize = dwVirtualSize - (dwVirtualSize % dwFileAlignment) + m_pMaxPEFile->m_stPEHeader.SectionAlignment + dwRVA;
				}
				else
				{
					dwImageSize = dwVirtualSize + dwRVA;
				}

				//calculating ImportSize Offset
				if(!GetBuffer((m_pMaxPEFile->m_stPEHeader.e_lfanew+sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) + 0x6C),sizeof(DWORD),sizeof(DWORD)))
				{
					return iRetStatus;
				}
				DWORD dwImportSize = (*(DWORD *)&m_pbyBuff[0x0]) + 0x2;
				DWORD dwImageSizeOff =  dwBaseOff + 0x38;  
				DWORD dwImportSizeOff =  dwBaseOff + 0x6C;
				DWORD dwImportTableOff = dwBaseOff + 0x68;
				if(m_pMaxPEFile->WriteBuffer(&dwImageSize,dwImageSizeOff,sizeof(DWORD),sizeof(DWORD)))
				{
					m_pMaxPEFile->WriteBuffer(&dwImportSize,dwImportSizeOff,sizeof(DWORD),sizeof(DWORD));
					m_pMaxPEFile->WriteBuffer(&m_dwImportOffset,dwImportTableOff,sizeof(DWORD),sizeof(DWORD));
					m_pMaxPEFile->FillWithZeros((m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader + sizeof(DWORD) + dwTempOff + IMAGE_SIZEOF_SECTION_HEADER),IMAGE_SIZEOF_SECTION_HEADER);
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return REPAIR_FAILED;
}



/*-------------------------------------------------------------------------------------
	Function		: CPolyDropperDapatoAZUE
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyDropperDapatoAZUE::CPolyDropperDapatoAZUE(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwReplaceOff = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyDropperDapatoAZUE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyDropperDapatoAZUE::~CPolyDropperDapatoAZUE(void)
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
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Detection routine for different varients of Dapato Family
				      A. Process Operation: Creates & starts(run) process cmd.exe,taskkill.exe.
				      B. Folder/File Operations: 
						1. Drops copy of itself in 'C' drive with name java.exe,delme.bat
						2. Also maintains copy of itself with random-name (4-digit name wherein last digit has to be 9)
						in C:\Documents and Settings\All Users\Application Data.
						3. On opening/exploring drive launches(autoruns) "java.exe" 	
						4. Infects file's with extensions exe,dll,com,sys
					  C. Registry Operation: Disables Find,Run,StartMenuLogOff
					  D. Attempts to connect to : www.rem.cn
--------------------------------------------------------------------------------------*/
int CPolyDropperDapatoAZUE::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wNoOfSections == 0x4 && m_wAEPSec == 0x0 && m_dwAEPUnmapped == 0x178E0 && m_dwAEPMapped == m_dwAEPUnmapped &&
		m_pMaxPEFile->m_stPEHeader.CheckSum == 0x25EEE && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == m_pSectionHeader[m_wAEPSec].SizeOfRawData &&
		(memcmp(m_pSectionHeader[m_wAEPSec].Name,".midu0",6)==0))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int DROPPERDAPATOAZUE_BUFF_SIZE = 0x350;
		m_pbyBuff = new BYTE[DROPPERDAPATOAZUE_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x0],m_dwAEPUnmapped - 0x2430,0x300,0x300))
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x300],m_dwAEPUnmapped - 0x1320,0x10,0x10))
		{
			return iRetStatus;
		}
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x310],m_dwAEPUnmapped - 0x9E0,0x15,0x15))
		{
			return iRetStatus;
		}
		CSemiPolyDBScn	polydbObj;
		TCHAR	szVirusName[MAX_PATH] = {0};
		TCHAR	szDropperDapatoAZUE[] = {_T("687474703A2F2F7777772E72656D2E636E*4B696C6C20596F7521*455F6D61696C3A62736F6F6D403136332E636F6D*633A5C64656C6D652E626174*6F70656E3D6A6176612E657865")};
						// http://www.rem.cn*Kill You!*E_mail:bsoom@163.com*c:\delme.bat*open=java.exe
		polydbObj.LoadSigDBEx(szDropperDapatoAZUE, _T("Dropper.Dapato.AZUE"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], DROPPERDAPATOAZUE_BUFF_SIZE, szVirusName) >= 0)
		{
			DWORD dwOverlayOff = m_pSectionHeader[m_wNoOfSections -1].SizeOfRawData + m_pSectionHeader[m_wNoOfSections -1].PointerToRawData;
			DWORD dwIndex = 0x1C416;
			if(dwOverlayOff < m_pMaxPEFile->m_dwFileSize &&  dwOverlayOff != 0x0 && dwOverlayOff + dwIndex != m_pMaxPEFile->m_dwFileSize)
			{
				if(m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x0],dwOverlayOff + 0x1C416,0x2,0x2))
				{
					if(m_pbyBuff[0x0] == 0x4D && m_pbyBuff[0x01] == 0x5A)
					{
						m_dwReplaceOff = dwOverlayOff + 0x1C416;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
						return VIRUS_FILE_REPAIR;
					}
				}
			}
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Prajakta + Virus Analysis Team
	Description		: Repair routine for different varients of Dapato Family
--------------------------------------------------------------------------------------*/
int CPolyDropperDapatoAZUE::CleanVirus(void)
{
	int iRetStatus=VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->CopyData(m_dwReplaceOff, 0x0, m_pMaxPEFile->m_dwFileSize - m_dwReplaceOff))
	{
		if(m_pMaxPEFile->ForceTruncate((m_pMaxPEFile->m_dwFileSize - m_dwReplaceOff) - 0x4))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyJethro
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyJethro::CPolyJethro(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyJethro
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyJethro::~CPolyJethro(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Jethro Family
--------------------------------------------------------------------------------------*/
int CPolyJethro::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	WORD wReservedBytes = 0;
	m_pMaxPEFile->ReadBuffer(&wReservedBytes, 0x38, sizeof(WORD), sizeof(WORD));
	if(m_wAEPSec == m_wNoOfSections - 1 && wReservedBytes == 0x534C && m_pMaxPEFile->m_dwFileSize - m_dwAEPMapped == 0x1619)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int JETHRO5657_BUFF_SIZE = 0x50;
		m_pbyBuff = new BYTE[JETHRO5657_BUFF_SIZE];
		if(!m_pMaxPEFile ->ReadBuffer(&m_pbyBuff[0x0],m_dwAEPMapped,0x20,0x20))
		{
			return iRetStatus;
		}
		const BYTE bSig[] = {0x9C,0x60,0xE8,0x00,0x00,0x00,0x00,0x58,0x68,0x07,0x10,0x40,0x00,0x5B,0x2B,0xC3,0x50,
				     0x5D,0x8D,0xBD,0x29,0x10,0x40,0x00,0x68,0x7C,0x05,0x00,0x00,0x59,0x81,0x37};
		if(memcmp(&m_pbyBuff[0x0],bSig,sizeof(bSig)) == 0)
		{
			DWORD dwXorKey = 0x0;
			m_pMaxPEFile->ReadBuffer(&dwXorKey,m_dwAEPMapped + 0x20,sizeof(DWORD),sizeof(DWORD));
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x0],m_dwAEPMapped + 0x2D,sizeof(DWORD)*3,sizeof(DWORD)*3))
			{
				return iRetStatus;
			}
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0xC],m_dwAEPMapped + 0x305,0x20,0x20))
			{
				return iRetStatus;
			}
			for(int i = 0;i < 0x2C;i += 4 )
			{
				*(DWORD *)&m_pbyBuff[i] ^=  dwXorKey;
			}
			CSemiPolyDBScn	polydbObj;
			TCHAR	szVirusName[MAX_PATH] = {0};
			TCHAR	szJETHRO5657[] = {_T("5B4A455448524F5D*5B44657369676E6564206279204C6974655379732F58414B45525D")};
						  // [JETHRO]*[Designed by LiteSys/XAKER]
			polydbObj.LoadSigDBEx(szJETHRO5657, _T("Virus.Jethro.5657"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], JETHRO5657_BUFF_SIZE, szVirusName) >= 0)
			{
				m_pMaxPEFile->ReadBuffer(&m_dwOriginalAEP,m_dwAEPMapped + 0x121,sizeof(DWORD),sizeof(DWORD));
				m_dwOriginalAEP ^= dwXorKey;
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Jethro Family
--------------------------------------------------------------------------------------*/
int CPolyJethro::CleanVirus(void)
{
	int iRetStatus=VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP - m_dwImageBase))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
		{
			if(m_pMaxPEFile->FillWithZeros(0x38, 2))	
			{
				return REPAIR_SUCCESS;
				
			}
		}
	}
	return REPAIR_FAILED;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolySpinex
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolySpinex::CPolySpinex(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolySpinex
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolySpinex::~CPolySpinex(void)
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
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Spinex Family
					 -  Its drops own copy
					-  Got samples in which virus code is prepended 
					-  original file at offset 0xC8D8  
--------------------------------------------------------------------------------------*/
int CPolySpinex::DetectVirus(void)
{
	int iRetstatus = VIRUS_NOT_FOUND; 
	if(m_wAEPSec != 0 || m_dwAEPUnmapped != 0x10D8 || m_pSectionHeader[1].SizeOfRawData != 0)
	{
		return iRetstatus; 
	}

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	const int SPINEX_BUFF_SIZE = 0x170;
	m_pbyBuff = new BYTE[SPINEX_BUFF_SIZE];
	if(!m_pbyBuff)
	{
		return iRetstatus;
	}

	if(!GetBuffer(m_dwAEPMapped + 0xCF8, SPINEX_BUFF_SIZE, SPINEX_BUFF_SIZE))
	{
		return iRetstatus;
	}
	const TCHAR szSpinexSign[] = {_T("53007000680069006E0058*63003A005C00740065006D0070002E006500780065*42007200690074006E00650079")};
										//(S.p.h.i.n.X*c.:.\.t.e.m.p...e.x.e*B.r.i.t.n.e.y)
	CSemiPolyDBScn polydbObj;

	polydbObj.LoadSigDBEx(szSpinexSign, _T("Virus.W32.HLLW.Spinex"), FALSE);

	TCHAR szVirusName[MAX_PATH] = {0};
	if(polydbObj.ScanBuffer(&m_pbyBuff[0], SPINEX_BUFF_SIZE, szVirusName) >=0)
	{
		WORD wCheck4MZ = 0x0;
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
		if(m_pMaxPEFile->ReadBuffer(&wCheck4MZ, 0xC8D8, 0x2, 0x2))
		{
			if(wCheck4MZ == 0x5A4D)
			{	
				return VIRUS_FILE_REPAIR;
			}
		}
		return VIRUS_FILE_DELETE;
	}

	return iRetstatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Repair routine for different varients of Spinex Family
--------------------------------------------------------------------------------------*/
int CPolySpinex::CleanVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwOrignalFilesize = m_pMaxPEFile->m_dwFileSize - 0xC8D8;
	m_pMaxPEFile->CopyData(0xC8D8,0,dwOrignalFilesize);
	if(m_pMaxPEFile->ForceTruncate(dwOrignalFilesize))
	{
		return REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMemorial
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMemorial::CPolyMemorial(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMemorial
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMemorial::~CPolyMemorial(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Memorial Family
--------------------------------------------------------------------------------------*/
int CPolyMemorial::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_wAEPSec == m_wNoOfSections -1 && m_dwAEPUnmapped == m_pSectionHeader[m_wAEPSec].VirtualAddress &&
		m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x3000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int MEMORIAL_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[MEMORIAL_BUFF_SIZE];
		
		BYTE bXORKey = 0x0;
		m_pMaxPEFile->ReadBuffer(&bXORKey,m_dwAEPMapped + 0x2D,sizeof(BYTE),sizeof(BYTE));
		if(bXORKey == 0x0)
		{
			return iRetStatus;
		}
		bXORKey = LOBYTE(0x2BE + bXORKey);
		if(!m_pMaxPEFile ->ReadBuffer(&m_pbyBuff[0x0],m_dwAEPMapped + 0x2EC,MEMORIAL_BUFF_SIZE,MEMORIAL_BUFF_SIZE))
		{
			return iRetStatus;
		}
		for(int i = 0; i < MEMORIAL_BUFF_SIZE; i++)
		{
			m_pbyBuff[i] ^=  bXORKey;
			bXORKey += 0x1; 
		}
		CSemiPolyDBScn	polydbObj;
		TCHAR	szVirusName[MAX_PATH] = {0};
		TCHAR	szMEMORIAL[] = {_T("433A5C434C494E542E565844*436C696E746F6E204861696E6573204D656D6F7269616C205669727573206279205175616E74756D2F564C414420616E64205161726B2F564C4144")};
					 // C:\CLINT.VXD*Clinton Haines Memorial Virus by Quantum/VLAD and Qark/VLAD
		polydbObj.LoadSigDBEx(szMEMORIAL, _T("Virus.W9X.Memorial"), FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0xA2], MEMORIAL_BUFF_SIZE, szVirusName) >= 0)
		{
			m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0x0];
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_REPAIR;
		}

	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Memorial Family
--------------------------------------------------------------------------------------*/
int CPolyMemorial::CleanVirus(void)
{
	int iRetStatus=VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->RemoveLastSections(0x1,true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyOporto
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyOporto::CPolyOporto(CMaxPEFile *pMaxPEFile)
: CPolyBase(pMaxPEFile)
{
	m_dwVirusStartOffset = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyOporto
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyOporto::~CPolyOporto(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Oporto Family
--------------------------------------------------------------------------------------*/
int CPolyOporto::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0x80000000) == 0x80000000)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int OPORTO_BUFF_SIZE = 0x110;
		m_pbyBuff = new BYTE[OPORTO_BUFF_SIZE];				
		if(GetBuffer(m_dwAEPMapped, 0x6, 0x6))
		{
			if(m_pbyBuff[0] == 0x68 && m_pbyBuff[5] == 0xC3)
			{
				m_dwVirusStartOffset = *((DWORD *)&m_pbyBuff[1]) - m_dwImageBase;
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwVirusStartOffset, &m_dwVirusStartOffset))
				{
					if(GetBuffer(m_dwVirusStartOffset, OPORTO_BUFF_SIZE, OPORTO_BUFF_SIZE))
					{
						if(m_pbyBuff[0] == 0xB8 && m_pbyBuff[0x5] == 0xB9 && *((WORD *)&m_pbyBuff[0xA]) == 0x3181)
						{
							DWORD dwXORKey = *(DWORD *)&m_pbyBuff[0xC];
							for(DWORD i = 0x76; i < 0x106; i+= 0x4)
							{
								*(DWORD *)&m_pbyBuff[i] ^= dwXORKey;
							}
							TCHAR szVirusName[MAX_PATH] = {0};
							TCHAR szOporto3076_Sig[] = _T("544F54494C4958*4F706F72746F20506F72747567616C21*6761735F70617240686F746D61696C2E636F6D");
							                            //TOTILIX*Oporto Portugal!*gas_par@hotmail.com

							CSemiPolyDBScn polydbObj;
							polydbObj.LoadSigDBEx(szOporto3076_Sig, _T("Virus.Oporto.3076"), FALSE);
							if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
							{
								if(_tcslen(szVirusName) > 0)
								{
									_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Opotro.3076"));	
									return VIRUS_FILE_REPAIR;
								}
							}
						}
					}
				}
			}
		}
	}
	return VIRUS_NOT_FOUND;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Oporto Family
--------------------------------------------------------------------------------------*/
int CPolyOporto::CleanVirus()
{
	if(m_pMaxPEFile->WriteBuffer(&m_pbyBuff[0x79], m_dwAEPMapped, 6, 6))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwVirusStartOffset,true))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyEak
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyEak::CPolyEak(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x0;
	m_dwVirusOff = 0x0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyEak
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyEak::~CPolyEak(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Eak Family
--------------------------------------------------------------------------------------*/
int CPolyEak::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if(m_dwAEPUnmapped == m_dwAEPMapped && m_dwAEPUnmapped < m_pSectionHeader[0x0].PointerToRawData &&
		(m_dwAEPUnmapped % 0x2) == 0x0)
	{
		BYTE bCavityData[0x8] = {0};
		if(m_pMaxPEFile->ReadBuffer(&bCavityData[0x0],m_dwAEPUnmapped - 0xC,0x8,0x8))
		{
			DWORD dwCavitySize = *(DWORD*)&bCavityData[0x4];
			m_dwVirusOff = *(DWORD*)&bCavityData[0x0];
			if(dwCavitySize == 0x109 && m_dwVirusOff != 0x0)
			{
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				m_pbyBuff = new BYTE[dwCavitySize];
				if(!m_pbyBuff)
				{
					return iRetStatus;
				}
				if(!GetBuffer(m_dwAEPUnmapped, dwCavitySize, dwCavitySize)) 
				{
					return iRetStatus;
				}
				if(m_pbyBuff[0x0] != 0x60 || m_pbyBuff[0x1] != 0x53)
				{
					return iRetStatus;
				}
				CSemiPolyDBScn	polydbObj;
				TCHAR	szVirusName[MAX_PATH] = {0};
				TCHAR	szEak[] = {_T("E8000000005E8D76E68D86AA0000005033C964FF318BC46487018D86B3000000*744B8BF8578B56F88B4EFCF3A40BD27411BE*8B3C248BF78B3EB980040000F3A45F8B378DB6CD000000*608D87050500008D9FB901000089584C89442404890424CD203D00280000")};
							
				polydbObj.LoadSigDBEx(szEak, _T("Virus.W9x.Eak"), FALSE);
				if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
				{
					if(_tcslen(szVirusName) > 0)
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
						m_dwOriginalAEP = *(DWORD*)&m_pbyBuff[0xA1] - m_dwImageBase;
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Eak Family
--------------------------------------------------------------------------------------*/
int CPolyEak::CleanVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPUnmapped - 0xC,0x111))
		{
			for(int i = 0x0; i < m_wNoOfSections; i++)
			{
				if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwVirusOff,&m_dwVirusOff))
				{
					if(GetBuffer(m_dwVirusOff,0x8,0x8))
					{
						DWORD dwVirusOffset = *(DWORD*)&m_pbyBuff[0x0];
						DWORD dwVirusSize = *(DWORD*)&m_pbyBuff[0x4];
						m_pMaxPEFile->FillWithZeros(m_dwVirusOff,dwVirusSize + 0x8);
						if(dwVirusOffset == 0x0)
							break;
						else
							m_dwVirusOff = dwVirusOffset;
					}
				}
			}
		}
		return REPAIR_SUCCESS;
	}
	return iRetStatus;
}

/********************************************************************************************************
Analyst     : Alisha
Type:       : Virus (Infector)
Name        : Virus.W9x.Nathan (Covered Varient Nathan.3476 && Nathan.3412)
Sig Region  : Start of file and AEP 
Intension   : Virus name & few bytes from start of virus code.
Description :- Type: Appender
		     - Adds new section with name ".Nathan"
		     - Original AEP in encrypted format
			 - Infects system .exe files
********************************************************************************************************/
/*-------------------------------------------------------------------------------------
	Function		: CPolyNathan
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyNathan::CPolyNathan(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0x00;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyNathan
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyNathan::~CPolyNathan(void)
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
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Nathan Family
					  - Type: Appender
					  - Adds new section with name ".Nathan"
					  - Original AEP in encrypted format
					  - Infects system .exe files
--------------------------------------------------------------------------------------*/
int CPolyNathan::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if	((memcmp(m_pSectionHeader[m_wAEPSec].Name,".NathaN",7) == 0) && m_dwAEPUnmapped == m_pSectionHeader[m_wAEPSec].VirtualAddress
	     && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x2000 && m_wAEPSec == m_wNoOfSections -1)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int	Nathan_Buff_Size = 0x100;
		m_pbyBuff = new BYTE[Nathan_Buff_Size];
		
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(GetBuffer(m_dwAEPMapped, Nathan_Buff_Size, Nathan_Buff_Size))  
		{
			DWORD	dwOffset = 0x0, dwLength = 0x0, dwDecrypKey = 0x0, dwDecrypStart = 0x0;
			int		iMatchInstr = 0;
			char	opr = ' ';

			while(dwOffset < dwOffset + Nathan_Buff_Size)					
			{	
				t_disasm	da;
				
				memset(&da, 0x00, sizeof(struct t_disasm));
				dwLength = m_objMaxDisassem.Disasm((char*)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE);	

				if(iMatchInstr == 0x0 && dwLength == 0x6 && strstr(da.result, "LEA EBP,"))
				{
					dwDecrypStart = m_dwAEPUnmapped + *(DWORD *)&m_pbyBuff[dwOffset + 2] + m_dwImageBase;
					iMatchInstr++;
				}
				if(iMatchInstr == 0x1 && dwLength == 0x6 && strstr(da.result, "LEA EDX,"))
				{
					dwDecrypStart = dwDecrypStart + *(DWORD *)&m_pbyBuff[dwOffset + 2] - m_dwImageBase - m_dwAEPUnmapped;
					iMatchInstr++;
				}
				if(iMatchInstr == 0x2 && dwLength == 0x2 && strstr(da.result, "JMP SHORT"))
				{
					dwOffset = dwOffset + m_pbyBuff[dwOffset + 1];
					iMatchInstr++;
				}
				if(iMatchInstr == 0x3 && dwLength == 0x6 && (strstr(da.result, "SUB") || strstr(da.result, "XOR")))
				{
					dwDecrypKey = da.immconst;
					if(strstr(da.result, "SUB"))
					{
						for(int i=dwDecrypStart;  i< Nathan_Buff_Size; i=i+0x4)
						{
							*(DWORD *)&m_pbyBuff[i] -= dwDecrypKey;
						}
					}
					else
					{
						for(int i=dwDecrypStart;  i< Nathan_Buff_Size; i=i+0x4)
						{
							*(DWORD *)&m_pbyBuff[i] ^= dwDecrypKey;
						}
					}

					break;
				}
				dwOffset = dwOffset + dwLength;

				if(dwOffset > 20 && iMatchInstr <= 0x1)
				{
					return iRetStatus;
				}
			}

			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};
			TCHAR			szNathanSign[] = {_T("4E617468614E20696E20*5472616E5A652D47727570")};  // Sign for Varient Nathan.3476 && Nathan.3412
							//(NathaN in *TranZe-Grup)

			polydbObj.LoadSigDBEx(szNathanSign, _T("Virus.Win9x.Nathan.3412"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[dwDecrypStart], Nathan_Buff_Size - dwDecrypStart, szVirusName) >= 0)
			{
				DWORD	dwIndex = 0x0;
				BYTE	szNathanSign1[] = {0x8D,0xA8,0x00,0xF0,0xBF,0xFF,0x2D}; 
				
				if(OffSetBasedSignature(szNathanSign1,sizeof(szNathanSign1),&dwIndex))
				{
					m_dwOriginalAEP = m_dwAEPUnmapped - *(DWORD *)&m_pbyBuff[dwIndex + sizeof(szNathanSign1)];
				}
				if(m_dwOriginalAEP > m_pMaxPEFile->m_dwFileSize)
				{
					return iRetStatus;
				}

				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				return VIRUS_FILE_REPAIR;
			}

		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Repair routine for different varients of Dundun Family
--------------------------------------------------------------------------------------*/
int CPolyNathan::CleanVirus(void)
{
	int iRetStatus = REPAIR_FAILED;
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->RemoveLastSections())
		{
			return REPAIR_SUCCESS;
		}
	}
	 
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMamianuneIf
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMamianuneIf::CPolyMamianuneIf(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
        m_dwtruncateOffset = 0;
        m_dwOverlaySize = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMamianuneIf
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMamianuneIf::~CPolyMamianuneIf(void)
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
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Virus.Mamianune.If Family
--------------------------------------------------------------------------------------*/
int CPolyMamianuneIf::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
 
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pbyBuff = new BYTE[0x48];
	int const MAMIANUNEIF_BUFF_SIZE = 0x48;
	

     m_dwOverlaySize = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);
	if(!GetBuffer(m_pMaxPEFile->m_dwFileSize - m_dwOverlaySize - 0x48, MAMIANUNEIF_BUFF_SIZE, MAMIANUNEIF_BUFF_SIZE))
	{
		return iRetStatus;
	}
	
	if((m_wAEPSec == 0 || m_wAEPSec == 1) && ((*(DWORD *)&m_pbyBuff[0x3B] - m_dwImageBase == m_dwAEPUnmapped) || (*(DWORD *)&m_pbyBuff[0x44] == m_pSectionHeader[m_wAEPSec].PointerToRawData)))
	{
		BYTE bdecrypkey = 0;
		bdecrypkey = m_pbyBuff[0x3A];
		
		for(int i = 0; i <= 0x3A; i++)
		{
			m_pbyBuff[i] ^= bdecrypkey;
		}
		CSemiPolyDBScn polydbObj;

		TCHAR szVirusName[MAX_PATH] = {0};
		TCHAR szMAMIANUNEIF_SIG[] = {_T("E805000000E9CDF4FFFF8B04248D989DE7FFFF*8DB89DE8FFFF8BF7BA5E17000033C98BC1FEC9AC3A04197403*49EBF886C1AA85D274034A75E7C300")};
		polydbObj.LoadSigDBEx(szMAMIANUNEIF_SIG,_T("Virus.Mamianune.If"),false);

		if(polydbObj.ScanBuffer(m_pbyBuff, MAMIANUNEIF_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
				if(*(DWORD *)&m_pbyBuff[0x44] == m_pSectionHeader[m_wAEPSec].PointerToRawData)  // For Stub
				{
					return VIRUS_FILE_DELETE;
				}
				m_dwtruncateOffset = *(DWORD *)&m_pbyBuff[0x44];
				if(m_dwtruncateOffset > m_pMaxPEFile->m_dwFileSize || m_dwtruncateOffset == 0x0)
				{
					return iRetStatus;
				}
				return VIRUS_FILE_REPAIR;		
				
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Repair routine for different varients of Mamianune.If Family
--------------------------------------------------------------------------------------*/
int CPolyMamianuneIf::CleanVirus(void)
{
	if(m_pMaxPEFile->CopyData(m_pMaxPEFile->m_dwFileSize - m_dwOverlaySize -0x9, m_dwAEPMapped, 0x5, 0x5))
	{
		if(m_pMaxPEFile->TruncateFile(m_dwtruncateOffset,false))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyGameThiefLmirWJ
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGameThiefLmirWJ::CPolyGameThiefLmirWJ(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile),m_dwReplaceOffset(0)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGameThiefLmirWJ
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGameThiefLmirWJ::~CPolyGameThiefLmirWJ(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of GameThief.Lmir.WJ Family
--------------------------------------------------------------------------------------*/
int CPolyGameThiefLmirWJ::DetectVirus()
{
	int	iRetStatus = VIRUS_NOT_FOUND;
	bool bIsDll = false;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
		bIsDll = true;

	if((bIsDll == false && (m_wNoOfSections == 0x8 || m_wNoOfSections == 0xA) && (m_dwAEPUnmapped == 0x3B10 && m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x2CD0) 
		|| ((m_dwAEPUnmapped & 0xF000) == 0x4000 && m_pSectionHeader[m_wAEPSec].SizeOfRawData >= 0x4200 && m_pSectionHeader[m_wAEPSec].SizeOfRawData <= 0x5000)) ||

		(bIsDll == true && (m_wNoOfSections == 0x7 || m_wNoOfSections == 0x9) && ((m_dwAEPUnmapped & 0xFF00) == 0x7D00) ||
	 	((m_dwAEPUnmapped & 0xF000) == m_pSectionHeader[m_wAEPSec].SizeOfRawData)))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}
		const int LMIRWJ_BUFF_SIZE = 0x420;
		m_pbyBuff = new BYTE[LMIRWJ_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		DWORD dwReadOff = 0x0,dwBuffSize = 0x0;
		if(bIsDll == true)
		{
			const BYTE bDLLSig[] = {0x6D,0x69,0x6E,0x69,0x4D,0x69,0x72,0x2E,0x64,0x6C,0x6C}; //miniMir.dll
			DWORD dwExportTableOff = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x0].VirtualAddress;
			if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwExportTableOff, &dwExportTableOff))
			{
				return iRetStatus;
			}
			DWORD dwDllNameOff=0x0;
			if(!m_pMaxPEFile->ReadBuffer(&dwDllNameOff, dwExportTableOff + 0xC, 0x04, 0x04))
			{
				return iRetStatus;
			}
			if((OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwDllNameOff, &dwDllNameOff)) || dwDllNameOff == 0x0)
			{
				return iRetStatus;
			}
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwDllNameOff, sizeof(bDLLSig), sizeof(bDLLSig)))
			{
				return iRetStatus;
			}
			if(memcmp(&m_pbyBuff[0x0],bDLLSig,sizeof(bDLLSig)) == 0x0)
			{
				dwBuffSize = 0x420;
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x0],m_dwAEPMapped - 0x320,dwBuffSize,dwBuffSize))
				{
					return iRetStatus;
				}
			}
		}
		else 
		{
			if(m_dwAEPUnmapped == 0x3B10)
			{
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize],m_dwAEPMapped + 0x175,0x50,0x50))
				{
					return iRetStatus;
				}
				dwBuffSize+= 0x50;
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwBuffSize],m_dwAEPMapped - 0xB70,0x10,0x10))
				{
					return iRetStatus;
				}
				dwBuffSize+= 0x10;
			}
			else
			{
				dwBuffSize = 0x250;
				if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[0x0],m_dwAEPMapped + 0x200,dwBuffSize,dwBuffSize))
				{
					return iRetStatus;
				}
			}
		}
		CSemiPolyDBScn	polydbObj;
		TCHAR szVirusName[MAX_PATH] = {0};
		LPCTSTR	szGameThiefLmirwjDLL = (_T("6567656E64206F66*7363616E726567772E657865"));
		LPCTSTR	szGameThiefLmirwjEXE = (_T("6B65726E656C2E646C6C*737663686F73742E657865*584645415258"));
		LPCTSTR	szGameThiefLmirwjEXE1 = (_T("7363616E726567772E657865*6D73736F636B2E444C4C"));
		LPCTSTR	szGameThiefLmirwjEXE2 = (_T("7363616E726567772E657865*4E65742E444C4C"));
		                         
		polydbObj.LoadSigDBEx(szGameThiefLmirwjDLL, _T("Trojan.GameThief.Lmir.wj"),TRUE);
		polydbObj.LoadSigDBEx(szGameThiefLmirwjEXE, _T("Trojan.GameThief.Lmir.wj"),TRUE);
		polydbObj.LoadSigDBEx(szGameThiefLmirwjEXE1, _T("Trojan.GameThief.Lmir.wj"),TRUE);
		polydbObj.LoadSigDBEx(szGameThiefLmirwjEXE2, _T("Trojan.GameThief.Lmir.wj"),FALSE);
		if(polydbObj.ScanBuffer(&m_pbyBuff[0x0], dwBuffSize, szVirusName) >= 0)
		{
			DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
			if(dwOverlayStart < m_pMaxPEFile->m_dwFileSize && dwOverlayStart != m_pMaxPEFile->m_dwFileSize)
			{
				DWORD dwBytes2Read = 0x200,dwIndex = 0x0;
				if(m_pMaxPEFile->m_dwFileSize - dwOverlayStart < 0x200)
					dwBytes2Read = m_pMaxPEFile->m_dwFileSize - dwOverlayStart;
				if(!GetBuffer(dwOverlayStart, dwBytes2Read, dwBytes2Read))
				{
					return iRetStatus;
				}
				
				BYTE bSig[] = {0x78, 0x66, 0x65, 0x61, 0x72, 0x78}; //xfearx
				if(OffSetBasedSignature(bSig,sizeof(bSig),&dwIndex))
				{
					if(m_pbyBuff[dwIndex + sizeof(bSig)] == 0x4D && m_pbyBuff[dwIndex + sizeof(bSig) + 0x1] == 0x5A)
					{
						m_dwReplaceOffset = dwOverlayStart + dwIndex + sizeof(bSig);
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
						return VIRUS_FILE_REPAIR;
					}
				}
			}
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of GameThief.Lmir.WJ Family
--------------------------------------------------------------------------------------*/
int CPolyGameThiefLmirWJ::CleanVirus(void)
{
	DWORD dwOriFileSize = m_pMaxPEFile->m_dwFileSize - m_dwReplaceOffset;
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0x0, dwOriFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(dwOriFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyViking
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyViking::CPolyViking(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
        m_dwOverlayStartoff = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyViking
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyViking::~CPolyViking(void)
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
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Dundun Family
					  Worm.Viking.Gen( Viking.GE,Viking.ii,Viking.iz,Viking.ix,Viking.cf,Viking.ha,Viking.fb,Viking.cy,Viking.cp,Viking.cm,Viking.mw,Viking.cd,Viking.cc)
					  1) Drops executable dll
					  2) Every Varient has different decryption technique. So written huristic checks for headers of .exe files & for dropped dll.
		              3) infects *.dll files in system.
					  Detection: 100% 	
--------------------------------------------------------------------------------------*/
int CPolyViking::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND, iIsDll = 0;
	/*if (m_wNoOfSections < 3)
	{
		return iRetStatus;
	}*/
	if(m_wAEPSec == 0x1 && (m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData == 0 && m_pMaxPEFile->m_stSectionHeader[1].SizeOfRawData != 0 && m_pMaxPEFile->m_stSectionHeader[2].SizeOfRawData != 0) && 
		(m_pMaxPEFile->m_stSectionHeader[0].Characteristics & 0x20000000) == 0x20000000 && (m_pMaxPEFile->m_stSectionHeader[1].Characteristics & 0x20000000) == 0x20000000 && (m_pMaxPEFile->m_stSectionHeader[2].Characteristics & 0x20000000) == 0x20000000)
	{
		if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
		{
			if(m_wNoOfSections == 3)
				iIsDll = 1;
			else
				return iRetStatus;
		}
		for(int i = sizeof(m_pMaxPEFile->m_stSectionHeader[0].Name); i > 0; i--)
		{
			if(m_pMaxPEFile->m_stSectionHeader[1].Name[i] !=0)
			{
				if( (m_pMaxPEFile->m_stSectionHeader[0].Name[i] == 0x30) && (m_pMaxPEFile->m_stSectionHeader[1].Name[i] == 0x31) &&
					(m_pMaxPEFile->m_stSectionHeader[2].Name[i] == 0x32))
				{
					if(iIsDll == 1)	// check for dll
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Worm.VikingDll.Gen"));
						return VIRUS_FILE_DELETE;
					}

					IMAGE_DOS_HEADER stDosHeader;
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}
					m_pbyBuff = new BYTE[sizeof(IMAGE_DOS_HEADER)];
					if(!GetBuffer(0,sizeof(IMAGE_DOS_HEADER),sizeof(IMAGE_DOS_HEADER)))
						return iRetStatus;

					if(!memcpy(&stDosHeader, &m_pbyBuff[0x0], sizeof(IMAGE_DOS_HEADER)))
						return iRetStatus;

					if(stDosHeader.e_res2[0x4] != 0 && stDosHeader.e_res2[0x6] == 0x6B63 && stDosHeader.e_res2[0x7] == 0x6963)
					{
						m_dwOverlayStartoff = m_pMaxPEFile->m_stSectionHeader[0x2].PointerToRawData +  m_pMaxPEFile->m_stSectionHeader[0x2].SizeOfRawData;
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Worm.Viking.Gen"));
						if(m_dwOverlayStartoff == m_pMaxPEFile->m_dwFileSize)
							return VIRUS_FILE_DELETE;

						//delete []m_pbyBuff;
						//m_pbyBuff = NULL;	
						if(m_pbyBuff)
						{
							delete []m_pbyBuff;
							m_pbyBuff = NULL;
						}
						m_pbyBuff = new BYTE[2];
						if(GetBuffer(m_dwOverlayStartoff, 2, 2))
						{
							if(*(WORD *)&m_pbyBuff[0] == 0x5A4D)
								return VIRUS_FILE_REPAIR;
							else 
								return VIRUS_FILE_DELETE;
						}
						else
							return VIRUS_FILE_DELETE;

					}
				}
				else
					break;
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Viking Family
--------------------------------------------------------------------------------------*/
int CPolyViking:: CleanVirus()
{
	DWORD dwOverlaySize = m_pMaxPEFile->m_dwFileSize - m_dwOverlayStartoff;
	if(m_pMaxPEFile->CopyData(m_dwOverlayStartoff, 0, dwOverlaySize, dwOverlaySize))
	{
		if(m_pMaxPEFile->TruncateFile(dwOverlaySize,false))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolyLamerEL
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyLamerEL::CPolyLamerEL(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwStartOffset = 0;
	m_dwFirstSecOffset = 0;
	m_iMZCheck = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyLamerEL
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyLamerEL::~CPolyLamerEL(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	if(m_byDecrypBuff)
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
	Author			: Tushar Kadam + Alisha + Sneha + Virus Analysis Team
	Description		: Detection routine for different varients of Lamer.EL Family
					  1) Prepends data
					  2) Encrypts original files header 
--------------------------------------------------------------------------------------*/
int CPolyLamerEL::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	bool bRetStatus = false;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return bRetStatus;
	}
	
	if((m_wAEPSec == 0 && m_wNoOfSections == 0x4  && m_dwAEPMapped == 0x1FD4&& 
		m_pSectionHeader[0].SizeOfRawData == 0x2D000 && memcmp(m_pSectionHeader[0].Name, "UPX0", 4) == 0)||
		(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0 && m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x2BD4 && 
		m_pSectionHeader[0].SizeOfRawData == 0x24000 &&  memcmp(m_pSectionHeader[0].Name, ".text", 5) == 0)) //added

	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}


		DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;

		if (m_pMaxPEFile->m_dwFileSize <= dwOverlayStart || dwOverlayStart == 0x00)
		{
			return iRetStatus;
		}

		const int OVR_BUFF_SIZE = 0x5000;
		m_pbyBuff = new BYTE [OVR_BUFF_SIZE];

		const BYTE bySign[] = {0x56, 0x62, 0x45, 0x78, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x42, 0x69, 0x6E, 0x64}; 

		DWORD i=m_pMaxPEFile->m_dwFileSize - 0x5000;



		for(i; i>= dwOverlayStart; i-=0x5000)
		{


			if(GetBuffer(i, OVR_BUFF_SIZE, OVR_BUFF_SIZE))
			{

				DWORD var1 = OVR_BUFF_SIZE/*-  sizeof(bySign) - 2*/;
				for(int j = var1; j >= 0x0000; j--)
				{
					if(memcmp(&m_pbyBuff[j], bySign, sizeof(bySign)) == 0x00)
					{
						if(CheckSigInBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + 0xA0A0,0x200,_T("460069006E0069006C006500000000000600000044006F0063*4B006100760055007000640061002E006500780065*480065006C0070005C00480065006C0070004300610074002E006500780065")))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Lamer.EL"));



							m_dwOrigFileOff =  j + i + 0xD;

							m_dwOrigFileSize = (m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff)- 0xD;


							BYTE byXorKey= 0x63;

							if(m_pbyBuff)
							{
								delete []m_pbyBuff;
								m_pbyBuff = NULL;
							}
							const int OVR_BUFF_SIZE = 0x450;
							m_pbyBuff = new BYTE [OVR_BUFF_SIZE];

							if(GetBuffer(m_dwOrigFileOff, OVR_BUFF_SIZE, OVR_BUFF_SIZE))
							{
								if(*(WORD *)&m_pbyBuff[0]!= 0x5a4d)
								{
									for(int m_iMZCheck = 0; m_iMZCheck < 0x10;  m_iMZCheck++)
									{
										if(*(WORD *)&m_pbyBuff[m_iMZCheck] == 0x392E)
											break;
									}

									for(int j = m_iMZCheck; j <= (0x63 + m_iMZCheck);  j++)
									{
										m_pbyBuff[j] ^= byXorKey;
									}

									byXorKey = 0x44;
									m_dwFirstSecOffset = *(DWORD *)&m_pbyBuff[0x3C] + 0x18 + 0xE0  + 0x14;
									m_dwFirstSecOffset =  *(DWORD *)&m_pbyBuff[m_dwFirstSecOffset];

									for(int j = m_dwFirstSecOffset - 0x19; j < m_dwFirstSecOffset + 0x4C;  j++)
									{
										m_pbyBuff[j] ^= byXorKey;

									}
									return VIRUS_FILE_REPAIR;

								}
							}
						}
					}
				}
			}
		}
	}


	DWORD BUFF_SIZE = 0x200;
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff =NULL;
	}
	m_pbyBuff = new BYTE[BUFF_SIZE];
	if(!m_pbyBuff)
	{
		return VIRUS_NOT_FOUND;
	}
	memset(m_pbyBuff,0,BUFF_SIZE);
	DWORD dwOffset = 0xA0A0;
	if(GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + dwOffset, BUFF_SIZE, BUFF_SIZE))
	{
		CSemiPolyDBScn		polydbObj;
		TCHAR				szVirusName[MAX_PATH] = {0};
		DWORD				dwOverlayStart = 0;

		LPCTSTR LamerEL = {_T("460069006E0069006C006500000000000600000044006F0063*4B006100760055007000640061002E006500780065*480065006C0070005C00480065006C0070004300610074002E006500780065")};

		polydbObj.LoadSigDBEx(LamerEL,_T("Virus.Lamer.EL"),FALSE);
		if(polydbObj.ScanBuffer(m_pbyBuff,BUFF_SIZE,szVirusName) >= 0)
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
			BYTE byXorKey= 0x63;
			DWORD dwCurPos=m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData,dwLastOffsetAdd=0;
			if(dwCurPos == m_pMaxPEFile->m_dwFileSize)
				return VIRUS_FILE_DELETE;
			while( dwCurPos < m_pMaxPEFile->m_dwFileSize)
			{
				m_dwStartOffset = dwCurPos;
				dwCurPos = DecryptionLamerEL(dwCurPos,byXorKey);
				if(dwCurPos == 0x0 )
				{
					break;
				}
				if(m_pMaxPEFile->m_dwFileSize - dwCurPos <0x400)
				{
					dwCurPos+=m_pMaxPEFile->m_dwFileSize - dwCurPos;
				}
			}
			if(m_dwStartOffset)
			{
				m_dwStartOffset += 0xD;
				if(m_byDecrypBuff)
				{
					delete []m_byDecrypBuff;
					m_byDecrypBuff =NULL;
				}
				m_byDecrypBuff = new BYTE[m_dwFirstSecOffset + 0x4C];
				if(m_pMaxPEFile->ReadBuffer(m_byDecrypBuff,m_dwStartOffset,m_dwFirstSecOffset + 0x4C,m_dwFirstSecOffset + 0x4C))
				{	
					if(*(WORD *)&m_byDecrypBuff[0]!= 0x5a4d)
					{
						for(int m_iMZCheck = 0; m_iMZCheck < 0x10;  m_iMZCheck++)
						{
							if(*(WORD *)&m_byDecrypBuff[m_iMZCheck] == 0x392E)
								break;
						}
						if(m_iMZCheck == 0x10)
							m_iMZCheck = 0;
						for(int j = m_iMZCheck; j <= (0x64 + m_iMZCheck);  j++)
						{
							m_byDecrypBuff[j] ^= byXorKey;
						}
						if (m_dwFirstSecOffset > 0x19)
						{
							if(m_byDecrypBuff[m_dwFirstSecOffset - 0x19])
							{
								byXorKey = 0x44;
								for(int j = m_dwFirstSecOffset - 0x19; j < m_dwFirstSecOffset + 0x4C;  j++)
								{
									m_byDecrypBuff[j] ^= byXorKey;
								}
								m_dwFirstSecOffset += 0x4C;
							}
							else
								m_dwFirstSecOffset = 0x64;

						}
						else
							m_dwFirstSecOffset = 0x64;

						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	return bRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: DecryptionLamerEL
	In Parameters	: DWORD dwDecStart,DWORD dwXorKey
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		:Decryption routine for lamer.el
--------------------------------------------------------------------------------------*/
int CPolyLamerEL::DecryptionLamerEL(DWORD dwDecStart,DWORD dwXorKey)
{
	DWORD dwChunk = 0x1000,dwBytesToRead=0;
	if((m_pMaxPEFile->m_dwFileSize  -  dwDecStart)< dwChunk)
	{
		dwChunk = m_pMaxPEFile->m_dwFileSize  -  dwDecStart;
	}
	for(dwDecStart; dwDecStart < m_pMaxPEFile->m_dwFileSize; dwDecStart += dwChunk)
	{
		dwBytesToRead = (m_pMaxPEFile->m_dwFileSize - dwDecStart) < dwChunk ?  (m_pMaxPEFile->m_dwFileSize - dwDecStart) : dwChunk;

		m_byDecrypBuff = new BYTE[0x1000];
		if(!m_pMaxPEFile->ReadBuffer(m_byDecrypBuff,dwDecStart, dwBytesToRead, dwBytesToRead))
		{
			dwDecStart=0;
			return dwDecStart;
		}
		for(int i = 0; i < dwBytesToRead;  i ++)
		{
			const BYTE bySignature[] = {0x56,0x62,0x45,0x78,0x65,0x46,0x69,0x6C,0x65,0x42,0x69,0x6E,0x64};
			if(memcmp(&m_byDecrypBuff[i], bySignature, sizeof(bySignature)) == 0x00)
			{
				if((m_pMaxPEFile->m_dwFileSize - dwDecStart) >= 0x400)
				{
					dwDecStart += (sizeof(bySignature)+ i);
					if(m_pMaxPEFile->ReadBuffer(m_byDecrypBuff,dwDecStart,0x400,0x400))
					{	
						if(*(WORD *)&m_byDecrypBuff[0]!= 0x5a4d)
						{
							for(int j = 0; j < 0x64;  j++)
							{
								*(WORD *)&m_byDecrypBuff[j] ^= dwXorKey;
							}
							m_dwStartOffset += i;
							return DecryptionLamerEL1(dwDecStart);
						}
						else
						{
							return DecryptionLamerEL1(dwDecStart);
						}
					}
				}
			}
		}
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
	Function		: DecryptionLamerEL
	In Parameters	: DWORD dwDecStart,DWORD dwXorKey
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Decryption routine for lamer.el
--------------------------------------------------------------------------------------*/
int CPolyLamerEL::DecryptionLamerEL1(DWORD dwOffset)
{
	DWORD dwNoSectionsOffset,dwLSecPrd = 0,dwLSecSrd = 0,dwCerticatetable = 0,dwPEOffset = 0,m_dwMZOffset=0, dwFSecPrd;
	dwPEOffset = *(DWORD *)&m_byDecrypBuff[0x3C];
	if(dwPEOffset > 0x400 || *(WORD *)&m_byDecrypBuff[dwPEOffset] != 0x4550)
	{
		dwOffset=0;
		return dwOffset;
	}

	dwNoSectionsOffset = *(DWORD *)&m_byDecrypBuff[0x3C] + 0x06;
	dwCerticatetable = *(DWORD *)&m_byDecrypBuff[0x3C] + 0x18 +  0x80;
	dwLSecSrd = *(DWORD *)&m_byDecrypBuff[0x3C] + 0x18 + 0xE0 + ((*(WORD *)&m_byDecrypBuff[dwNoSectionsOffset] -1) * 0x28) + 0x10;
	dwLSecPrd = *(DWORD *)&m_byDecrypBuff[0x3C] + 0x18 + 0xE0 + ((*(WORD *)&m_byDecrypBuff[dwNoSectionsOffset] -1) * 0x28) + 0x14;
	m_dwFirstSecOffset = *(DWORD *)&m_byDecrypBuff[0x3C] + 0x18 + 0xE0  + 0x14;
	m_dwFirstSecOffset =  *(DWORD *)&m_byDecrypBuff[m_dwFirstSecOffset];
	if( m_dwFirstSecOffset >m_pMaxPEFile->m_dwFileSize)
		m_dwFirstSecOffset = 0;

	if(*(DWORD *)&m_byDecrypBuff[dwCerticatetable] > m_pMaxPEFile->m_dwFileSize)
		return dwOffset;

	if(*(DWORD *)&m_byDecrypBuff[dwCerticatetable] != 0)
	{
		if(*(DWORD *)&m_byDecrypBuff[dwCerticatetable] == (*(DWORD *)&m_byDecrypBuff[dwLSecSrd] + *(DWORD *)&m_byDecrypBuff[dwLSecPrd]))
		{
			dwCerticatetable = *(DWORD *)&m_byDecrypBuff[dwCerticatetable + 4];
		}
		else
		{
			dwCerticatetable = *(DWORD *)&m_byDecrypBuff[dwCerticatetable + 4] + ( *(DWORD *)&m_byDecrypBuff[dwCerticatetable] - (*(DWORD *)&m_byDecrypBuff[dwLSecSrd] + *(DWORD *)&m_byDecrypBuff[dwLSecPrd]));
		}
	}
	else
	{
		dwCerticatetable = 0;
	}
	if(dwCerticatetable > m_pMaxPEFile->m_dwFileSize)
		return dwOffset;

	dwOffset += *(DWORD *)&m_byDecrypBuff[dwLSecSrd] + *(DWORD *)&m_byDecrypBuff[dwLSecPrd] + dwCerticatetable;

	if(dwOffset > m_pMaxPEFile->m_dwFileSize)
		return 0;

	int x = 0;
	int counter=0,iSign1 = 0, iSign2 = 0;
	const BYTE bySignature1[] = {0x53,0x68,0x69,0x74,0x2C,0x49,0x73,0x4F,0x76,0x65,0x72};
	const BYTE bySignature2[] = {0x56,0x62,0x45,0x78,0x65,0x46,0x69,0x6C,0x65,0x42,0x69,0x6E,0x64};
	DWORD dwReadByte = 0x40;
	while(!iSign1 && !iSign2 && (dwOffset + 0xC <= m_pMaxPEFile->m_dwFileSize ))
	{
		if(m_byDecrypBuff)
		{
			delete []m_byDecrypBuff;
			m_byDecrypBuff =NULL;
		}
		if(m_pMaxPEFile->m_dwFileSize - dwOffset < 0x40)
		{
			dwReadByte = m_pMaxPEFile->m_dwFileSize - dwOffset;
		}
		m_byDecrypBuff = new BYTE[dwReadByte];
		if(!m_pMaxPEFile->ReadBuffer(m_byDecrypBuff,dwOffset,dwReadByte,dwReadByte))
		{
			dwOffset=0;
			return dwOffset;
		}

		for(int k = 0; k < dwReadByte; k ++)
		{
			if(iSign2 == 0)
			{
				if(memcmp(&m_byDecrypBuff[k], bySignature1, sizeof(bySignature1)) == 0x00)
				{ 
					x=k;
					k+=sizeof(bySignature1);
					counter++;
					if(counter ==1)
					{
						dwOffset += 0xD;
					}
					iSign1 = 1;
				}
			}
			if(iSign1 == 0)
			{
				if(memcmp(&m_byDecrypBuff[k], bySignature2, sizeof(bySignature2)) == 0x00)
				{ 
					dwOffset += k;
					iSign2 = 1;
				}
			}
		}

		if(!iSign1 && !iSign2)
		{
			dwOffset += dwReadByte;
			dwReadByte = 0x1000;
		}
		if(x != 0)
		{
			dwOffset += x;
		}
	}

	return dwOffset;
}			

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Alisha + Virus Analysis Team
	Description		: Repair routine for different varients of Lamer.EL Family
--------------------------------------------------------------------------------------*/
int CPolyLamerEL::CleanVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if (m_dwAEPMapped == 0x1FD4 || m_dwAEPMapped == 0x2BD4)//added
	{

		if(m_pMaxPEFile->WriteBuffer(m_pbyBuff, 0,  m_dwFirstSecOffset+0x4C,  m_dwFirstSecOffset + 0x4C))
		{
			DWORD dwCopyDataSize = 0x00;
			dwCopyDataSize= m_dwOrigFileSize-(m_dwFirstSecOffset + 0x4C);
			if(m_pMaxPEFile->CopyData(m_dwOrigFileOff + m_dwFirstSecOffset + 0x4C, m_dwFirstSecOffset + 0x4C, dwCopyDataSize, dwCopyDataSize))
			{
				if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	else
	{
		for(m_iMZCheck = 0; m_iMZCheck < 0x64;  m_iMZCheck++)
		{
			if(*(WORD *)&m_byDecrypBuff[m_iMZCheck] == 0x5A4D)
				break;
		}
		if(m_iMZCheck == 0x10)
			m_iMZCheck = 0;
		DWORD dwCopyDataSize = m_pMaxPEFile->m_dwFileSize - m_dwStartOffset - m_dwFirstSecOffset - 0xD;
		if(m_pMaxPEFile->WriteBuffer(m_byDecrypBuff+m_iMZCheck, 0,  m_dwFirstSecOffset,  m_dwFirstSecOffset))
		{
			if(m_pMaxPEFile->CopyData(m_dwStartOffset + m_dwFirstSecOffset + m_iMZCheck, m_dwFirstSecOffset,dwCopyDataSize ,dwCopyDataSize))
			{
				if(m_pMaxPEFile->ForceTruncate((m_pMaxPEFile->m_dwFileSize - m_dwStartOffset)-0xD))
				{
					return REPAIR_SUCCESS;
				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyPatchedQr
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPatchedQr::CPolyPatchedQr(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP=0;
	m_dwPatchSize=0;
	m_dwPatchStart=0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPatchedQr
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPatchedQr::~CPolyPatchedQr(void)
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
	Author			: Tushar Kadam + Ramandeep + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Patched.qr Family
--------------------------------------------------------------------------------------*/
int CPolyPatchedQr::DetectVirus()
{
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		if(m_wAEPSec==0x00&& (m_pMaxPEFile->m_stPEHeader.CheckSum == 0x7F42 ||  m_pMaxPEFile->m_stPEHeader.CheckSum == 0xEE63) && (m_dwAEPUnmapped >=0x345C || m_dwAEPUnmapped <= 0x48E8)&& (m_pSectionHeader[m_wAEPSec].SizeOfRawData ==0x3A00
			|| m_pSectionHeader[m_wAEPSec].SizeOfRawData ==0x2C00 )&& m_wNoOfSections == 0x04 )
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff =NULL;
			}

			const int	PATCHEDQR_BUFF_SIZE = 0x55;
			m_pbyBuff = new BYTE[PATCHEDQR_BUFF_SIZE];
			if(!m_pbyBuff)
			{
				return VIRUS_NOT_FOUND;
			}

			DWORD	dwBuffOffset = m_dwAEPMapped - 0x30 , dwCallOffset = 0;

			BYTE *bCallBuff = new BYTE[0x5];
			int iCallFlag = 0;
			if(m_pMaxPEFile->ReadBuffer(&bCallBuff[0],m_dwAEPMapped,0x5,0x5))
			{
				if(bCallBuff[0] == 0xE8)
				{
					dwBuffOffset = *(DWORD *)&bCallBuff[0x1] + m_dwAEPUnmapped + 0x5 ;
					if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwBuffOffset,&dwBuffOffset))
					{
						return VIRUS_NOT_FOUND;
					}
					dwBuffOffset = dwBuffOffset - 0x30;
					dwCallOffset = dwBuffOffset;
					iCallFlag = 1;
				}
			}

			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			m_pbyBuff = new BYTE[PATCHEDQR_BUFF_SIZE];
			if(!GetBuffer(dwBuffOffset,PATCHEDQR_BUFF_SIZE,PATCHEDQR_BUFF_SIZE))
			{
				return VIRUS_NOT_FOUND;
			}

			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};
			LPCTSTR			szPatchedQr = (_T("EB11585005*FFFF8B00FFD0*FFFFC3E8EAFFFFFF"));
			LPCTSTR			szPatchedQr1 = (_T("EB115850*9090FFD0E9*FFFFC3E8EAFFFFFF*2E646C6C"));

			polydbObj.LoadSigDBEx(szPatchedQr, _T("Trojan.W32.Patched.qr"), TRUE);
			polydbObj.LoadSigDBEx(szPatchedQr1, _T("Trojan.W32.Patched.qr1"), TRUE);

			if(polydbObj.ScanBuffer(m_pbyBuff, PATCHEDQR_BUFF_SIZE, szVirusName) >= 0)
			{
				if(_tcslen(szVirusName) > 0)
				{
					DWORD	iIndex = 0x0;
					BYTE	byCheckSig[] = {0xEB,0x11,0x58};

					if(OffSetBasedSignature(byCheckSig,sizeof(byCheckSig),&iIndex))
					{
						if(m_pbyBuff[0xD + iIndex] == 0xEB)
						{
							m_dwOriginalAEP = m_pbyBuff[0xE + iIndex] + (dwBuffOffset - m_pSectionHeader[0].PointerToRawData + m_pSectionHeader[0].VirtualAddress)+ iIndex + 0xD +2;
							dwBuffOffset =  m_dwOriginalAEP - (dwBuffOffset - m_pSectionHeader[0].PointerToRawData + m_pSectionHeader[0].VirtualAddress);
							m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[dwBuffOffset +1] + (m_dwOriginalAEP + 0x5);
						}
						else
							m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[iIndex + 0xE] + (m_dwAEPUnmapped + iIndex -0x30+0xD+0x5);

						m_dwPatchSize = 0x25;
						if(iCallFlag)
							m_dwPatchStart = dwCallOffset + iIndex;
						else
							m_dwPatchStart = m_dwAEPMapped + iIndex - 0x30;

						if(m_dwOriginalAEP >=m_dwAEPUnmapped )
							return VIRUS_NOT_FOUND;

						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);	
						return VIRUS_FILE_REPAIR;

					}
				}
				return VIRUS_NOT_FOUND;
			}
			return VIRUS_NOT_FOUND;
		}

	}


	if(m_wAEPSec==0x00 &&(m_dwAEPUnmapped ==0x48BD || m_dwAEPUnmapped ==0x3B85)&& (m_pSectionHeader[m_wAEPSec].Misc.VirtualSize ==0x38BD
		||m_pSectionHeader[m_wAEPSec].Misc.VirtualSize ==0x2B85 )&& m_wNoOfSections == 0x04 &&( m_pMaxPEFile->m_dwFileSize==0x4C00 || m_pMaxPEFile->m_dwFileSize==0x4A00))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff =NULL;
		}

		const int	PATCHEDQR_BUFF_SIZE = 0x25;
		m_pbyBuff = new BYTE[PATCHEDQR_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return VIRUS_NOT_FOUND;
		}

		DWORD	dwBuffOffset = m_dwAEPMapped;

		//m_pbyBuff = new BYTE[PATCHEDQR_BUFF_SIZE];
		if(!GetBuffer(dwBuffOffset,PATCHEDQR_BUFF_SIZE,PATCHEDQR_BUFF_SIZE))
		{
			return VIRUS_NOT_FOUND;
		}

		CSemiPolyDBScn	polydbObj;
		TCHAR			szVirusName[MAX_PATH] = {0};
		LPCTSTR			szPatchedQr = (_T("EB11585005*FFFF8B00FFD0E9*FFFFC3E8EAFFFFFF*2E646C6C"));
		polydbObj.LoadSigDBEx(szPatchedQr, _T("Trojan.W32.Patched.qr"), FALSE);
		if(polydbObj.ScanBuffer(m_pbyBuff, PATCHEDQR_BUFF_SIZE, szVirusName) >= 0)
		{
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);	
				m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[0xe] + (m_dwAEPUnmapped + 0xd + 0x5);
				if(m_dwOriginalAEP >=m_dwAEPUnmapped )
				{
					return VIRUS_NOT_FOUND;
				}
				m_dwPatchSize = 0x25; 
				m_dwPatchStart = m_dwAEPMapped;
				return VIRUS_FILE_REPAIR;

			}
			return VIRUS_NOT_FOUND;
		}
		return VIRUS_NOT_FOUND;
	}
	return VIRUS_NOT_FOUND;//end check if
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Patched.QR Family
--------------------------------------------------------------------------------------*/
int CPolyPatchedQr::CleanVirus()
{
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(	m_pMaxPEFile->FillWithZeros(m_dwPatchStart, m_dwPatchSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyPatchedQw
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPatchedQw::CPolyPatchedQw(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwEggOffset=0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyPatchedQw
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPatchedQw::~CPolyPatchedQw(void)
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
	Author			: Tushar Kadam + Ramandeep + Alisha + Virus Analysis Team
	Description		: Detection routine for different varients of Patched.qw Family
					  Infected dll files named dnsapi.dll.This makes all windows files which resolve dns to load the 
                      local dns information from a file specified by the malware author rather than loading the dns
					  information from hosts file placed in drivers/etc/hosts....
--------------------------------------------------------------------------------------*/
int CPolyPatchedQw::DetectVirus()
{
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{
		return VIRUS_NOT_FOUND;
	}


	int		iRetStatus = VIRUS_NOT_FOUND;
	TCHAR	szDNSFilePath[MAX_PATH] = {0};
	TCHAR	*pTemp = NULL;

	/*
	TCHAR	szFilePathTemp[MAX_PATH] = {0};
	TCHAR	szInternalName[MAX_PATH] = {0};
	TCHAR	szInternalNameStatic[MAX_PATH] = {0};
	
	TCHAR	*pTemp = NULL;

	_tcscpy_s(szFilePathTemp, MAX_PATH,m_pMaxPEFile->m_szFilePath);
	_tcscpy_s(szInternalNameStatic,_T("dnsapi"));


	////////////////////////////////////////////////////////////////////////////////////////
	if(!GetInfo(szFilePathTemp,szInternalName,L"InternalName"))
	{
		return iRetStatus;
	}

	if(_tcsstr(szInternalNameStatic,szInternalName) == NULL)
	{
		return iRetStatus;
	}
	*/

	DWORD	dwNameID = 0x10, dwLang = 0x1 , dwLangID = 0x409, dwRVA = 0x0 , dwSize = 0x0, dwReadOffset = 0x0;
	if(!FindRes(LPCTSTR(&dwNameID), LPCTSTR(&dwLang), LPCTSTR(&dwLangID), dwRVA, dwSize))
	{
		return VIRUS_NOT_FOUND;
	}
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwRVA, &dwReadOffset))
	{
		return iRetStatus;
	}
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}  

	m_pbyBuff = new BYTE[dwSize];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0x00, dwSize);

	if(!GetBuffer(dwReadOffset,dwSize,dwSize))
	{
		return iRetStatus;
	}
	const BYTE bSig[] = {0x49,0x00,0x6E,0x00,0x74,0x00,0x65,0x00,0x72,0x00,0x6E,0x00,0x61,0x00,0x6C,0x00,0x4E,0x00,0x61,0x00,0x6D,0x00,0x65,0x00,0x00,0x00,0x64,0x00,0x6E,0x00,0x73,0x00,0x61,0x00,0x70,0x00,0x69};
	//I.n.t.e.r.n.a.l.N.a.m.e...d.n.s.a.p.i
	boolean bFound = false;
	for(int iCnt = 0; iCnt <dwSize; iCnt++)	
	{
		if(memcmp(&m_pbyBuff[iCnt], bSig, sizeof(bSig)) == 0)
		{
			bFound = true;
			break;
		}
	}

	if(!bFound)
	{
		return iRetStatus;
	}


	//////////////////////////////////////////////////////////////////////////////////////
	BYTE		bEgg[]		= {0x2E,0x64,0x61,0x74,0x00}; //.dat.
	BYTE		bEgg1[]		= {0x68,0x6F,0x73,0x74,0x73,0x2E,0x69,0x63,0x73}; //hosts.ics                                                      
	DWORD	dwBuffOffset =0;
	dwBuffOffset=m_pSectionHeader[m_wAEPSec].PointerToRawData ;
	int PATCHEDQW_BUFF_SIZE =m_pMaxPEFile->m_dwFileSize-dwBuffOffset;


	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}  


	m_pbyBuff = new BYTE[PATCHEDQW_BUFF_SIZE];
	if(!m_pbyBuff)
	{
		return iRetStatus;
	}

	memset(m_pbyBuff, 0x00, PATCHEDQW_BUFF_SIZE);

	if(!GetBuffer(dwBuffOffset,PATCHEDQW_BUFF_SIZE,PATCHEDQW_BUFF_SIZE))
	{
		return iRetStatus;
	}
	int iCount=0x0;

	//loop to find egg
	while(iCount<=(PATCHEDQW_BUFF_SIZE -0x12))
	{
		if(memcmp(&m_pbyBuff[iCount],bEgg,sizeof(bEgg)) == 0x0)
		{
			m_dwEggOffset =iCount+dwBuffOffset-14; //to get file offset of the start of the string
			break;
		}
		iCount++;
	}
	//check companion string(egg) near the malicious injected string
	int iCount1=iCount -50;
	bool bDetected;

	while(iCount1<=iCount+50)
	{
		if(memcmp(&m_pbyBuff[iCount1],bEgg1,sizeof(bEgg1)) == 0x0)
		{
			bDetected=0;
			break;
		}
		iCount1++;
	}

	if(bDetected)
	{
		return iRetStatus;  

	}


	//string validation checks 				
	mbstowcs(szDNSFilePath,(char *)(&m_pbyBuff[iCount-14]), 0x12);

	TCHAR	szExclusionList[MAX_PATH] = {0x00};
	int		iLen = 0x00, kCnt = 0x00;


	pTemp = NULL;
	_tcscpy(szExclusionList,_T(".\\"));
	iLen = _tcslen(szDNSFilePath);

	for (int i = 0x00;  i < iLen; i++)
	{

		pTemp = _tcsrchr(szExclusionList,szDNSFilePath[i]);
		if (pTemp != NULL)
		{
			kCnt++;
			pTemp = NULL;
			continue;
		}


	}
	if(kCnt!=4)
	{
		return iRetStatus; //the number of / and . dont fit 
	}

	_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Trojan.Win32.Patched.qw"));

	return VIRUS_FILE_REPAIR;//end check if
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ramandeep + Alisha + Virus Analysis Team
	Description		: Repair routine for different varients of Patched.QW Family
--------------------------------------------------------------------------------------*/
int CPolyPatchedQw::CleanVirus()
{
	BYTE		bEggReplacer[]	= {0x5C,0x64,0x72,0x69,0x76,0x65,0x72,0x73,0x5C,0x65,0x74,0x63,0x5C,0x68,0x6F,0x73,0x74,0x73}; //\drivers\etc\hosts

	if(	m_pMaxPEFile->FillWithZeros(m_dwEggOffset, 0x12))
	{
		if(m_pMaxPEFile->WriteBuffer(bEggReplacer,m_dwEggOffset,0x12,0x12));
		{
			if(m_pMaxPEFile->CalculateChecksum())
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;

}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: LPCTSTR szFullPathh,LPTSTR szInternalName,LPCTSTR szInfoToGet
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Ramandeep + Alisha + Virus Analysis Team
	Description		: Collects the nformation required for detection and repair
--------------------------------------------------------------------------------------*/
bool CPolyPatchedQw::GetInfo(LPCTSTR szFullPathh,LPTSTR szInternalName,LPCTSTR szInfoToGet)

{

	TCHAR    szResult[MAX_PATH] = {0};
	TCHAR    szFullPath[MAX_PATH]= {0};
	TCHAR   szGetName[MAX_PATH]= {0};

	LPCTSTR   lpVersion;        // String pointer to Item text
	DWORD   dwVerInfoSize;    // Size of version information block
	DWORD   dwVerHnd=0;        // An 'ignored' parameter, always '0'
	UINT    uVersionLen;
	BOOL    bRetCode;

	_tcscpy_s(szFullPath, MAX_PATH,  szFullPathh);


	// GetModuleFileName (NULL, szFullPath, sizeof(szFullPath));

	dwVerInfoSize = GetFileVersionInfoSize(szFullPath, &dwVerHnd);

	if (dwVerInfoSize) {

		LPSTR   lpstrVffInfo;
		HANDLE  hMem;
		hMem = GlobalAlloc(GMEM_MOVEABLE, dwVerInfoSize);
		lpstrVffInfo  =  (LPSTR)GlobalLock(hMem);

		GetFileVersionInfo(szFullPath, dwVerHnd, dwVerInfoSize, lpstrVffInfo);


		// Get a codepage from base_file_info_sctructure

		lstrcpy(szGetName, _T("\\VarFileInfo\\Translation"));


		uVersionLen   = 0;
		lpVersion     = NULL;

		bRetCode = VerQueryValue((LPVOID)lpstrVffInfo,
			(LPCTSTR)szGetName,
			(void **)&lpVersion,
			(UINT *)&uVersionLen);

		if ( bRetCode && uVersionLen && lpVersion) {

			_stprintf(szResult, L"%04x%04x", (WORD)(*((DWORD *)lpVersion)),

				(WORD)(*((DWORD *)lpVersion)>>16));

			//            lstrcpy(szResult, lpVersion);

		}

		else {

			// 041904b0 is a very common one, because it means:

			//   US English/Russia, Windows MultiLingual characterset

			// Or to pull it all apart:

			// 04------        = SUBLANG_ENGLISH_USA

			// --09----        = LANG_ENGLISH

			// --19----        = LANG_RUSSIA

			// ----04b0 = 1200 = Codepage for Windows:Multilingual

			lstrcpy(szResult, _T("041904b0"));

		}


		// Add a codepage to base_file_info_sctructure

		_stprintf(szGetName, L"\\StringFileInfo\\%s\\", szResult);

		// Get a specific item
		TCHAR    szOption[MAX_PATH] = {0};
		_tcscpy_s(szOption, MAX_PATH, szInfoToGet);

		lstrcat (szGetName, szInfoToGet);


		uVersionLen   = 0;

		lpVersion     = NULL;

		bRetCode = VerQueryValue((LPVOID)lpstrVffInfo,

			(LPCTSTR)szGetName,

			(void **)&lpVersion,

			(UINT *)&uVersionLen);

		if ( bRetCode && uVersionLen && lpVersion) {

			lstrcpy(szResult, lpVersion);

		}

		else {

			lstrcpy(szResult, _T(""));

		}


	}

	if (szResult[0x00] == 0x00)
	{
		return false;
	}
	_tcslwr(szResult);
	_tcscpy_s(szInternalName, MAX_PATH, szResult);

	return true;

}

/*-------------------------------------------------------------------------------------
	Function		: CPolyTenga
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTenga:: CPolyTenga(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{

}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTenga
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTenga::~ CPolyTenga(void)
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
	Author			: Tushar Kadam + Santosh Awale + Virus Analysis Team
	Description		: Detection routine for different varients of Tenga Family
					  loop decrypting the code
--------------------------------------------------------------------------------------*/
int CPolyTenga::DetectVirus()
{
	int		iRetStatus = VIRUS_NOT_FOUND;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff =NULL;
	}

	const int TENGA_BUFF_SIZE = 0xB;
	m_pbyBuff = new BYTE[TENGA_BUFF_SIZE];
	if(!m_pbyBuff)
	{
		return VIRUS_NOT_FOUND;
	}		

	BYTE TENGA_Sig[] = {0x4F,0x66,0x31,0xFF,0x66,0x81,0x3F,0x4D,0x5A,0x75,0xF5};

	if(GetBuffer(m_dwAEPMapped+13,TENGA_BUFF_SIZE,TENGA_BUFF_SIZE))
	{
		if(memcmp(&m_pbyBuff[0x00],TENGA_Sig, sizeof(TENGA_Sig)) == 0)
		{
			if(GetBuffer(m_dwAEPMapped+3,0x4,04))
			{
				dwOriAep=*(DWORD *)&m_pbyBuff[0x0];

				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("virus.tenga.a"));
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Tenga Family
--------------------------------------------------------------------------------------*/
int CPolyTenga::CleanVirus()
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
	{
		if(m_pMaxPEFile->WriteAEP(dwOriAep))
		{
			return REPAIR_SUCCESS;
		}
	}
	return iRetStatus;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolyReconyc
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyReconyc::CPolyReconyc(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwReplaceOffset = 0x00;
	m_dwTruncateSize = 0x00;
	m_dwReplaceOffset1 = 0x00;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyReconyc
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyReconyc::~CPolyReconyc(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of Reconyc Family
					  Trojan Reconcy.Gen : Trojan.Reconyc.guvm Trojan.Reconyc.cdbq
					  >this file infect to .exe files 
                      >this is prepender virus 
					  >and added code at start of clean file
--------------------------------------------------------------------------------------*/
int CPolyReconyc::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
		return iRetStatus;

	if(m_wNoOfSections == 0x2 && (m_dwAEPMapped == 0x46138 || m_dwAEPMapped == 0x45DA4) && (m_pSectionHeader[0].SizeOfRawData == 0x5A000 || m_pSectionHeader[0].SizeOfRawData == 0x59000) && (m_pMaxPEFile->m_stPEHeader.CheckSum == 0x239B3 || m_pMaxPEFile->m_stPEHeader.CheckSum == 0x23203))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int RECONYC_BUFF_SIZE = 0x3D4;
		m_pbyBuff = new BYTE[RECONYC_BUFF_SIZE];

		byte bDecryptionKey = 0x0A;

		if(GetBuffer(0x459C8,  RECONYC_BUFF_SIZE,  RECONYC_BUFF_SIZE))
		{   
			for(int i=0; i<0x3D4; i++)
			{
				m_pbyBuff[i] ^= bDecryptionKey;
			}

			TCHAR  RECONYC_CZ_Sig[] = {_T("687474703a2f2f7777772e3538736b792e636f6d*687474703a2f2f77782e676f3839302e636f6d")};
			//http ://www.58sky.com 
			//http ://wx.go890.com
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx( RECONYC_CZ_Sig, _T("Trojan Reconcy.Gen"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],RECONYC_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;
				}
			}
		}
	}
	else if(m_wAEPSec == 0x0	&& m_wNoOfSections == 0x3 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x26000)
	{

		m_dwReplaceOffset = 0x00;
		m_dwTruncateSize = 0x00;
		m_dwReplaceOffset1 = 0x00;

		TCHAR szVirusName[MAX_PATH] = {0};
		CSemiPolyDBScn polydbObj;
		TCHAR szReconyc[] = _T("F43B400001F830*74394000F43A4000A43040");
		polydbObj.LoadSigDBEx(szReconyc, _T("Trojan.Reconyc.cdbq"), FALSE);

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int RECONYC_BUFF_SIZE = 0x2D;
		m_pbyBuff = new BYTE[RECONYC_BUFF_SIZE];

		if(!GetBuffer(0X3914,RECONYC_BUFF_SIZE,RECONYC_BUFF_SIZE))
		{
			return iRetStatus;
		}
		if(polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName) >= 0)
		{ 
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

				if(m_pMaxPEFile->ReadBuffer(&m_dwTruncateSize, m_pMaxPEFile->m_dwFileSize - 0x19, 4, 4))
				{      
					if(m_dwTruncateSize > m_pMaxPEFile->m_dwFileSize)  // added
					{
						return VIRUS_FILE_DELETE;
					}
					m_dwReplaceOffset = m_pMaxPEFile->m_dwFileSize - m_dwTruncateSize;
					m_dwReplaceOffset1 = m_dwReplaceOffset - 0x19;

				}

				WORD	byCheckMz = 0x0;
				if(m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwReplaceOffset1,0x2,0x2))
				{
					if(byCheckMz != 0x5A4D)
					{
						return VIRUS_FILE_DELETE;
					}
				}
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Reconyc Family
--------------------------------------------------------------------------------------*/
int CPolyReconyc::CleanVirus(void)
{	
	int iRetStatus = REPAIR_FAILED;
	
	if(m_wNoOfSections == 0x3)
	{
       m_dwReplaceOffset1 = m_dwReplaceOffset - 0x19;
	}
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset1, 0, m_dwTruncateSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwTruncateSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyMEWSPY
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyMEWSPY::CPolyMEWSPY(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   //CPolyDeemo
{
	DWORD m_dwOriginalFileSize=0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyMEWSPY
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyMEWSPY::~CPolyMEWSPY(void)
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
	Author			: Tushar Kadam + Swapnil Sanghai + Virus Analysis Team
	Description		: Detection routine for different varients of Virus.Mewspy.F Family
--------------------------------------------------------------------------------------*/
int CPolyMEWSPY::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x5 && m_dwAEPMapped == 0x530  && m_pSectionHeader[0].SizeOfRawData ==0x1400)
	{
		DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		DWORD dwOverlaySize = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);
		if(dwOverlayStart == 0x1D600 && dwOverlaySize >= 0x2FE31 && dwOverlaySize!=0)//changes
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int MEWSPY_BUFF_SIZE = 0xA0;
			m_pbyBuff = new BYTE[MEWSPY_BUFF_SIZE];
			if(GetBuffer(dwOverlayStart, MEWSPY_BUFF_SIZE, MEWSPY_BUFF_SIZE))
			{
				TCHAR			MEWSPY_CZ_Sig[] = {_T("4A3136645542457A464B69554374584E5137744B504B43434B*464D316E57656D6D4E5675694E43726B7941374259*6D30434D76346953357330543768695257694C43305461483550743549315337726F71*50686A79327436343666544B4958576C506B")};
				CSemiPolyDBScn	polydbObj;
				TCHAR			szVirusName[MAX_PATH] = {0};
				int				i =0x00,j = 0x00;
				unsigned int	m_iBufferSize = 0;
				char			szFilesizeBuff1[0xB], *szDummmy = NULL ;

				polydbObj.LoadSigDBEx(MEWSPY_CZ_Sig, _T("Virus.Mewspy.F"), FALSE);
				if(polydbObj.ScanBuffer(&m_pbyBuff[0], MEWSPY_BUFF_SIZE , szVirusName)>=0)	
				{
					BYTE bOverlayDecryptKey[0x62] = {0};
					DWORD dwBuffSize = 0x62;
					if(m_pMaxPEFile->ReadBuffer(bOverlayDecryptKey,dwOverlayStart + 0x66,dwBuffSize,dwBuffSize))
					{
						for(int ikey = 0, idata = 0x35; ikey<0x35, idata<dwBuffSize; ikey++,idata++)
						{
							bOverlayDecryptKey[idata]= ~bOverlayDecryptKey[idata];
							bOverlayDecryptKey[idata]^=bOverlayDecryptKey[ikey]-1;
						}


						memset(szFilesizeBuff1,0,0xB);
						for(j = 0x35;i<0xA, j<0x3F; i++,j++)				
							sprintf(szFilesizeBuff1+i,"%c",bOverlayDecryptKey[j]);	
					}
					m_dwOriginalFileSize = strtol(szFilesizeBuff1,&szDummmy,10); 
					memset(szFilesizeBuff1,0,0xB);
					for(j = 0x56, i = 0x0; i<0xA,j<0x60; i++,j++)				
					{
						sprintf(szFilesizeBuff1 + i,"%c",bOverlayDecryptKey[j]);
					}
					DWORD dwFileStart = strtol(szFilesizeBuff1,&szDummmy,10);
					memset(szFilesizeBuff1,0,0xB);
					for(j = 0x4B, i = 0x0;i<0xA, j<0x55; i++,j++)				
					{
						sprintf(szFilesizeBuff1 + i,"%c",bOverlayDecryptKey[j]);
					}
					DWORD dwNewSize = strtol(szFilesizeBuff1,&szDummmy,10);
					memset(szFilesizeBuff1,0,0xB);
					for(j = 0x40, i = 0x0;i<0xA, j<0x4A; i++,j++)				
					{
						sprintf(szFilesizeBuff1 + i,"%c",bOverlayDecryptKey[j]);
					}

					DWORD dwDecryptionK = strtol(szFilesizeBuff1,&szDummmy,10);
					DWORD Key1;
					DWORD BDE;
					DWORD BDA=0;
					//BYTE *bEncryptedBuff;

					const int Buff_Size = m_dwOriginalFileSize;
					//bEncryptedBuff = new BYTE[Buff_Size];
					if(m_pbyBuff)
					{
						delete []m_pbyBuff;
						m_pbyBuff = NULL;
					}

					m_pbyBuff = new BYTE[Buff_Size];
					DWORD byread = 0x0;

					if(!GetBuffer(dwOverlayStart+dwNewSize+0xC7,Buff_Size,Buff_Size))
					{
						return iRetStatus;
					}

					for(i=0 ; i<m_dwOriginalFileSize ; i++ )
					{
						dwDecryptionK = dwDecryptionK * 0x343FD;
						dwDecryptionK = dwDecryptionK + 0x269EC3;
						Key1 = dwDecryptionK;
						Key1 = Key1 >> 0x10;
						Key1 = Key1 & 0x7FFF;
						BDE = Key1% 0xFF;
						BDE = 0xFF-BDE;
						m_pbyBuff[i]^=BDE;
					}
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.W32.MewSpy"));	
					return VIRUS_FILE_REPAIR;
				}
			}
		}

		else 
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}
			const int MEWSPY_BUFF_SIZE = 0xCFF;//changes
			m_pbyBuff = new BYTE[MEWSPY_BUFF_SIZE];

			if(GetBuffer(m_pSectionHeader[0x0].PointerToRawData + 0x3BC, MEWSPY_BUFF_SIZE, MEWSPY_BUFF_SIZE)) //changes
			{
				TCHAR MEWSPY_CZ_Sig[] = {_T("33C98A1C11F6DB301C3040413BC7*69F6FD43030081C6C39E26008BC6C1E8*69F6FD43030081C6C39E26008BC6C1E8*D2BBFF000000F7F38B450C41FEC28854")}; //changes
				CSemiPolyDBScn polydbObj;
				polydbObj.LoadSigDBEx(MEWSPY_CZ_Sig, _T("Virus.W32.MewSpy"), FALSE);
				TCHAR szVirusName[MAX_PATH] = {0};

				if(polydbObj.ScanBuffer(&m_pbyBuff[0], MEWSPY_BUFF_SIZE , szVirusName)>=0)	
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
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Virus.Mewspy.F Family
--------------------------------------------------------------------------------------*/
int CPolyMEWSPY::CleanVirus()
{

	if(m_pMaxPEFile->WriteBuffer(m_pbyBuff,0,m_dwOriginalFileSize ,m_dwOriginalFileSize ))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOriginalFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}

	return FALSE;

}


/*-------------------------------------------------------------------------------------
	Function		: CPolyInfector
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyInfector::CPolyInfector(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOverlaySize = 0;
    m_dwMoveDataSize = 0;
    m_dwStratBuff = 0;
    bDecryptionKey = 0;
    m_dwOriginalAEP = 0;
    m_infectorType = 0;
    m_dwOrigAEP = 0;
    m_dwOrigFileOffset=0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyInfector
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyInfector::~CPolyInfector(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of Infector Family
					  >it is a appender virus
					  >it infect .exe file and append the code at last section and in overlay of file
					  >it do changes in registery
					  >it added value i.e :
					  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\Microsoft\NAPStat\traceIdentifier\Guid: "c26aee2c-2388-4633-8c3f-5fe295c81b4b"
					  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\Microsoft\NAPStat\traceIdentifier\BitNames: " Error Unusual Info Debug"
					  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\Microsoft\NAPStat\LogSessionName: "stdout	
--------------------------------------------------------------------------------------*/
int CPolyInfector::DetectVirus()
{

	int iRetStatus = VIRUS_NOT_FOUND;

	m_dwOverlaySize = m_pMaxPEFile->m_dwFileSize - (m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData);

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	int INFECTOR_BUFF_SIZE = 0x6;
	m_pbyBuff = new BYTE[INFECTOR_BUFF_SIZE];

	if(GetBuffer(m_dwAEPMapped,INFECTOR_BUFF_SIZE,INFECTOR_BUFF_SIZE))
	{
		BYTE byAEPbuff[] ={0x00, 0x11, 0x00, 0x00};
		for(int i=0;i<0x3;i++)
		{
			if(memcmp(&m_pbyBuff[i],&byAEPbuff,0x4)== 0)
			{
				if(m_pbyBuff)
				{
					delete []m_pbyBuff;
					m_pbyBuff = NULL;
				}
				INFECTOR_BUFF_SIZE = 0x30;
				m_pbyBuff = new BYTE[INFECTOR_BUFF_SIZE];
				if(GetBuffer(0x400,INFECTOR_BUFF_SIZE,INFECTOR_BUFF_SIZE))
				{
					DWORD dwLength = 0;
					t_disasm da = {0};
					int iInstructionNo = 0;

					DWORD dwOffset=0, dwKey =0, dwStart = 0, dwDecryptSize = 0;

					while(dwOffset<INFECTOR_BUFF_SIZE)
					{
						dwOffset=dwOffset+dwLength;
						if(dwOffset > INFECTOR_BUFF_SIZE)
						{
							break;
						}
						dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE); 

						if(dwLength == 0x1 && strstr(da.result,"NOP"))
						{
							continue;
						}
						if(iInstructionNo == 0 && (strstr(da.result,"LEA ") || strstr(da.result,"MOV ")))
						{
							if(dwLength == 0x7 && strstr(da.result,"LEA "))
							{
								dwStart = *(DWORD *)&m_pbyBuff[dwOffset + 3];
							}
							else if(dwLength == 0x5 && strstr(da.result,"MOV "))
							{
								dwStart = da.immconst;
							}

							iInstructionNo++;
							continue;
						}
						else if((dwLength == 0x6 || dwLength == 0x5) && iInstructionNo == 1 && (strstr(da.result,"MOV ECX") || strstr(da.result,"ADD ECX")))
						{
							dwDecryptSize = da.immconst;
							iInstructionNo++;
							continue;
						}
						else if(dwLength == 0x7 && iInstructionNo == 2 && strstr(da.result,"LEA EBP,[ESP+1000]"))
						{
							iInstructionNo++;
							continue;
						}
						else if(dwLength == 0x7 && iInstructionNo == 3 && strstr(da.result,"MOV DWORD PTR [EBP],"))
						{
							DWORD dwKey1 = 0,dwKey2 = 0,dwKey3 = 0,dwKey4 = 0,dwKey5 = 0,dwKey6 = 0,dwKey7 = 0,dwKeyF =0;
							BYTE bKey8 = 0;

							if(m_pbyBuff)
							{
								delete []m_pbyBuff;
								m_pbyBuff = NULL;
							}

							INFECTOR_BUFF_SIZE = dwDecryptSize;
							m_pbyBuff = new BYTE[INFECTOR_BUFF_SIZE];
							if(GetBuffer(0x400 + dwStart,INFECTOR_BUFF_SIZE,INFECTOR_BUFF_SIZE))
							{
								dwKey = da.immconst;
								for(DWORD dwCount = 0;dwCount < INFECTOR_BUFF_SIZE; dwCount++)
								{                                              

									dwKey1 = dwKey ^ 0x75BCD15;
									dwKey2 = dwKey1/0x1F31D;
									dwKey3 = dwKey2*0x1F31D;
									dwKey4 = dwKey1 - dwKey3;
									dwKey5 = dwKey4*0x41A7;
									dwKey6 = dwKey2 * 0xB14;
									dwKey7 = dwKey5 - dwKey6;
									if(dwKey5 < dwKey6)
									{
										dwKey7 = dwKey7 + 0x7FFFFFFF;
									}
									bKey8 = dwKey7 / 0x7FFFFF;
									m_pbyBuff[dwCount] ^= bKey8;
									dwKey =dwKey7 ^ 0x75BCD15; 
								}
								BYTE bySig[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21}; //Hello World!
								CMaxBMAlgo *pBMScan = new CMaxBMAlgo;
								if(pBMScan == NULL)
								{
									return iRetStatus;
								}
								if(pBMScan->AddPatetrn2Search(bySig, sizeof(bySig)))
								{
									DWORD dwStartOffset = 0;
									if(pBMScan->Search4Pattern(m_pbyBuff, INFECTOR_BUFF_SIZE,&dwStartOffset))
									{
										if(!dwStartOffset)
										{
											return iRetStatus;
										}
										//m_dwMoveDataSize = m_pMaxPEFile->m_dwFileSize - (0x1000 + m_dwOverlaySize); 

										memcpy(&m_bAEPPatched,&m_pbyBuff[dwStartOffset+(sizeof(bySig))+1],0x3C);
										m_infectorType = 0;
										_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,_T("Virus.W32.Infector.Gen"));      
										return VIRUS_FILE_REPAIR;
									}
									else
									{
										return iRetStatus;
									}
								}
							}
						}

					}
				}
			}

		}
	}

	//Comment Sneha

	/*
	if(m_wAEPSec == (m_wNoOfSections - 1)&&(m_pSectionHeader[m_wAEPSec].Characteristics & 0xC0000040) == 0xC0000040)  // sneha
	{


		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff =NULL;
		}

		const int INFECTOR_BUFF_SIZE = 0x30;
		m_pbyBuff = new BYTE[INFECTOR_BUFF_SIZE];

		DWORD  m_dwStratBuff =  m_dwAEPMapped;


		if(GetBuffer(m_dwStratBuff, INFECTOR_BUFF_SIZE, INFECTOR_BUFF_SIZE))
		{

			DWORD dwLength = 0;
			t_disasm da = {0};
			int iInstructionNo = 0;



			DWORD dwOffset=0;

			while(dwOffset<0x1A)
			{
				dwOffset=dwOffset+dwLength;

				dwLength = m_objMaxDisassem.Disasm((char *)&m_pbyBuff[dwOffset], MAX_INSTRUCTION_LEN, 0x400000, &da, DISASM_CODE); 


				if(dwLength == 0x5 && (iInstructionNo == 0x0 || iInstructionNo == 0x1 || iInstructionNo == 0x2) && strstr(da.result, "PUSH") || dwLength == 0x5 && (iInstructionNo == 0x0 || iInstructionNo == 0x1 ||iInstructionNo == 0x2)&& strstr(da.result, "MOV") || dwLength == 0x6 && iInstructionNo == 0x0 && strstr(da.result, "LEA EBP"))
				{

					dwDecrypStart = (da.immconst - m_dwAEPUnmapped) - m_dwImageBase;
					iInstructionNo++;
					continue;
				}
				else if(dwLength == 0x1 && (iInstructionNo == 0x1 || iInstructionNo == 0x2) && strstr(da.result,"POP ECX") || dwLength == 0x1 && (iInstructionNo == 0x1 || iInstructionNo == 0x2) && strstr(da.result,"POP EAX") || dwLength == 0x5 && iInstructionNo == 0x1 && strstr(da.result,"MOV"))
				{
					iInstructionNo++;
					continue;
				}
				else if(dwLength == 0x3 && (iInstructionNo == 0x2 || iInstructionNo == 0x3) && strstr(da.result,"ADD") || dwLength == 0x3 && (iInstructionNo == 0x3 || iInstructionNo == 0x4) && strstr(da.result,"XOR") || dwLength == 0x3 && (iInstructionNo == 0x2 || iInstructionNo == 0x3) && strstr(da.result,"SUB"))
				{  

					int i , j = dwDecrypStart + 0x5;
					bDecryptionKey = da.immconst; 


					if(strstr(da.result, "ADD"))
					{
						for(i=dwDecrypStart; i<j; i++)
						{
							m_pbyBuff[i] += bDecryptionKey;
						}
						m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[i-0x4];
					}

					else if(strstr(da.result, "SUB"))
					{
						for(i=dwDecrypStart; i<j; i++)
						{
							m_pbyBuff[i] -= bDecryptionKey;
						}
						m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[i-0x4];
					}

					else if(strstr(da.result, "XOR"))
					{
						for(i=dwDecrypStart; i<j; i++)
						{
							m_pbyBuff[i] ^= bDecryptionKey;
						}
						m_dwOriginalAEP = *(DWORD *)&m_pbyBuff[i-0x4];
					}


					m_dwOriginalAEP  = m_dwOriginalAEP - m_dwImageBase;


					iInstructionNo++;
					continue;
				}
				else if((dwLength == 0x5 || dwLength == 0x6)&& iInstructionNo == 0x4 && strstr(da.result, "SUB") || dwLength == 0x1 && iInstructionNo == 0x3 && strstr(da.result,"INC"))
				{
					iInstructionNo++;
					continue;
				}
				else if(dwLength == 0x6 && (iInstructionNo == 0x3 || iInstructionNo == 0x5) && strstr(da.result,"SUB") || dwLength == 0x1 && iInstructionNo == 0x4 && strstr(da.result,"INC"))
				{
					m_infectorType = 1;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.W32.Infector.Gen"));

					return VIRUS_FILE_REPAIR;

				}
			}
		}

	}
	*/


	if(m_wAEPSec == 0x2)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int SELFDEL_BUFF_SIZE = 0xA;
		m_pbyBuff = new BYTE[SELFDEL_BUFF_SIZE];

		if(GetBuffer(m_dwAEPMapped+0x3d1, SELFDEL_BUFF_SIZE, SELFDEL_BUFF_SIZE))
		{
			BYTE byROLCnt = 4;
			for(int i=0;i<0xA;i+=2)
			{
				*(WORD*)&m_pbyBuff[i] = *(WORD*)&m_pbyBuff[i] + 0x54;
				*(WORD*)&m_pbyBuff[i] = *(WORD*)&m_pbyBuff[i] ^ 0x19FC;
				*(WORD*)&m_pbyBuff[i] =  0x00 - (*(WORD*)&m_pbyBuff[i]); 

				*(WORD*)&m_pbyBuff[0x9] = *(WORD*)&m_pbyBuff[i];
				WORD wShiftLeft = *(WORD*)&m_pbyBuff[0x9] ;
				*(WORD*)&m_pbyBuff[i] = (LOBYTE(wShiftLeft)|HIBYTE(wShiftLeft));
				*(WORD*)&m_pbyBuff[0x9]=  _rotl(*(WORD*)&m_pbyBuff[0x9], 4);
				*(BYTE*)&m_pbyBuff[0x1] = *(BYTE*)&m_pbyBuff[0xA] + *(BYTE*)&m_pbyBuff[0x1];
				*(WORD*)&m_pbyBuff[i] =  ~(*(WORD*)&m_pbyBuff[i]);

			}

			//m_dwOrigAEP = m_pbyBuff[0x23C];

			TCHAR SELFDEL_CZ_Sig[] = {_T("DD7F8CAA1999152D08F71A81C2AB2DB9*15724EAB2D791A0D9181C2AB2D991F9D")};
			CSemiPolyDBScn polydbObj;

			polydbObj.LoadSigDBEx(SELFDEL_CZ_Sig, _T("Virus.Infector.Gen"), FALSE);


			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],SELFDEL_BUFF_SIZE , szVirusName)>=0)          
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}

	/*************************************//*/sagar*///******************************************************/

	if((m_wAEPSec == (m_wNoOfSections - 1)) && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
	{             
		m_dwOrigFileOffset= m_pMaxPEFile->m_dwFileSize-0x83e;
		const int Infector_BUFF_SIZE = 0x50;
		m_pbyBuff = new BYTE[Infector_BUFF_SIZE];
		if(!m_pbyBuff)
		{
			return iRetStatus;
		}
		if(CheckSigInBuffer(m_dwOrigFileOffset,Infector_BUFF_SIZE,_T("E91708000068656C6C6F2E65786500757365723332*00B1BEB3CCD0F2D2D1D0AFB4F8B2A1B6BE00643A5C6C6F76655C00643A5C0065")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("CPolyInfectorjp"));
			DWORD m_dwOriginalAEPoffset=(m_dwOrigFileOffset + 0X16);

			if(m_pMaxPEFile->ReadBuffer(&m_dwOriginalAEP,m_dwOriginalAEPoffset,0x4,0x4))
			{
				m_infectorType = 2;
				return VIRUS_FILE_REPAIR;

			}
			return VIRUS_FILE_DELETE;

		}
	}

	else if(m_wNoOfSections==0x001 &&  m_wAEPSec==0x000 && (m_dwAEPMapped == 0x0a1c) && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x0a00)
	{
		if(CheckSigInBuffer(0x200,0x50,_T("E91708000068656C6C6F2E65786500757365723332*657865001400000000000000643A5C7A745C00")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("CPolyInfectorjp"));

			return VIRUS_FILE_DELETE;

		}
	} 
	return iRetStatus;
} 
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade + Aniket + Virus Analysis Team
	Description		: Repair routine for different varients of Infector Family
--------------------------------------------------------------------------------------*/
int CPolyInfector::CleanVirus()
{
	int iRetStatus =0;
	if(m_infectorType == 0)  // alisha mam
	{
		if(m_pMaxPEFile->WriteBuffer(m_bAEPPatched,m_dwAEPMapped,0x3C,0x3C))
		{
			if(m_pMaxPEFile->FillWithZeros(0x400,0xC00))
			{
				if(m_dwOverlaySize)
					if(!m_pMaxPEFile->TruncateFile((m_pSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData),false))
					{
						iRetStatus = REPAIR_FAILED;
					}

					iRetStatus = REPAIR_SUCCESS;
			}

		}
	}
	else if(m_infectorType == 1)    // sneha 
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped ,TRUE))
			{
				return REPAIR_SUCCESS;
			}

		}
	}

	else if(m_infectorType == 2)  // sagar new added 
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
		{
			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - 0x83E))
			{
				DWORD d_wOldsizeofimage=0x00;
				DWORD d_wNewsizeofimage=0x00;
				m_pMaxPEFile->ReadBuffer(&d_wOldsizeofimage,m_pMaxPEFile->m_stPEOffsets.SizeOfImage,0x4,0x4);
				d_wNewsizeofimage = d_wOldsizeofimage-0x1000;
				DWORD virtualsize = m_pMaxPEFile->m_stPEHeader.DataDirectory[2].Size;
				DWORD m_dwGotorsrc=m_wAEPSec*0x28;
				PE_OFFSETS m_stPEOffsets=m_pMaxPEFile->m_stPEOffsets;
				DWORD d_wmagic= m_stPEOffsets.Magic;
				DWORD m_dwpeoffset=(d_wmagic-0x18);
				DWORD d_wrsrcsecoffset=(m_dwpeoffset+0xf8)+m_dwGotorsrc;
				m_pMaxPEFile->WriteBuffer(&virtualsize,(d_wrsrcsecoffset+0x8), 4, 4);
				DWORD m_dwcharecristics=0x40000040;
				m_pMaxPEFile->WriteBuffer(&m_dwcharecristics,(d_wrsrcsecoffset+0x24), 4, 4);
				if(m_pMaxPEFile->CalculateImageSize())
				{
					if(m_pMaxPEFile->FillWithZeros(0xA,0x04))
					{
						if(m_pMaxPEFile->CalculateLastSectionProperties())
						{
							m_pMaxPEFile->WriteBuffer(&d_wNewsizeofimage, m_pMaxPEFile->m_stPEOffsets.SizeOfImage, 4, 4);
							return REPAIR_SUCCESS;
						}
					}
				}
			}
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyAgent
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyAgent:: CPolyAgent(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwStartHeader = 0x00;
	m_dwStratBoundImport = 0x00;
	m_wNosec = 0x00;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyAgent
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyAgent::~ CPolyAgent(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of Agent Family
--------------------------------------------------------------------------------------*/
int CPolyAgent::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_wAEPSec >= 0x2 && m_wAEPSec <= 0x9)&&(m_wNoOfSections >= 0x6 && m_wNoOfSections <= 0xD) && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5060))//added
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff =NULL;
		}

		const int AGENT_BUFF_SIZE = 0x78;
		m_pbyBuff = new BYTE[AGENT_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData + 0x5EE , AGENT_BUFF_SIZE, AGENT_BUFF_SIZE))
		{
			TCHAR			AGENT_CZ_Sig[] = {_T("81E700F0000081FF00300000*8B7C24108B4C290C25FF0F0000*8B4C24108938668B0625FF0F0000*8B44243883C6024889442438")};
			CSemiPolyDBScn	polydbObj;
			TCHAR			szVirusName[MAX_PATH] = {0};
			
			polydbObj.LoadSigDBEx(AGENT_CZ_Sig, _T("Virus.Agent.FN"), FALSE);
			if(polydbObj.ScanBuffer(&m_pbyBuff[0], AGENT_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{ 
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					m_dwOrigHeader  = m_pSectionHeader[m_wAEPSec + 2].PointerToRawData + 0x960;

					m_dwStartTruncate = m_pSectionHeader[m_wAEPSec].PointerToRawData;

					if(!m_pMaxPEFile->ReadBuffer(&m_dwStartHeader, 0X3C, 2 , 2))
					{
						return VIRUS_FILE_DELETE;
					}
					if(!m_pMaxPEFile->ReadBuffer(&m_wNosec, m_dwOrigHeader + 0x06, 2 , 2))
					{
						return VIRUS_FILE_DELETE;
					}
					if(memcmp(m_pSectionHeader[m_wNosec -1].Name, ".text", 5) == 0)
					{
						return VIRUS_FILE_DELETE;
					}
					return VIRUS_FILE_REPAIR;

				}
			}
		}
	}

	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Agent Family
--------------------------------------------------------------------------------------*/
int CPolyAgent::CleanVirus()
{
	int	iRetStatus = REPAIR_FAILED;

	if(m_pMaxPEFile->CopyData(m_dwOrigHeader, m_dwStartHeader, 0XF7))
	{ 
		if(m_pMaxPEFile->ReadBuffer(&m_dwStratBoundImport, m_dwStartHeader + 0xD0, 4 , 4))
		{
			if(m_dwStratBoundImport == 0x00)
			{
				if(m_pMaxPEFile->ForceTruncate(m_dwStartTruncate));
				{
					return REPAIR_SUCCESS;
				}
			}
			else 
			{   
				if(m_pMaxPEFile->FillWithZeros(m_dwStratBoundImport, 0xA0));
				{
					if(m_pMaxPEFile->ForceTruncate(m_dwStartTruncate));
			  {
				  return REPAIR_SUCCESS;
			  }
				}
		 }
		}
	}
	return iRetStatus;
}

/******************************************************************************************************/

/******************************************************************************************************
Analyst     : Gaurav Pakhale
Type:       : Virus
Name        : Virus.Win32.HLLP.DeTroie
******************************************************************************************************/
/*-------------------------------------------------------------------------------------
	Function		: CPolyVirusHLLPDeTroie
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVirusHLLPDeTroie::CPolyVirusHLLPDeTroie(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{

}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVirusHLLPDeTroie
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyVirusHLLPDeTroie::~CPolyVirusHLLPDeTroie(void)
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
	Author			: Tushar Kadam + Gaurav Phalake + Virus Analysis Team
	Description		: Detection routine for different varients of HLLP.DeTroie Family
--------------------------------------------------------------------------------------*/
int CPolyVirusHLLPDeTroie::DetectVirus()
{

	int iRetStatus = 0;


	if( m_wNoOfSections == 0x0009 && m_dwAEPMapped == 0x5A180 && m_wAEPSec == 0x0000 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5A000 && m_pMaxPEFile ->m_dwFileSize >= 0x7AECF )
	{
		TCHAR HLLPDTRE_CZ_Sig[] = {_T("54536372757465446F73736965728D400058*4400070E54536372757465446F7373696572F01344006CC940*536372757465*536F7573446F73736965728013440040")};
		if (CheckSigInBuffer(0x041443,0x100,HLLPDTRE_CZ_Sig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,  _T("Virus.Win32.HLLP.DeTroie"));
			if(m_pMaxPEFile ->m_dwFileSize >= 0x7AECF && m_pMaxPEFile ->m_dwFileSize <= 0x80AF2 )
			{
				return VIRUS_FILE_DELETE;

			}
			else
			{
				return VIRUS_FILE_REPAIR;
			}
		}
		/*

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		int HLLPDTRE_BUFF_SIZE = 0x100;
		m_pbyBuff = new BYTE[HLLPDTRE_BUFF_SIZE];

		if(GetBuffer(0x041443 ,HLLPDTRE_BUFF_SIZE,HLLPDTRE_BUFF_SIZE))
		{
			


			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(HLLPDTRE_CZ_Sig, _T("Virus.Win32.HLLP.DeTroie"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], HLLPDTRE_BUFF_SIZE , szVirusName)<=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{ 
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					if(m_pMaxPEFile ->m_dwFileSize >= 0x7AECF && m_pMaxPEFile ->m_dwFileSize <= 0x80AF2 )
					{
						return VIRUS_FILE_DELETE;

					}
					else
					{
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}
		*/
	}

	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Gaurav Phalake + Virus Analysis Team
	Description		: Repair routine for different varients of HLLP.DeTroie Family
--------------------------------------------------------------------------------------*/
int CPolyVirusHLLPDeTroie::CleanVirus()
{	

	m_dwOrigFilseSize = m_pMaxPEFile->m_dwFileSize - 0x7B1E4;

	if(m_pMaxPEFile->CopyData(m_pMaxPEFile->m_dwFileSize - m_dwOrigFilseSize, 0x00, m_dwOrigFilseSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFilseSize - 0x15))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;

}

/*-------------------------------------------------------------------------------------
	Function		: CPolyInfectorGen
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyInfectorGen::CPolyInfectorGen(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOriginalAEP = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyInfectorGen
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyInfectorGen::~CPolyInfectorGen(void)
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
	Author			: Tushar Kadam + Gaurav Phalake + Virus Analysis Team
	Description		: Detection routine for different varients of Infector Family
--------------------------------------------------------------------------------------*/
int CPolyInfectorGen::DetectVirus()
{

	int iRetStatus = 0;


	if(m_dwAEPUnmapped == ( m_pSectionHeader[m_wAEPSec].Misc.VirtualSize + 0x0100A ) )
	{
		TCHAR bVirusInfectorGenSig[] = {_T("CC834202000083F8FF7505E96CFF771D807C010000*FFB342020000FF93F4000000*6A00FF0B05D877008B")};

		if(CheckSigInBuffer(m_dwAEPMapped,0x64,bVirusInfectorGenSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,  _T("Virus_Infector.Gen"));
			
			DWORD	dwReadOFF = m_dwAEPUnmapped - 0xBBB;
			DWORD	dwReadOFFNew = 0x0;

			if(!m_pMaxPEFile->ReadBuffer(&dwReadOFFNew,dwReadOFF,0x4,0x4))
			{
				return VIRUS_FILE_DELETE;
			}
			m_dwOriginalAEP = dwReadOFFNew + m_pSectionHeader[m_wAEPSec].Misc.VirtualSize + 0x1053;


			return VIRUS_FILE_REPAIR;
		}

		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}


		int INFECTOR_BUFF_SIZE = 0x64;
		m_pbyBuff = new BYTE[INFECTOR_BUFF_SIZE];

		if(GetBuffer( m_dwAEPMapped ,INFECTOR_BUFF_SIZE,INFECTOR_BUFF_SIZE))
		{
			


			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(INFECTOR_CZ_Sig, _T("Virus Infector.Gen"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], INFECTOR_BUFF_SIZE , szVirusName)<=0)	
			{
				if(_tcslen(szVirusName) >= 0)
				{ 
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					DWORD dwReadOFF = m_dwAEPUnmapped - 0xBBB;

					DWORD dwReadOFF1 = 0x0;

					if(!m_pMaxPEFile->ReadBuffer(&dwReadOFF1,dwReadOFF,0x4,0x4))
					{
						return VIRUS_FILE_DELETE;
					}
					m_dwOriginalAEP = dwReadOFF1 + m_pSectionHeader[m_wAEPSec].Misc.VirtualSize + 0x1053;


					return VIRUS_FILE_REPAIR;
				}
			}
		}
		*/
	}

	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Gaurav Phalake + Virus Analysis Team
	Description		: Repair routine for different varients of Infector Family
--------------------------------------------------------------------------------------*/
int CPolyInfectorGen::CleanVirus()
{	
	if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
	{
		if(m_pMaxPEFile->FillWithZeros(m_dwAEPMapped, 0x050))

			return REPAIR_SUCCESS;

	}
	return REPAIR_FAILED;
}



/*-------------------------------------------------------------------------------------
	Function		: CPolyLAMERFG
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyLAMERFG::CPolyLAMERFG(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	DWORD m_dwOrigFilseSizeOff =0;
	DWORD m_dwOrigFilseSize = 0;

}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyLAMERFG
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyLAMERFG::~CPolyLAMERFG(void)
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
	Author			: Tushar Kadam + Gaurav Pakhale + Virus Analysis Team
	Description		: Detection routine for different varients of Lmaer.fg Family
					  >It changes in registry.
					>Nodifies all excutable file with malicious code.
					>Append original file at the end of file.
					>It can do multilevel infection.
					>It keeps the path at which it infects and the size of original file name before that file.
					>Each level of infection is seperated with string "BagarBubba.."
					>It starts infects from root drive and prepend all data in excutable files.
					>Data added in a file is greater than 25MB. So gradually it slows system performance.
					>It we are running virus file for long time, it increases memory and sometimes crashes due to memory onerflow.	
--------------------------------------------------------------------------------------*/
int CPolyLAMERFG::DetectVirus(void)
{
	int		iRetStatus = VIRUS_NOT_FOUND;
	bool	bCQCheckMatched = false;
	DWORD	dwCheckVisua = 0x00;

	if(m_dwAEPMapped == 0x1000 && m_wNoOfSections == 0x5 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x400)
	{
		DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].Size;
		if(dwOverlayStart == 0x3400)
		{
			if(m_pMaxPEFile->ReadBuffer(&dwCheckVisua,dwOverlayStart,0x04,0x04))
			{
				if(dwCheckVisua != 0x75736976)
				{
					bCQCheckMatched = true;
				}
			}
		}
	}
	if (bCQCheckMatched == true)
	{
		if(CheckSigInBuffer(m_pMaxPEFile->m_stSectionHeader[0x0].PointerToRawData,0x500,_T("5331C0505050508B5424188D0C24E8360F00006825504000FF74240468FFFFFFFFE8DB*52508F4424088F442408833C24000F8407020000FF742410FF7424108304240183542404008F4424*542404008F4424108F442410FF742410FF7424105B5F3B7C24087C0C7F063B5C24")))
		{
			DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;

			DWORD dwCheckVisua = 0x0;
			for(int iIndex = m_pMaxPEFile->m_dwFileSize;iIndex >= dwOverlayStart; iIndex = iIndex - 0x512)
			{
				if(CheckSigInBuffer(iIndex - 0x1000,0x1000,_T("766973*7561")))
				{
					for(int ii = 0x0;ii<1000;ii++)
					{
						if(m_pMaxPEFile->ReadBuffer(&dwCheckVisua,iIndex + ii - 0x1000,0x04,0x04))
						{
							if(dwCheckVisua == 0x75736976)
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Lamer.CQ"));
								m_dwOrigFilseSizeOff = iIndex + ii - 0x1000 + 0x05;
								m_dwOrigFilseSize = m_pMaxPEFile->m_dwFileSize - m_dwOrigFilseSizeOff;
								return VIRUS_FILE_REPAIR;
							}
						}
					}
				}
			}
		}
	}
	/* --Comment Sagar
	if(m_dwAEPMapped == 0x2A801 && m_wNoOfSections == 0xA && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x3000)
	{
		if (CheckSigInBuffer(0x400,0x190,_T("344F3D3F724E4E4E139C84E4F4020111E1E9080921150872449E8487AA072481*793CB56F7CB16F5F4D4122FE5BF3C4164F74898BF5C3288D222A88ED2C7B32")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Lamer.CB"));
			if(m_pMaxPEFile->ReadBuffer(&m_dwOrigFilseSizeOff,m_pMaxPEFile->m_dwFileSize - 0x110, 0x4, 0x4))
			{
				m_dwOrigFilseSize = m_pMaxPEFile->m_dwFileSize - m_dwOrigFilseSizeOff - 0x218;
				return VIRUS_FILE_REPAIR;
			}
		}
	}
	*/
	//Added By Sagar
	if((m_dwAEPMapped == 0x2A801 || m_dwAEPMapped == 0x5cf80 || m_dwAEPMapped == 0x2AA01) && m_wNoOfSections >= 0xa && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x3000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5C000))
	{
		DWORD m_dwsignadr=0x400;
		if(m_dwAEPMapped == 0x2AA01)
		{
			m_dwsignadr=0x600;
		}
		if (CheckSigInBuffer(m_dwsignadr,0x190,_T("344F3D3F724E4E4E139C84E4F4020111E1E9080921150872449E8487AA072481*793CB56F7CB16F5F4D4122FE5BF3C4164F74898BF5C3288D222A88ED2C7B32")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Lamer.CB"));
			if(m_pMaxPEFile->ReadBuffer(&m_dwOrigFilseSizeOff,m_pMaxPEFile->m_dwFileSize - 0x110, 0x4, 0x4))
			{
				m_dwOrigFilseSize = m_pMaxPEFile->m_dwFileSize - m_dwOrigFilseSizeOff - 0x218;
				if(m_dwOrigFilseSize<=m_pMaxPEFile->m_dwFileSize)
				{
					return VIRUS_FILE_REPAIR;
				}
				else
					return VIRUS_FILE_DELETE;
			}
		}
	}

	if(m_dwAEPMapped == 0x24C0 && m_wNoOfSections == 0x3 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2400)
	{
		if (CheckSigInBuffer(m_pMaxPEFile->m_dwFileSize - 0x130,0x130,_T("EFBEEDFE00000000*42616761724275626261")))
		{
			DWORD dwTrickOff = 0x0;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Lamer.FG"));
			if(m_pMaxPEFile->ReadBuffer(&dwTrickOff,m_pMaxPEFile->m_dwFileSize - 0x11A, 0x4, 0x4))
			{
				if(m_pMaxPEFile->ReadBuffer(&m_dwOrigFilseSize,dwTrickOff + 0x08, 0x4, 0x4))
				{
					m_dwOrigFilseSizeOff = dwTrickOff + 0x118;
				}
				return VIRUS_FILE_REPAIR;	
			}
		}
	}

	return iRetStatus;

}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Gaurav Phalake + Virus Analysis Team
	Description		: Repair routine for different varients of Lamer.FG Family
--------------------------------------------------------------------------------------*/
int CPolyLAMERFG::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFilseSizeOff, 0x00, m_dwOrigFilseSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFilseSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyHOROPED
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHOROPED::CPolyHOROPED(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   //CPolyDeemo
{
	DWORD m_dwReplaceOffset = 0;
	DWORD m_dwOrigFileSize = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHOROPED
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHOROPED::~CPolyHOROPED(void)
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
	Author			: Tushar Kadam + Swapnil Sanghai + Virus Analysis Team
	Description		: Detection routine for different varients of Horope.d Family
					  *>RT_Main Structure
					  *>Project Structure
					  *>Dialog Structure
					  *>Extern Struction
					  *>Project Info
					  *>Code Start
					  *>Code End 
--------------------------------------------------------------------------------------*/
int CPolyHOROPED::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x3 || m_wNoOfSections == 0x5 && m_dwAEPMapped == 0x1134 || m_dwAEPMapped == 0xD3B0 &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xA000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x45000)
	{
		TCHAR  pbyHOROPEDSig[] = {_T("2500104000FF25641040006884164000*2419400000F03000*2C1540002C1540004011400078*A0A44000B0A44000B00B000000B040000A1140*52006F006E0074006F006B00420072006F0077004300300033")};

		if(CheckSigInBuffer(0x1129,0x900,pbyHOROPEDSig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,  _T("Virus.Horope.D"));

			m_dwReplaceOffset  = m_pSectionHeader[m_wAEPSec].PointerToRawData + 0x2800;
			m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - (m_dwReplaceOffset+4);
			return VIRUS_FILE_REPAIR;
		}
		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int HOROPED_BUFF_SIZE = 0x900;
		m_pbyBuff = new BYTE[HOROPED_BUFF_SIZE];

		if(GetBuffer(0x1129, HOROPED_BUFF_SIZE, HOROPED_BUFF_SIZE))

		{

			TCHAR  HOROPED_CZ_Sig[] = {_T("2500104000FF25641040006884164000*2419400000F03000*2C1540002C1540004011400078*A0A44000B0A44000B00B000000B040000A1140*52006F006E0074006F006B00420072006F0077004300300033")};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(HOROPED_CZ_Sig, _T("Virus.Horope.d"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], HOROPED_BUFF_SIZE , szVirusName)>=0)	
			{

				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					m_dwReplaceOffset  = m_pSectionHeader[m_wAEPSec].PointerToRawData + 0x2800;
					m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - (m_dwReplaceOffset+4);
					return VIRUS_FILE_REPAIR;
				}
			}
		}
		*/
	}

	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Swapnil Sanghai + Virus Analysis Team
	Description		: Repair routine for different varients of Horope.d Family
--------------------------------------------------------------------------------------*/
int CPolyHOROPED::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}




/*-------------------------------------------------------------------------------------
	Function		: CPolyHOROPEI
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHOROPEI::CPolyHOROPEI(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   //CPolyDeemo
{
	DWORD m_dwReplaceOffset = 0;
	DWORD m_dwOrigFileSize = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHOROPEI
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHOROPEI::~CPolyHOROPEI(void)
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
	Author			: Tushar Kadam + Swapnil Sanghai + Virus Analysis Team
	Description		: Detection routine for different varients of Dundun Family
					  *>Company Name
					  *>Product Name
					  *>Internal Name
					  *>Orignal File Name

					  >all files are visual Basic files.
					  >it make changes in registery.
					  >it alter the registry entries.
					  >Modify files from Current directory.
--------------------------------------------------------------------------------------*/
int CPolyHOROPEI::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	
	if(m_wNoOfSections == 0x3 || m_wNoOfSections == 0x5 && m_dwAEPMapped == 0x1134 || m_dwAEPMapped == 0xD3B0 &&  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xA000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x45000)
	{

		TCHAR  pbyHOROPEISig[] = {_T("440075006E00670065006F006E00200049006E00630000*52006F006E0074006F006B00420072006F00770042003000320000*52006F006E0074006F006B00420072006F00770043003000330000*52006F006E0074006F006B00420072006F0077004300300033002E0065007800650000")};

		if(CheckSigInBuffer(0xB1EC,0x140,pbyHOROPEISig))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME,  _T("Virus.Horope.I"));

			m_dwReplaceOffset  = 0xC000;
			m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - (m_dwReplaceOffset+4);

			return VIRUS_FILE_REPAIR;
		}
		/*
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int HOROPEI_BUFF_SIZE = 0x140;
		m_pbyBuff = new BYTE[HOROPEI_BUFF_SIZE];

		if(GetBuffer(0xB1EC, HOROPEI_BUFF_SIZE, HOROPEI_BUFF_SIZE))

		{
			TCHAR  HOROPEI_CZ_Sig[] = {_T("440075006E00670065006F006E00200049006E00630000*52006F006E0074006F006B00420072006F00770042003000320000*52006F006E0074006F006B00420072006F00770043003000330000*52006F006E0074006F006B00420072006F0077004300300033002E0065007800650000")};
			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(HOROPEI_CZ_Sig, _T("Virus.Horope.I"), FALSE);
			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], HOROPEI_BUFF_SIZE , szVirusName)>=0)	
			{

				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);
					 m_dwReplaceOffset  = 0xC000;
					 m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - (m_dwReplaceOffset+4);
					return VIRUS_FILE_REPAIR;

				}
			}
		}
		*/
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Swapnil Sanghai + Virus Analysis Team
	Description		: Repair routine for different varients of Horope.I Family
--------------------------------------------------------------------------------------*/
int CPolyHOROPEI::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}


/*-------------------------------------------------------------------------------------
	Function		: CPolyIpamor
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyIpamor::CPolyIpamor(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyIpamor
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyIpamor::~CPolyIpamor(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of Daws.dxlz Family
					   >this file drop one file in c:/WINDOWS i.e "MSWDM.EXE"
					   >also added entry of this file in registery in:
					   >HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WDM: 
					   >HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\WDM
					   >it also infected to the .exe file
					  >also it modified its own file
--------------------------------------------------------------------------------------*/
int CPolyIpamor::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x0	&& (m_dwAEPUnmapped & 0xF003)== 0x4003 && 
		((m_wNoOfSections == 0x1 && (m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x14000 || m_pSectionHeader[m_wAEPSec].Misc.VirtualSize == 0x13000)) ||
		((m_wNoOfSections == 0x4 || m_wNoOfSections == 0x6 || m_wNoOfSections == 0x5) && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xA000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x9794))))
	{

		m_dwReplaceOffset=0; m_dwTruncateSize=0;


		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int IPAMOR_BUFF_SIZE = 0x500;
		m_pbyBuff = new BYTE[IPAMOR_BUFF_SIZE];
		DWORD dwReadOff = 0xD1A0;
		DWORD dwReadSize = 0xA0;
		if(m_wNoOfSections > 0x1)
		{
			dwReadOff = m_pSectionHeader[m_wAEPSec + 0x2].PointerToRawData + 0x150;
			dwReadSize = IPAMOR_BUFF_SIZE;
		}

		if(!GetBuffer(dwReadOff,dwReadSize,dwReadSize))
		{
			return iRetStatus;
		}

		TCHAR szVirusName[MAX_PATH] = { 0 };
		
		TCHAR szIpamor[] = _T("494558504C4F52452E455845000000004E4554455945532E455845004D534445562E455845*495041524D4F520054524F4A414E*4E4F52544F4E00004649524557414C4C");
		
		CSemiPolyDBScn polydbObj;
		polydbObj.LoadSigDBEx(szIpamor, _T("Virus.Ipamor.Gen"), FALSE);

		int	iRetValue = 0;

		iRetValue = polydbObj.ScanBuffer(&m_pbyBuff[0], m_dwNoOfBytes, szVirusName);

		if(iRetValue >= 0)
		{ 
			if(_tcslen(szVirusName) > 0)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

				if(m_pMaxPEFile->ReadBuffer(&m_dwTruncateSize, m_pMaxPEFile->m_dwFileSize - 0x12, 4, 4))
				{  
					if(m_pMaxPEFile->ReadBuffer(&m_dwReplaceOffset, m_pMaxPEFile->m_dwFileSize - 0xA, 4, 4))
					{
				
						WORD	byCheckMz = 0x0;  //added

						if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwReplaceOffset,0x2,0x2))
						{
							return VIRUS_FILE_DELETE;
						}
						else if(byCheckMz == 0x5A4D)
						{
							return VIRUS_FILE_REPAIR;
						}
						else
						{
							return VIRUS_FILE_DELETE;
						}

					}
					if(m_dwReplaceOffset > m_pMaxPEFile->m_dwFileSize || m_dwReplaceOffset == 0x00 || m_dwTruncateSize == 0x00 || m_dwTruncateSize > m_pMaxPEFile->m_dwFileSize)//added
					{	
						return VIRUS_FILE_DELETE;
					}
				}
				return VIRUS_FILE_REPAIR;
			}
		}
	}

	return VIRUS_NOT_FOUND;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Repair routine for different varients of Ipamor Family
--------------------------------------------------------------------------------------*/
int CPolyIpamor::CleanVirus(void)
{	
	int iRetStatus = REPAIR_FAILED;
	if(m_wNoOfSections == 0x6 || m_wNoOfSections == 0x5)
	{
		m_dwReplaceOffset = (m_pMaxPEFile->m_dwFileSize - 0x12) - m_dwTruncateSize;

	}
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0, m_dwTruncateSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwTruncateSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyGodogA
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyGodogA::CPolyGodogA(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{

	m_dwOriginalAEP = 0;
	m_dwDecryptionKey = 0;
	m_dwFillZeroOff = 0;
	m_dwStartHeader = 0;
	m_dwStartHeader1 = 0;
	m_dwStartHeader2 = 0;
	m_GodogType = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyGodogA
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyGodogA::~CPolyGodogA(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of Godog.a Family
					  >it is a appender virus
					  >it infect .exe file and append the code at last section 
					  >it do changes in registery	
--------------------------------------------------------------------------------------*/
int CPolyGodogA::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if ((m_wAEPSec = m_wNoOfSections - 1) && (m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000060) == 0xE0000060)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		int GODOG_BUFF_SIZE = 0x200;
		m_pbyBuff = new BYTE[GODOG_BUFF_SIZE];

		if(!m_pMaxPEFile->ReadBuffer(&m_dwDecryptionKey, m_dwAEPMapped + 0x5 ,0x4, 0x4))
		{
			return VIRUS_NOT_FOUND;
		}

		if(GetBuffer(m_dwAEPMapped + 0x600, GODOG_BUFF_SIZE, GODOG_BUFF_SIZE))
		{
			for(int i=0; i<0x200; i+=4)
			{
				*(DWORD*)&m_pbyBuff[i] = *(DWORD*)&m_pbyBuff[i] - 0x37687;
				*(DWORD*)&m_pbyBuff[i] = ~(*(DWORD*)&m_pbyBuff[i]);
				*(DWORD*)&m_pbyBuff[i] =  _lrotl(*((DWORD *)&m_pbyBuff[i]), 0x25);
				*(DWORD*)&m_pbyBuff[i] =  0x00 - (*(DWORD*)&m_pbyBuff[i]);
				*(DWORD*)&m_pbyBuff[i] = *(DWORD*)&m_pbyBuff[i]^m_dwDecryptionKey;

			}
			m_dwOriginalAEP = *(DWORD*)&m_pbyBuff[0x1D4];

			TCHAR GODOG_CZ_Sig[] = {_T("57696E33322E48616E6E656C6F726520*204B6F686C206F662047686F7374446F67")};
			//Win32.Hannelore*Kohl of GhostDog 

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(GODOG_CZ_Sig, _T("Virus.Win32.Godog.a"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], GODOG_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{ 
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					if(!m_pMaxPEFile->ReadBuffer(&m_dwStartHeader, 0X3C, 2 , 2))
					{
						return VIRUS_FILE_DELETE;
					}
					m_dwFillZeroOff = m_dwStartHeader + 0x4C;

					return VIRUS_FILE_REPAIR;

				}
			}
		}
	}
	
	//Added on 19 Jul 2018 : Sneha (No Decryption loop)
	if ((m_wAEPSec = m_wNoOfSections - 1) && (m_pSectionHeader[m_wAEPSec].Characteristics & 0xE0000060) == 0xE0000060)
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_dwOriginalAEP, m_dwAEPMapped + 0x40D ,0x4, 0x4))
		{
			return VIRUS_NOT_FOUND;
		}
		if(!m_pMaxPEFile->ReadBuffer(&m_dwStartHeader, 0X3C, 2 , 2))
		{
			return VIRUS_NOT_FOUND;
		}
		
		m_dwFillZeroOff = m_dwStartHeader + 0x4C;

		if(m_pMaxPEFile->ReadBuffer(&m_dwStartHeader1, m_dwStartHeader + 0x16C, 4 , 4))
		{
			m_dwStartHeader2 = m_dwStartHeader1 - 0xA0000020;
			
		}

		if (CheckSigInBuffer(m_dwAEPMapped,0x0200,_T("E8000000008B042483C4042D05104000*57696E33322E47686F7374446F67")))
		{

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Godog"));
			m_GodogType = 1;
			return VIRUS_FILE_REPAIR;
		}
	}

	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Repair routine for different varients of Godog.A Family
--------------------------------------------------------------------------------------*/
int CPolyGodogA::CleanVirus()
{
	int	iRetStatus = REPAIR_FAILED;
	if(m_GodogType = 0)
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped ,TRUE))
			{
				if(m_pMaxPEFile->FillWithZeros(m_dwFillZeroOff, 0x4))
				{
					return REPAIR_SUCCESS;
				}

			}

		}
	}
	if(m_GodogType = 1)//added
	{
		if(m_pMaxPEFile->WriteAEP(m_dwOriginalAEP))
		{
			if(m_pMaxPEFile->TruncateFile(m_dwAEPMapped))
			{
              
				if(m_pMaxPEFile->FillWithZeros(m_dwFillZeroOff, 0x4))
				{
					if(m_pMaxPEFile->WriteBuffer(&m_dwStartHeader2, m_dwStartHeader + 0x16C , 4, 4))
					{
					   return REPAIR_SUCCESS;
					}
				}


			}

		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyVBGN
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVBGN::CPolyVBGN(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwReplaceOffset = 0;
	m_dwOrigFileSize = 0;
	m_dwOverlayStart = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVBGN
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyVBGN::~CPolyVBGN(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of VB.gn Family
					   >it is a prepender virus
					   >it infect .exe file 
					   >it do changes in registery
--------------------------------------------------------------------------------------*/
int CPolyVBGN::DetectVirus()
{

	int iRetStatus = 0;

	if(m_pMaxPEFile->m_bIsVBFile && m_wAEPSec == 0 && m_wNoOfSections == 0x3 && m_dwAEPMapped == 0x1710 && m_dwAEPMapped == m_dwAEPUnmapped && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x7000 && m_pMaxPEFile->m_stPEHeader.CheckSum == 0x17CE7) 
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int VB_BUFF_SIZE = 0x64;
		m_pbyBuff = new BYTE[VB_BUFF_SIZE];

		if(GetBuffer(m_pSectionHeader[0].PointerToRawData + 0x1E64, VB_BUFF_SIZE, VB_BUFF_SIZE))
		{
			TCHAR VB_CZ_Sig[] = {_T("CC2E400000F1340000FFFFFF*E42D4000D42D40001C17400078*706A7442696E646572")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(VB_CZ_Sig, _T("Virus.Win32.VB.gn"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],VB_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					m_dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;

					m_dwReplaceOffset = m_dwOverlayStart - 0x01;  

					m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - m_dwReplaceOffset;

					WORD	byCheckMz = 0x0; 

					if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwReplaceOffset,0x2,0x2))
					{
						return VIRUS_FILE_DELETE;
					}
					else if(byCheckMz == 0x5A4D)
					{
						return VIRUS_FILE_REPAIR;
					}
					else
					{
						return VIRUS_FILE_DELETE;
					}
				}
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of VB.gn Family
--------------------------------------------------------------------------------------*/
int CPolyVBGN::CleanVirus()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyYakA
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyYakA::CPolyYakA(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{

	m_dwReplaceOffset = 0;
	m_dwOrigFileSize = 0;
	m_dwOverlayStart = 0;

}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyYakA
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyYakA::~CPolyYakA(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of Yak.A Family
					  >it is a prepender virus
					  >it infect .exe file 
					  >it do changes in registery
--------------------------------------------------------------------------------------*/
int CPolyYakA::DetectVirus()
{
	int iRetStatus = 0;

	if((m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
	{
		return iRetStatus;
	}
	if(m_wAEPSec == 0x0 && m_wNoOfSections == 0x5 && m_dwAEPMapped == 0x0400 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0X8400)
	{

		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		int YAK_BUFF_SIZE = 0x30E;
		m_pbyBuff = new BYTE[YAK_BUFF_SIZE];

		if(GetBuffer(0x3CD8, YAK_BUFF_SIZE, YAK_BUFF_SIZE))
		{
			TCHAR YAK_CZ_Sig[] = {_T("536F6674776172655C50525C4745445A4143*4B61792042792050736575646F726F6F742F4745445A4143*506F72205733322F4B6179*457374617320696E6665637461646F3F")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(YAK_CZ_Sig, _T("Virus.Win32.Yak.A"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0], YAK_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{ 
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					m_dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;

					m_dwReplaceOffset = m_dwOverlayStart + 0xBBD6;   

					m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize - m_dwReplaceOffset;

					WORD	byCheckMz = 0x0; 
					if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwReplaceOffset,0x2,0x2))
					{
						return VIRUS_FILE_DELETE;
					}
					else if(byCheckMz == 0x5A4D)
					{
						return VIRUS_FILE_REPAIR;
					}
					else
					{
						return VIRUS_FILE_DELETE;
					}
				}
			}
		}

	}

	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Repair routine for different varients of Yak.A Family
--------------------------------------------------------------------------------------*/
int CPolyYakA::CleanVirus()
{
	int	iRetStatus = VIRUS_NOT_FOUND;

	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyTrojanZusy256811
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyTrojanZusy256811::CPolyTrojanZusy256811(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	DWORD m_dwOrigFileOff =0;
	DWORD m_dwOrigFileSize = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: ~CPolyTrojanZusy256811
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyTrojanZusy256811::~CPolyTrojanZusy256811(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of zusy.256811 Family
--------------------------------------------------------------------------------------*/
int CPolyTrojanZusy256811::DetectVirus()
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x06 && (memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".NewSec", 9) == 0) && m_dwAEPMapped == 0x01000 && m_pSectionHeader[0x0].PointerToRawData == 0x1000 && m_pSectionHeader[0x0].SizeOfRawData == 0x0731 )
	{

		if (CheckSigInBuffer( 0x05000 ,0x070,_T("496E666F726D6174696F6E002E65786500*2F00633A002A2E2A00436F756C646E2774206F70656E207468652066696C6521*433A2F6578702F007669737561002E2E00205B46696C655D*00205B5375622D4469725D20")))  //off:500d sign : Information..exe.../.c:.*.*.Couldn't open the file! .C:/exp/.visua.... [File] . [Sub-Dir] 
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.zusy.256811")); //GZ type

			//DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
			m_dwOrigFileOff =  0x0430B61;//m_pMaxPEFile->m_dwFileSize - dwOverlayStart - 0x0BA00 ;
			m_dwOrigFileSize = m_pMaxPEFile->m_dwFileSize -  m_dwOrigFileOff;

			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of zusy.256811 Family
--------------------------------------------------------------------------------------*/
int CPolyTrojanZusy256811::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyRiskToolBitMinerMadam
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyRiskToolBitMinerMadam::CPolyRiskToolBitMinerMadam(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	DWORD m_dwOrigFileOff = 0x0;
	DWORD m_dwOrigFileSize = 0x0;
	DWORD	dwByteCheck = 0x0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyRiskToolBitMinerMadam
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyRiskToolBitMinerMadam::~CPolyRiskToolBitMinerMadam(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of BitMiner Family
--------------------------------------------------------------------------------------*/
int CPolyRiskToolBitMinerMadam::DetectVirus()
{

	int		iRetStatus = VIRUS_NOT_FOUND;


	if(m_wAEPSec == 0 && m_wNoOfSections == 0x02 && m_dwAEPMapped == 0x61A4  && m_pSectionHeader[0x0].SizeOfRawData == 0xD000 )
	{
		if(CheckSigInBuffer(m_pMaxPEFile->m_dwFileSize - 0x015,0x015,_T("4641*43454841434B4552")))//FACEHACKER
		{
			//DWORD	dwByteCheck = 0x0;
			DWORD	dwFileEnd = 0x0;
			WORD	wAltCheck = 0x0;
			dwFileEnd = m_pMaxPEFile->m_dwFileSize - 0x08;
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Win32.Gen"));
			while(dwFileEnd > 0)
			{
				if(m_pMaxPEFile->ReadBuffer(&dwByteCheck,dwFileEnd,0x08,0x08))
				{
					if(dwByteCheck == 0xFEEDBEEF)
					{
						wAltCheck++;
						if(wAltCheck == 2)
							break;
					}
				}
				dwFileEnd--;


			}
			dwByteCheck = 0x0;
			if(m_pMaxPEFile->ReadBuffer(&m_dwOrigFileSize,dwFileEnd + 0x08,0x04,0x04))
			{
				m_dwOrigFileOff = dwFileEnd + 0x0118;
				return VIRUS_FILE_REPAIR;
			}
		}
		else
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Win32.Gen"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of BitMiner Family
--------------------------------------------------------------------------------------*/
int CPolyRiskToolBitMinerMadam::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyHEURGEN
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyHEURGEN::CPolyHEURGEN(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwReplaceOffset = 0;
	m_dwOrigFileSize = 0;

}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyHEURGEN
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyHEURGEN::~CPolyHEURGEN(void)
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
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Generic Family
--------------------------------------------------------------------------------------*/
int CPolyHEURGEN::DetectVirus()
{
	int iRetStatus = 0;

	if(m_wAEPSec == 0 && m_wNoOfSections == 0x3 && (m_dwAEPMapped == 0x1B2F || m_dwAEPMapped == 0x1B33)&& m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x1A00) 
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int HEUR_BUFF_SIZE = 0x30;
		m_pbyBuff = new BYTE[HEUR_BUFF_SIZE];

		if(GetBuffer(0x9E00, HEUR_BUFF_SIZE, HEUR_BUFF_SIZE))
		{
			TCHAR HEUR_CZ_Sig[] = {_T("70000000600000*5553525F53686F6864695F50686F746F5F555352")};

			CSemiPolyDBScn polydbObj;
			polydbObj.LoadSigDBEx(HEUR_CZ_Sig, _T("HEUR:Trojan.Win32.Generic"), FALSE);

			TCHAR szVirusName[MAX_PATH] = {0};

			if(polydbObj.ScanBuffer(&m_pbyBuff[0],HEUR_BUFF_SIZE , szVirusName)>=0)	
			{
				if(_tcslen(szVirusName) > 0)
				{
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, szVirusName);

					if(!m_pMaxPEFile->ReadBuffer(&m_dwReplaceOffset,m_pMaxPEFile->m_dwFileSize - 0x1C,0x4,0x4))
					{
						return VIRUS_FILE_DELETE;
					}


					if(!m_pMaxPEFile->ReadBuffer(&m_dwOrigFileSize,m_pMaxPEFile->m_dwFileSize - 0x18,0x4,0x4))
					{
						return VIRUS_FILE_DELETE;
					}

					WORD byCheckMz = 0x00; 

					if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwReplaceOffset,0x2,0x2))
					{
						return VIRUS_FILE_DELETE;
					}
					else if(byCheckMz == 0x5A4D)
					{
						return VIRUS_FILE_REPAIR;
					}
					else
					{
						return VIRUS_FILE_DELETE;
					}



				}
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Generic Family
--------------------------------------------------------------------------------------*/
int CPolyHEURGEN::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwReplaceOffset, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyBLOOREDE
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/

CPolyBLOOREDE::CPolyBLOOREDE(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	m_dwOrigFileOff =0;
	m_dwOrigFileSize = 0;
	m_dwOrigFileSizeoff = 0;
	m_dwExtraByte = 0;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyBLOOREDE
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyBLOOREDE::~CPolyBLOOREDE(void)
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
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Detection routine for different varients of Generic Family
--------------------------------------------------------------------------------------*/
int CPolyBLOOREDE::DetectVirus(void)
{
	int iRetStatus = 0x0;

	if((m_wAEPSec == 0x00 || m_wAEPSec == 0x01) && (m_wNoOfSections == 0x3 || m_wNoOfSections == 0x4 || m_wNoOfSections == 0x5) && (m_dwAEPMapped == 0x620 || m_dwAEPMapped == 0x14B50) && 
		(m_pSectionHeader[0].SizeOfRawData == 0x38000 || m_pSectionHeader[0].SizeOfRawData == 0x3EC00 || m_pSectionHeader[1].SizeOfRawData == 0x14C00) && (memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, "UPX2", 4) == 0 ||
		memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, "UPX1", 4) == 0 || memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, ".bss", 4) == 0))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		const int OVR_BUFF_SIZE = 0x13;
		m_pbyBuff = new BYTE [OVR_BUFF_SIZE];

		if(GetBuffer(m_pMaxPEFile->m_dwFileSize -0x13, OVR_BUFF_SIZE, OVR_BUFF_SIZE))
		{
			const BYTE bySign[] = {0x44, 0x65, 0x74, 0x72};

			DWORD var1 = OVR_BUFF_SIZE -  sizeof(bySign) - 0x0C;
			for(int j = var1; j <=0x13 ;j++)
			{
				if(memcmp(&m_pbyBuff[j], bySign, sizeof(bySign)) == 0x00)
				{
					m_dwOrigFileSizeoff =  (j + m_pMaxPEFile->m_dwFileSize -0x13)-0x4;
					m_dwExtraByte = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileSizeoff;
					break;
				}
			}
			if(!m_pMaxPEFile->ReadBuffer(&m_dwOrigFileSize,m_dwOrigFileSizeoff,0x4,0x4))
			{
				return VIRUS_FILE_DELETE;
			}

			DWORD dwStartBuff = 0x0;

			if(m_dwAEPMapped == 0x14B50)
			{
				dwStartBuff = 0x1DF00;
			}
			else
			{
				dwStartBuff = 0x3B00;
			}

			if(CheckSigInBuffer(dwStartBuff,0xC0,_T("7E7E7E426C6F6F647265647E7E7E6F776E73*7E7E7E796F757E7E7E786F786F7E7E7E32303034*4472446574726F69745B426C6F6F647265642E425D")))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Email-Worm.Win32.Bloored.e"));

				m_dwOrigFileOff = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileSize - m_dwExtraByte;

				WORD byCheckMz = 0x0;

				if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwOrigFileOff,0x2,0x2))
				{
					return VIRUS_FILE_DELETE;
				}
				else if(byCheckMz == 0x5A4D)
				{
					return VIRUS_FILE_REPAIR;
				}
				else 
				{
					return VIRUS_FILE_DELETE;

				}
			}
		}
	}

	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Sneha Kurade + Virus Analysis Team
	Description		: Repair routine for different varients of Generic Family
--------------------------------------------------------------------------------------*/
int CPolyBLOOREDE::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

CPolyWormAutorunVX::CPolyWormAutorunVX(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	DWORD m_dwOrigFileOff = 0x0;
}

CPolyWormAutorunVX::~CPolyWormAutorunVX(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolyWormAutorunVX::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;
	DWORD dwSignOffset;//added

	if( m_wNoOfSections==0x005 && m_wAEPSec == 0x003 && m_dwAEPUnmapped == 0x9001 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2200)
	{	
		if(CheckSigInBuffer(0x3037,0x30,_T("891656E8570200008A8C303E4044005E*BB0100000083C604D3*E303D34083F83A72DE")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Worm.Autorun.VX"));
			m_dwOrigFileOff = m_dwAEPMapped + 0x1E9BFE;
			return VIRUS_FILE_REPAIR;
		}
	}

	//else if(m_wNoOfSections==0x005 &&  m_wAEPSec==0x000 && (m_dwAEPMapped == 0x0AD8 || m_dwAEPMapped == 0x14D8) && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5000)
	else if(m_wNoOfSections==0x005 || m_wNoOfSections==0x004 || m_wNoOfSections==0x003 &&  m_wAEPSec==0x000 && (m_dwAEPMapped == 0x0AD8 || m_dwAEPMapped == 0x14D8 || m_dwAEPMapped ==0x08D8 ||  m_dwAEPMapped ==0x0b3c ) && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x5000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x4C00 ||  m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x9000)) //added
	{
		if (m_dwAEPMapped == 0x08D8)//added
		{
			m_dwOrigFileOffset = 0x1F49FF;
			dwSignOffset = 0x2014;
		}		
		else if(m_dwAEPMapped == 0xb3c)
		{
			m_dwOrigFileOffset = 0x1F49FF;
			dwSignOffset = 0x4c10;
		}
		else if(m_dwAEPMapped == 0x14d8)
		{
			m_dwOrigFileOffset = 0x12DD38;
			dwSignOffset = 0x2c14;
		}
		else
		{
			m_dwOrigFileOffset = 0x1F49FF;		
			dwSignOffset = 0x2214;
		}
		if(CheckSigInBuffer(dwSignOffset,0x1000,_T("63003A005C0076006200760069007200750073005C006F0077006E0065007200700072006F0074006500630074002E007000740074*43003A005C0039003000350063003000370036003900660039006100300036006300390035006100320034006400640066003900340035005C*43003A005C0039003000350063003000370036003900660039006100300036006300390035006100320034006400640066003900340035005C0070006100740063006800650072002E006500780065")))//added dwSignOffset
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Worm.Autorun.VX"));


			WORD	byCheckMz = 0x0;
			if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwOrigFileOffset,0x2,0x2))
			{
				return VIRUS_FILE_DELETE;
			}
			else if(byCheckMz == 0x5A4D)
			{
				return VIRUS_FILE_REPAIR;
			}
			else
			{
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

int CPolyWormAutorunVX::CleanVirus(void)
{
	// Data to be copied from offset 2000h and written at offset 0.Size to be written is Infected File Size - Virus Stub Size==Original File Size
	if((m_wAEPSec==0x003))
	{
		if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff))
		{
			//Truncate file applied after copy data.Set File End=Original File Size
			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff))
			{
				return REPAIR_SUCCESS;
			}
		}
	}

	else if(m_wAEPSec==0x000)
	{
		if(m_pMaxPEFile->CopyData(m_dwOrigFileOffset, 0x00, m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOffset))
		{
			//Truncate file applied after copy data.Set File End=Original File Size
			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOffset))
			{
				return REPAIR_SUCCESS;
			}
		}
	}

	return REPAIR_FAILED;
}

CPolyZusy22271::CPolyZusy22271(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	DWORD m_dwOrigFileOff = 0;
	DWORD m_dwOrigFileSize = 0;

}

CPolyZusy22271::~CPolyZusy22271(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolyZusy22271::DetectVirus()
{
	int iRetStatus = 0x0;
	DWORD dwOverlayStart = 0x0;

	if(!(m_wAEPSec == 0 && m_wNoOfSections == 0x3 &&  m_dwAEPMapped == 0x04F8 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x600))
		return iRetStatus;

	dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData;
	if(CheckSigInBuffer(dwOverlayStart,0x10,_T("0039393532363632*3936372E65786502")))
	{

		DWORD dwCheckMZ = 0x0;
		if(m_pMaxPEFile->ReadBuffer(&dwCheckMZ,dwOverlayStart + 0x16,0x02,0x02))
		{
			if(dwCheckMZ != 0x5A4D)
				return iRetStatus;
		}
		m_dwOrigFileSize = dwOverlayStart;
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.zusy.22271"));
		return VIRUS_FILE_REPAIR;


	}
	return iRetStatus;
}

int CPolyZusy22271::CleanVirus()
{
	if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
	{
		return REPAIR_SUCCESS;
	}
	return REPAIR_FAILED;
}

CPolyBankerBanbra::CPolyBankerBanbra(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	DWORD m_dwOriginalFileOffset = 0x0;
	DWORD dwStartBuff = 0x0;
}

CPolyBankerBanbra::~CPolyBankerBanbra(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolyBankerBanbra::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((m_wAEPSec == 0x00) && (m_wNoOfSections == 0x6) && (m_dwAEPMapped == 0x3C43 ) && (m_pSectionHeader[0].SizeOfRawData == 0x9800) && ( memcmp(m_pSectionHeader[m_wNoOfSections - 2].Name, ".aspack", 7) == 0 ))
	{
		if(m_pMaxPEFile->ReadBuffer(&m_dwOriginalFileOffset,m_pMaxPEFile->m_dwFileSize - 0x0A,0x4,0x4))
		{
			DWORD dwStartBuff = 0xAE6C;

			if(CheckSigInBuffer(dwStartBuff,0X1BE,_T("4D5357444D2E455845*5858585858585858585858585858585858585858585858582E455845*495041524D4F520054524F4A414E00003235352E3235352E3235352E32353500")))
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Banker.Banbra.vwsb"));
				WORD	byCheckMz = 0x0;

				if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwOriginalFileOffset,0x2,0x2))
				{
					return VIRUS_FILE_DELETE;
				}
				else if(byCheckMz == 0x5A4D)
				{
					return VIRUS_FILE_REPAIR;
				}
				else
				{
					return VIRUS_FILE_DELETE;
				}
			}
		}

	}
	return iRetStatus;
}

int CPolyBankerBanbra::CleanVirus(void)
{
	if(m_pMaxPEFile->ReadBuffer(&m_dwOriginalFileSize,m_pMaxPEFile->m_dwFileSize - 0x12,0x4,0x4))
	{
		if(m_pMaxPEFile->CopyData(m_dwOriginalFileOffset, 0x00, m_dwOriginalFileSize))
		{
			//Truncate file applied after copy data.Set File End=Original File Size
			if(m_pMaxPEFile->ForceTruncate(m_dwOriginalFileSize))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
} 

CPolyZbotwten::CPolyZbotwten(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{

	m_dwOrigFileOff = 0;
	m_dwOrigFileSize = 0;
	m_dwReadValue = 0;

}
CPolyZbotwten::~CPolyZbotwten(void) 
{
	if(m_pbyBuff) 
	{

		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
int CPolyZbotwten::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x4 && m_dwAEPMapped == 0x0b3c && m_dwAEPUnmapped == 0x173c && (m_pSectionHeader[0].SizeOfRawData == 0x9000))
	{    
		DWORD dwStartBuff = 0x4c10;

		if(CheckSigInBuffer(dwStartBuff,0xEE,_T("63003A005C0076006200760069007200750073005C006F0077006E0065007200*43003A005C003100300061003000360039003900660061003300370039003200380064003300390063005C00730070006600690072006500770061006C006C002E006500780065")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Spy.Zbot.wten"));

			m_dwOrigFileOff=0xE9FF;
			if(!GetBuffer(m_dwOrigFileOff, 0x10, 0x10))
			{
				return VIRUS_FILE_DELETE;
			}
			else
			{
				return VIRUS_FILE_REPAIR;  
			}
		}
		//return VIRUS_FILE_REPAIR;
	}
	return iRetStatus;
}

int CPolyZbotwten::CleanVirus()
{
	if(m_wNoOfSections == 0x4 && m_dwAEPMapped == 0x0b3c)
	{
		if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00,m_pMaxPEFile->m_dwFileSize-m_dwOrigFileOff)) 
		{
			if(m_pMaxPEFile->ForceTruncate(m_pMaxPEFile->m_dwFileSize-m_dwOrigFileOff))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}


CPolyDownloaderH::CPolyDownloaderH(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOrigFileAEP = 0x0;
}

CPolyDownloaderH::~CPolyDownloaderH(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolyDownloaderH::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if((memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".LWY", 4) == 0  && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x022B && m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xE00000E0) ||
		(m_dwAEPMapped == 0x14214 && memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".idata2", 7) == 0  && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x1000 && m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0xC0000040) ||
		(m_dwAEPMapped == 0x135E4 && memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".rsrc", 5) == 0  && m_pSectionHeader[m_wNoOfSections - 1].SizeOfRawData == 0x1400 && m_pSectionHeader[m_wNoOfSections-1].Characteristics == 0x50000040))
	{
		DWORD dwStartBuff = 0x0;
		DWORD dwBuffSize = 0x0;

		if(memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".LWY", 4) == 0)
		{
			dwStartBuff = m_dwAEPMapped-0x9B;
			dwBuffSize =  0x1B4;

		}
		else
		{
			dwStartBuff = 0x11880;
			dwBuffSize = 0x1000;
		}
		if(CheckSigInBuffer(dwStartBuff,dwBuffSize,_T("687474703A2F2F3132332E*746573746B6C2E636E2F6E6F74657061642E657865*633A5C57494E2E657865*C1E30203DA8B3B033E813F47657450*83C304813B726F6341*83C308813B64647265752683C70C6681")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Downloader.h"));


			if(!m_pMaxPEFile->ReadBuffer(&m_dwOrigFileAEP,m_dwAEPMapped-0x10,0x4,0x4))
			{
				return VIRUS_FILE_DELETE;
			}

			if(m_dwOrigFileAEP >= m_pMaxPEFile->m_dwFileSize || m_dwOrigFileAEP == 0x00)
			{
				return VIRUS_FILE_DELETE;
			}

			return VIRUS_FILE_REPAIR;

		}
	}
	return iRetStatus;
}
int CPolyDownloaderH::CleanVirus(void)
{
	if(m_pMaxPEFile->WriteAEP(m_dwOrigFileAEP))
	{
		if(m_pMaxPEFile->RemoveLastSections())
		{
			return REPAIR_SUCCESS;
		}
	}

	return REPAIR_FAILED;
}

//Swapnil
CPolySWISYNFOHA::CPolySWISYNFOHA(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	m_dwOrigFileOff =0;
	m_dwOrigFilseSize = 0;
}

CPolySWISYNFOHA::~CPolySWISYNFOHA(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolySWISYNFOHA::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x03 && m_dwAEPMapped == 0x37CC && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2D000 && (m_pMaxPEFile->m_stPEHeader.Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL && m_pMaxPEFile->m_bIsVBFile)
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;

		const int OVR_BUFF_SIZE = 0x6000;
		m_pbyBuff = new BYTE [OVR_BUFF_SIZE];

		if(GetBuffer(dwOverlayStart, OVR_BUFF_SIZE, OVR_BUFF_SIZE))
		{		
			const BYTE bySign[] = {0x4D, 0x5A}; //MZ
			DWORD var1 = dwOverlayStart;
			for(DWORD j = 0x0  ; j <= OVR_BUFF_SIZE ;j++)
			{
				if(memcmp(&m_pbyBuff[j], bySign, sizeof(bySign)) == 0x00)
				{
					m_dwOrigFileOff =  j + dwOverlayStart;

					m_dwOrigFilseSize = (m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff)-0x19;

					if(CheckSigInBuffer(0x37CD, 0xBF8,_T("6C404000E8EEFFFFFF000040000000*F440400074424000D837400078*B0B5400030CB4200C41B000008E04200E633400000E042002A005C00410044003A00*5C004500780070006C006F007200650072005C004500780070006C006F007200650072002E007600620070")))
					{
						_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Win32.Swisyn.foha"));
						return VIRUS_FILE_REPAIR;
					}
				}
			}
		}
	}
	return iRetStatus;
}

int CPolySWISYNFOHA::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFilseSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFilseSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

CPolyTrojanGenKD30602080::CPolyTrojanGenKD30602080(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOrigFileOff = 0;
	m_dwOrigFileSize = 0;
	//m_dwReadValue = 0;
}

CPolyTrojanGenKD30602080::~CPolyTrojanGenKD30602080(void) 
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolyTrojanGenKD30602080::DetectVirus(void)
{

	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x6 && m_dwAEPMapped == m_dwAEPUnmapped && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xF000) && (memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".data", 7) == 0)) 
	{	
		DWORD dwStartBuff = 0x23F40; //Starting Offcet For Signature 

		if(CheckSigInBuffer(dwStartBuff,0x100,_T("570069006E002E0065007800650000*66E08FA5A60E28581B72D35A386977F96B270F62617847"))){

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.GenericKD.30602080"));

			DWORD m_dwReadValue = 0x0;
			if(m_pMaxPEFile->ReadBuffer(&m_dwOrigFileSize,m_pMaxPEFile->m_dwFileSize - 0x19,0x4,0x4));
			{
				m_dwOrigFileOff = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileSize - 0x019;
			}

			// TO Check File Starting with MZ
			if(m_pMaxPEFile->ReadBuffer(&m_dwReadValue,m_dwOrigFileOff,0x2,0x2)){

				if(m_dwReadValue == 0x5A4D)
					return VIRUS_FILE_REPAIR;
				else
					return VIRUS_FILE_DELETE;
			} 			
		}
	}
	return iRetStatus;
}

int CPolyTrojanGenKD30602080::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))	
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize)) 
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

CPolyDelfx::CPolyDelfx(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOrigFileOff = 0;
	m_dwOrigFileSize = 0;
	//m_dwReadValue = 0;
}


CPolyDelfx::~CPolyDelfx(void)
{
	if(m_pbyBuff) 
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}


int CPolyDelfx::DetectVirus(void)
{

	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && (m_wNoOfSections == 0x3 || m_wNoOfSections == 0x4) && m_dwAEPMapped == 0x36AC && m_dwAEPUnmapped == 0x42AC && (m_pSectionHeader[0].SizeOfRawData == 0x9200 || 0xB000)) 
	{	

		DWORD dwStartBuff = 0x3560;

		if(CheckSigInBuffer(dwStartBuff,0xEE,_T("41434C436F6E74726F6C2E65786500005245475F535A0000*534F465457415245")))
		{

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Delf.x"));

			DWORD m_dwReadValue = 0x0;
			m_dwReadValue = 0x0;
			m_dwOrigFileOff = 0x4E20;
			m_dwOrigFileSize=(m_pMaxPEFile->m_dwFileSize-m_dwOrigFileOff)-0x1;; 

			// TO Check File Starting with MZ
			if(m_pMaxPEFile->ReadBuffer(&m_dwReadValue,m_dwOrigFileOff,0x2,0x2))
			{
				if(m_dwReadValue == 0x5A4D)
					return VIRUS_FILE_REPAIR;
				else
					return VIRUS_FILE_DELETE;
			} 			
		}
	}
	return iRetStatus;
}

int CPolyDelfx::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

CPolyFUNLOVE::CPolyFUNLOVE(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	m_dwOrigFileOff =0;
	m_dwOrigFilseSize = 0;
}

CPolyFUNLOVE::~CPolyFUNLOVE(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolyFUNLOVE::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if ((m_pSectionHeader[m_wNoOfSections-0x1].Characteristics & IMAGE_SCN_MEM_WRITE) != IMAGE_SCN_MEM_WRITE && (m_pSectionHeader[m_wNoOfSections-0x1].Characteristics & IMAGE_SCN_MEM_READ) != IMAGE_SCN_MEM_READ)
		return iRetStatus;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}

	DWORD dwBuffStartOffset;
	for (WORD i = 0x0; i<=m_wNoOfSections;i++)
	{
		if(memcmp(m_pSectionHeader[i].Name, ".rsrc", 5) == 0)
		{
			dwBuffStartOffset = m_pMaxPEFile->m_stSectionHeader[i].PointerToRawData;

		}
	}
	if(m_pMaxPEFile->m_dwFileSize - dwBuffStartOffset == 0x0)
		return iRetStatus;
	dwBuffStartOffset = dwBuffStartOffset + m_pMaxPEFile->m_stPEHeader.DataDirectory[0x04].Size;
	const int OVR_BUFF_SIZE = 0x3000;
	m_pbyBuff = new BYTE [OVR_BUFF_SIZE];
	DWORD var1 = m_pMaxPEFile->m_dwFileSize - 0x3000;

	for(var1; var1>= dwBuffStartOffset; var1-=0x3000)
	{
		if(GetBuffer(var1, OVR_BUFF_SIZE, OVR_BUFF_SIZE))
		{		
			const BYTE bySign[] = {0x7E,0x46,0x75,0x6E,0x20,0x4C,0x6F,0x76,0x69,0x6E,0x67,0x20,0x43,0x72,0x69,0x6D,0x69,0x6E,0x61,0x6C,0x7E}; //~Fun Loving Criminal~

			for(DWORD j = 0x0  ; j <= OVR_BUFF_SIZE ;j++)
			{
				if(memcmp(&m_pbyBuff[j], bySign, sizeof(bySign)) == 0x00)
				{
					m_dwOrigFileOff =  j + var1 - 0x50;
					_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Funlove"));
					return VIRUS_FILE_REPAIR;
				}
			}
		}
	}
	return iRetStatus;
}


int CPolyFUNLOVE::CleanVirus()
{
	if(m_pMaxPEFile->TruncateFile(m_dwOrigFileOff,true))
	{
		return REPAIR_SUCCESS;
	}

	return REPAIR_FAILED;
}

CPolyTrojanSwisynBNER::CPolyTrojanSwisynBNER(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile) 
{
	m_dwOrigFileOff = 0;
	m_dwOrigFileSize = 0;
}

CPolyTrojanSwisynBNER::~CPolyTrojanSwisynBNER(void) 
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

int CPolyTrojanSwisynBNER::DetectVirus(void)
{

	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x0 && m_pMaxPEFile->m_bIsVBFile == true && (m_wNoOfSections == 0x03 ||m_wNoOfSections == 0x04) &&  (m_dwAEPMapped == 0x3670 || m_dwAEPMapped == 0x2A70) && (m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2B000 || m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0x2A000))
	{
		if (CheckSigInBuffer(0x2A80,0x2000,_T("9183A80580671347B1529358738B9004*4000F4A8F60057696E*4578576174636800C14000D8C040*683CFFCC310008739D6765BFB22D40B1B06C0C4E*D441400001F830*5C3F4000DC4040007C364000780000007C*57696E0057696E000057696E")))
		{	

			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Win32.Swisyn.bner"));

			DWORD m_dwReadValue = 0x0;
			if(m_pMaxPEFile->ReadBuffer(&m_dwOrigFileSize,m_pMaxPEFile->m_dwFileSize - 0x19,0x4,0x4));
			{
				m_dwOrigFileOff = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileSize - 0x019;
			}
		
			// TO Check File Starting with MZ
			if(m_pMaxPEFile->ReadBuffer(&m_dwReadValue,m_dwOrigFileOff,0x2,0x2))
			{
				if(m_dwReadValue == 0x5A4D)
					return VIRUS_FILE_REPAIR;
				else
					return VIRUS_FILE_DELETE;
			} 			
		}
	}
	return iRetStatus;
}

int CPolyTrojanSwisynBNER::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))	
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize)) 
		{

			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

CPolyAgentES::CPolyAgentES(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOrigFileOff = 0x00;
	m_dwStartBuff = 0x00;
	m_dwOrigFileSize = 0x00;
}

CPolyAgentES::~CPolyAgentES(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
int CPolyAgentES::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
	DWORD dwStartBuff = 0x04B0;

	if((m_wAEPSec == 0x00) && (m_wNoOfSections == 0x0006) && m_dwAEPMapped == 0x0400 && m_dwAEPUnmapped == 0x01000 && (m_pSectionHeader[0].SizeOfRawData == 0x800)&& (m_pSectionHeader[0].PointerToRawData == 0x400) && memcmp(m_pSectionHeader[m_wNoOfSections - 1].Name, ".NewSec", 7) == 0)
	{
		if (m_pMaxPEFile->m_dwFileSize <= dwOverlayStart || dwOverlayStart == 0x00)
		{
			return iRetStatus;
		}

		if(CheckSigInBuffer(dwStartBuff,0X2FA,_T("89C321DB750F68010000006822504000E8250000006800000000E810*0F843A010000FF742404E81922000021C00F8420010000A1745740005050FF74240CE865*754CBA535040008D4C240CE8530E0000FF35745740008B542404FF357457*EB0231C021C074598B15C8564000FF3574574000E83D2300008D44242450")))
		{
			if(m_pbyBuff)
			{
				delete []m_pbyBuff;
				m_pbyBuff = NULL;
			}

			bool CheckString = false;
			const int OVR_BUFF_SIZE = 0x5000;
			m_pbyBuff = new BYTE [OVR_BUFF_SIZE];

			const BYTE bySign[] = {0x76,0x69,0x73,0x75,0x61,0x4D,0x5A};

			DWORD i=m_pMaxPEFile->m_dwFileSize - 0x5000;

			for(i; i>=dwOverlayStart; i-=0x5000)
			{
				if(GetBuffer(i, OVR_BUFF_SIZE, OVR_BUFF_SIZE))
				{
					DWORD var1 = OVR_BUFF_SIZE/*-  sizeof(bySign) - 2*/;
					for(int j = var1; j >= 0x0000; j--)
					{
						if(memcmp(&m_pbyBuff[j], bySign, sizeof(bySign)) == 0x00)
						{
							CheckString = true;
							m_dwOrigFileOff =  j + i + 0x05;

							m_dwOrigFileSize = (m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff);

							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Agent.ES"));
							return VIRUS_FILE_REPAIR;

						}

					}

				}

			}
			if (CheckString == false)
			{
				_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Agent.ES"));
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}



int CPolyAgentES::CleanVirus(void)
{

	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		//Truncate file applied after copy data.Set File End=Original File Size
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}

	return REPAIR_FAILED;
}

CPolyVBHN::CPolyVBHN(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	 m_dwOrigFileOff = 0x00;
	 m_dwOrigFileSize = 0x00;
}

CPolyVBHN::~CPolyVBHN(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
int CPolyVBHN::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;


	if((m_wAEPSec == 0x00) && (m_wNoOfSections == 0x3) && (m_dwAEPMapped == m_dwAEPUnmapped ) && (m_pSectionHeader[0].SizeOfRawData == 0xA000)&& (m_pSectionHeader[0].PointerToRawData == 0x1000))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}


		DWORD dwOverlayStart = m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[m_wNoOfSections - 1].PointerToRawData;
		DWORD dwStartBuff = 0x1778;

		if (m_pMaxPEFile->m_dwFileSize <= dwOverlayStart || dwOverlayStart == 0x00)
		{
			return iRetStatus;
		}

		const int OVR_BUFF_SIZE = 0x5000;
		m_pbyBuff = new BYTE [OVR_BUFF_SIZE];

		const BYTE bySign[] = {0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,0x04};

		DWORD i=m_pMaxPEFile->m_dwFileSize - 0x5000;



		for(i; i>= dwOverlayStart; i-=0x5000)
		{


			if(GetBuffer(i, OVR_BUFF_SIZE, OVR_BUFF_SIZE))
			{

				DWORD var1 = OVR_BUFF_SIZE/*-  sizeof(bySign) - 2*/;
				for(int j = var1; j >= 0x0000; j--)
				{
					if(memcmp(&m_pbyBuff[j], bySign, sizeof(bySign)) == 0x00)
					{
						if(CheckSigInBuffer(dwStartBuff,0XADAF,_T("706A7442696E64657200*66726D4D61696E000D010500466F726D31*460069006C0065006E0061006D00650000004600690072006500770061006C006C002E006500780065")))
						{
							_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.VB.FBX"));



							m_dwOrigFileOff =  j + i;

							m_dwOrigFileSize = (m_pMaxPEFile->m_dwFileSize - m_dwOrigFileOff);


							return VIRUS_FILE_REPAIR;

						}
						return iRetStatus;
					}
				}
			}
		}
	}
	return iRetStatus;
}

int CPolyVBHN::CleanVirus(void)
{
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		//Truncate file applied after copy data.Set File End=Original File Size
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}

	return REPAIR_FAILED;
}

CPolyTrojanAgentRC4::CPolyTrojanAgentRC4(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	m_dwOrigFileOff = 0;
	m_dwOrigFileSize = 0;
	//dwkey[] = {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
	for (int  i = 0x0; i < 0x10; i++)
	{
		dwkey[i] = 0x00;
	}

}

CPolyTrojanAgentRC4::~CPolyTrojanAgentRC4(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CPolyTrojanAgentRC4::FirstKey()
{
	int j = 0;
	for(int i = 0x0;i<0x100;i++)
	{
		keyBuff[i] = i;
	}

	for(int i = 0x0;i<0x100;i++)
	{
		j = (j + keyBuff[i] + dwkey[i % 0x10]) % 0x100;
		DWORD tmp = keyBuff[i];
		keyBuff[i] = keyBuff[j];
		keyBuff[j] = tmp;

	}

	int a = 0;
	int b = 0;
	for(int i_last = 0x0; i_last < m_dwOrigFileSize; i_last++)
	{
		a = (a+1) % 0x100;
		b = (b + keyBuff[a]) % 0x100;

		DWORD tmp = keyBuff[a];
		keyBuff[a] = keyBuff[b];
		keyBuff[b] = tmp;

		int XOROp = keyBuff[(keyBuff[a] + keyBuff[b]) % 0x100];

		m_pbyBuff[i_last] = m_pbyBuff[i_last] ^ XOROp;

	}     
	return true;
}

int CPolyTrojanAgentRC4::DetectVirus()
{
	int iRetStatus = 0x0;

	if(!(m_wAEPSec == 0x0 && m_wNoOfSections == 0x03 &&  m_dwAEPMapped == 0x51d2 && m_pSectionHeader[m_wAEPSec].SizeOfRawData == 0xb800 ))
		return iRetStatus;

	if (CheckSigInBuffer(0x4000,0x0200,_T("002500740065006D00700025005C0000002E006500780065*2500770069006E0064006900720025005C004300540053002E00650078006500000000002500740065006D00700025005C004300540053002E006500780065*0053006F006600740077006100720065005C004D006900630072006F0073006F00660074005C00570069006E0064006F00770073005C00430075007200720065006E007400560065007200730069006F006E005C00520075006E000000430054005300")))
	{
		_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Agent.neyndy"));
	}
	else 
		return iRetStatus;

	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}


	m_pMaxPEFile->ReadBuffer(&m_dwOrigFileSize,m_pMaxPEFile->m_dwFileSize - 0x14,0x04,0x04);
	const int   DELFGK_BUFF_SIZE = m_dwOrigFileSize;
	m_pbyBuff = new BYTE[DELFGK_BUFF_SIZE];

	if(!m_pbyBuff)
	{
		return iRetStatus;
	}


	if(!GetBuffer(m_pMaxPEFile->m_dwFileSize - m_dwOrigFileSize - 0x18, DELFGK_BUFF_SIZE, DELFGK_BUFF_SIZE))
	{
		return iRetStatus;
	}



	for(int i = 0; i < 0x10; i++)
	{
		m_pMaxPEFile->ReadBuffer(&dwkey[i],m_pMaxPEFile->m_dwFileSize - 0x10 + i,0x1,0x1);
	}

	if(FirstKey())
		return VIRUS_FILE_REPAIR;



	return iRetStatus;
}

int CPolyTrojanAgentRC4::CleanVirus()
{

	if(m_pMaxPEFile->WriteBuffer(m_pbyBuff,0x0,m_dwOrigFileSize,0x0,0x0))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
			return REPAIR_SUCCESS;
	}

	return REPAIR_FAILED;
}

//Aniket
CPolyVirusShohdi::CPolyVirusShohdi(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOrigFileOff = 0x00;
	m_dwOrigFileSize = 0x00;
}

CPolyVirusShohdi::~CPolyVirusShohdi(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}
int CPolyVirusShohdi::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if (m_wAEPSec == 0x00 && m_wNoOfSections == 0x4 && (m_dwAEPMapped == 0x29f6 || m_dwAEPMapped == 0x4fb6) && (m_dwAEPUnmapped == 0x29f6 || m_dwAEPUnmapped == 0x5bb6)
		&& (m_pSectionHeader[0].SizeOfRawData == 0x2000 || m_pSectionHeader[0].SizeOfRawData == 0x20000 || m_pSectionHeader[0].SizeOfRawData == 0xf800)
		&& (m_pSectionHeader[0].PointerToRawData == 0x1000 || m_pSectionHeader[0].PointerToRawData == 0x400))
	{
		if(m_pbyBuff)
		{
			delete []m_pbyBuff;
			m_pbyBuff = NULL;
		}

		DWORD dwSignatureStart = m_pMaxPEFile->m_dwFileSize - 0x14;
		DWORD dwSignatureOffset = m_pMaxPEFile->m_stPEHeader.DataDirectory[4].VirtualAddress + m_pMaxPEFile->m_stPEHeader.DataDirectory[4].Size + 0x08;
		if(CheckSigInBuffer(dwSignatureStart,0X14,_T("5553525F53686F6864695F*50686F746F5F555352")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("virus.shohdi.i"));
			return VIRUS_FILE_REPAIR;
		}
		else if(CheckSigInBuffer(dwSignatureOffset,0X14,_T("5553525F53686F6864695F*50686F746F5F555352")))
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.Win32.Shohdi.I"));
			return VIRUS_FILE_DELETE;
		}
	}
	return iRetStatus;
}

int CPolyVirusShohdi::CleanVirus(void)
{
	DWORD m_dwOrigFileoffsetread = m_pMaxPEFile->m_dwFileSize - 0x1c;
	m_pMaxPEFile->ReadBuffer(&m_dwOrigFileOff,m_dwOrigFileoffsetread,0x4,0x4);
	DWORD m_dwOrigFileSize=(m_pMaxPEFile->m_dwFileSize -m_dwOrigFileOff)-0x1c;
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		//Truncate file applied after copy data.Set File End=Original File Size
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

//Added 27-Jan-2021 JayPrakash
/*-------------------------------------------------------------------------------------
	Function		: CPolyWormVikingEO
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyWormVikingEO::CPolyWormVikingEO(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	m_dwOriginalFileSize=0;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyWormVikingEO
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyWormVikingEO::~CPolyWormVikingEO(void)
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
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Detection routine for different varients of Worm.Win32.Burn.b Family
--------------------------------------------------------------------------------------*/
int CPolyWormVikingEO::DetectVirus(void)
{ 
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x03 && m_wAEPSec == 0x002 && m_dwAEPUnmapped == 0x30000 && m_dwAEPMapped == 0xB400 && m_pSectionHeader[2].SizeOfRawData ==0x0036 && (memcmp(m_pSectionHeader[2].Name, "WinLicen", 7) == 0))
	{
		if (CheckSigInBuffer(m_dwAEPMapped , m_pSectionHeader[2].SizeOfRawData, _T("68810000006882000000688300000068*840000006885000000688600000083C4*0483C40483C40483C40483C40483C404*6800104000C3"))) 
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Worm.Win32.Viking.eo")); 

			m_dwOriginalFileOffset = m_dwAEPMapped + m_pSectionHeader[2].SizeOfRawData;

			m_dwOriginalFileSize = (m_pMaxPEFile->m_dwFileSize - m_dwOriginalFileOffset); 

			WORD byCheckMz = 0x0;

			if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwOriginalFileOffset,0x2,0x2))
			{
				return VIRUS_FILE_DELETE;
			}
			else if(byCheckMz == 0x5A4D)
			{
				return VIRUS_FILE_REPAIR;
			}
			else
			{
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Repair routine for different varients of Worm.Win32.Viking.eo Family
--------------------------------------------------------------------------------------*/
int CPolyWormVikingEO::CleanVirus()
{
	if(m_pMaxPEFile->CopyData(m_dwOriginalFileOffset, 0x00, m_dwOriginalFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOriginalFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyVirusShodiA
	In Parameters	: 
	Out Parameters	: Constructor
	Purpose			: 
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Repair routine for different varients of Virus.WIN32.HLLP.Shodi.a Family
--------------------------------------------------------------------------------------*/
CPolyVirusShodiA::CPolyVirusShodiA(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{
	m_dwOrigFileOff = 0x00;
	m_dwOrigFileSize = 0x00;
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVirusShodiA
	In Parameters	: 
	Out Parameters	: Destructor
	Purpose			: 
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Repair routine for different varients of Virus.WIN32.HLLP.Shodi.a Family
--------------------------------------------------------------------------------------*/
CPolyVirusShodiA::~CPolyVirusShodiA(void)
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
	Out Parameters	: Status : VIRUS_FILE_DELETE or VIRUS_NOT_FOUND
	Purpose			: 
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Repair routine for different varients of Virus.WIN32.HLLP.Shodi.a Family
--------------------------------------------------------------------------------------*/
int CPolyVirusShodiA::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wAEPSec == 0x00 && m_wNoOfSections == 0x4 && m_dwAEPMapped == 0x3D57 && m_dwAEPUnmapped == 0x3D57 && m_pSectionHeader[0].SizeOfRawData == 0x8000 && m_pSectionHeader[0].PointerToRawData == 0x1000 )
	{
		if (CheckSigInBuffer(0xB000 , 0x100, _T("B24940003A774000AF7240*617375007573610055736153686F686469")))// asu.usa.UsaShohdi
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Virus.WIN32.HLLP.Shodi.a")); 

			if(m_pMaxPEFile->ReadBuffer(&m_dwOrigFileSize,m_pMaxPEFile->m_dwFileSize - 0xD,0x4,0x4));
			{
				m_dwOrigFileOff = m_pMaxPEFile->m_dwFileSize - m_dwOrigFileSize - 0x11;
			}

			WORD byCheckMz = 0x0;

			if(!m_pMaxPEFile->ReadBuffer(&byCheckMz,m_dwOrigFileOff,0x2,0x2))
			{
				return VIRUS_FILE_DELETE;
			}
			else if(byCheckMz == 0x5A4D)
			{
				return VIRUS_FILE_REPAIR;
			}
			else
			{
				return VIRUS_FILE_DELETE;
			}
		}
	}
	return iRetStatus;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Jay Prakash + Virus Analysis Team
	Description		: Repair routine for different varients of Virus.WIN32.HLLP.Shodi.a Family
--------------------------------------------------------------------------------------*/
int CPolyVirusShodiA::CleanVirus(void)
{	
	if(m_pMaxPEFile->CopyData(m_dwOrigFileOff, 0x00, m_dwOrigFileSize))
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwOrigFileSize))
		{
			return REPAIR_SUCCESS;
		}
	}
	return REPAIR_FAILED;
}

/*-------------------------------------------------------------------------------------
	Function		: CPolyPatchedRW
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Swapnil Sanghai
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyPatchedRW::CPolyPatchedRW(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)   
{
	m_dwAEPOffset= 0;
	m_dwVirusSectionOffset = 0;
}
/*-------------------------------------------------------------------------------------
	Function		: CPolyPatchedRW
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Swapnil Sanghai
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyPatchedRW::~CPolyPatchedRW(void)
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
	Author			: Swapnil Sanghai + Virus Analysis Team
	Description		: Detection routine for different varients of Trojan.Patched.RW Family
--------------------------------------------------------------------------------------*/
int CPolyPatchedRW::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	if(m_wNoOfSections == 0x07 && m_wAEPSec == 0x06 && m_pSectionHeader[m_wAEPSec].SizeOfRawData ==0x1000 && memcmp(m_pSectionHeader[m_wAEPSec].Name, ".zero", 6) == 0)
	{	
		
		DWORD dwAEPOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData + 0x762;

		m_pMaxPEFile->ReadBuffer(&m_dwAEPOffset,dwAEPOffset,0x4,0x4);
	 
		m_dwVirusSectionOffset = m_pSectionHeader[m_wAEPSec].PointerToRawData;
		if (CheckSigInBuffer(m_pSectionHeader[m_wAEPSec].PointerToRawData , 0x45, _T("558BEC81EC78090000E8B20C00008985C4FD*FFFF83BDC4FDFFFF007505E93D0700"))) 
		{
			_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("Trojan.Patched.RW")); 
			return VIRUS_FILE_REPAIR;
		}
	}
	return iRetStatus;
}
/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Virus Analysis Team
	Description		: Repair routine for different varients of Trojan.Patched.RW Family
--------------------------------------------------------------------------------------*/
int CPolyPatchedRW::CleanVirus()
{
	if(m_pMaxPEFile->RemoveLastSections())
	{
		if(m_pMaxPEFile->ForceTruncate(m_dwVirusSectionOffset))
		{
			if(m_pMaxPEFile->WriteAEP(m_dwAEPOffset))
			{
				return REPAIR_SUCCESS;
			}
		}
	}
	return REPAIR_FAILED;
}