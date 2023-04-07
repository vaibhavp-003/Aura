/*======================================================================================
FILE				: PolyVulcas.cpp
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
NOTES				: This is detection module for malware Vulcas Family.
					  Class is derived from CPolyBase Class
					  The repair action is : DELETE or REPAIR
VERSION HISTORY		: 
=====================================================================================*/
#include "PolyVulcas.h"

/*-------------------------------------------------------------------------------------
	Function		: CPolyVulcas
	In Parameters	: CMaxPEFile *pMaxPEFile
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Constructor for this class
--------------------------------------------------------------------------------------*/
CPolyVulcas::CPolyVulcas(CMaxPEFile *pMaxPEFile): CPolyBase(pMaxPEFile)
{	
}

/*-------------------------------------------------------------------------------------
	Function		: ~CPolyVulcas
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam
	Description		: Destructor for this class
--------------------------------------------------------------------------------------*/
CPolyVulcas::~CPolyVulcas(void)
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
	Description		: Detection routine for different varients of Vulcas Family
--------------------------------------------------------------------------------------*/
int CPolyVulcas::DetectVirus(void)
{
	int iRetStatus = VIRUS_NOT_FOUND;

	WORD wMachine = 0;
	if(!m_pMaxPEFile->ReadBuffer(&wMachine, m_pMaxPEFile->m_stPEHeader.e_lfanew + 4, 2, 2))
	{
		return iRetStatus;
	}
	if((wMachine == 0x14C) && ((m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress > 0) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress < (m_pSectionHeader[m_wNoOfSections-1].VirtualAddress + m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData))) &&
		((m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size > 0 ) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size < ((m_pMaxPEFile->m_dwFileSize-(m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x80))))) &&
		((m_pMaxPEFile->m_stPEHeader.DataDirectory[5].VirtualAddress == 0x00) && (m_pMaxPEFile->m_stPEHeader.DataDirectory[5].Size == 0x00)) && 
		((m_pMaxPEFile->m_stPEHeader.Characteristics & 0x3002) == 0x0002) && (memcmp(m_pSectionHeader[m_wNoOfSections-1].Name,".reloc",0x06) == 0x00) &&
		(m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData >= 0x1A00 && ((m_pSectionHeader[m_wNoOfSections-1].SizeOfRawData%m_pMaxPEFile->m_stPEHeader.FileAlignment) == 0x00) ) &&
		((m_pSectionHeader[m_wNoOfSections-1].Characteristics & 0xC0000040) == 0xC0000040))
	{
		NameTableAPI stAPITable[MAX_RVA_VALUES] = {0};
		NameTableAPI stExportDirectTable[MAX_RVA_VALUES] = {0};

		IMAGE_IMPORT_DESCRIPTOR objImportDescriptor = {0};
		DWORD dwImportDLLIndex = 0x00;

		if(GetImportAndNameTableRVA("kernel32.dll", objImportDescriptor, &dwImportDLLIndex))
		{
			m_wImportSection = m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress, &m_dwKernelNameOffset);
			if(OUT_OF_FILE == m_wImportSection)
			{
				return iRetStatus;
			}
			DWORD dwCounter = ReadRVAValues(true, m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size, 0x14, stExportDirectTable, false);
			if(dwCounter > 0)
			{
				SortRVAValues(stExportDirectTable,dwCounter);
				DWORD dwImportDLLNextIndex = dwImportDLLIndex + 0x01;
				if(stExportDirectTable[dwImportDLLIndex].Index != dwImportDLLIndex)
				{
					DWORD dwtempcounter = 0x00;
					while(dwtempcounter < dwCounter)
					{
						if(stExportDirectTable[dwtempcounter].Index == dwImportDLLIndex)
						{
							dwImportDLLNextIndex = dwtempcounter + 0x01;
							break;
						}
						dwtempcounter++;
					}
				}
				if(m_pMaxPEFile->Rva2FileOffset(objImportDescriptor.OriginalFirstThunk,&m_dwKernelNameOffset) == m_wImportSection)
				{
					dwCounter = 0;
					if(dwImportDLLNextIndex < (dwCounter - 0x01))
					{
						dwCounter = ReadRVAValues(true, stExportDirectTable[dwImportDLLNextIndex].dwRVAValues - stExportDirectTable[dwImportDLLNextIndex-0x01].dwRVAValues, 0x04, stAPITable, true);
					}
					else if(dwImportDLLNextIndex == dwCounter)
					{
						dwCounter = ReadRVAValues(false, 0x00, 0x04, stAPITable, true);
					}
					if(dwCounter > 0)
					{
						SortRVAValues(stAPITable, dwCounter);
						if(CheckForValidAPI(stAPITable, dwCounter, true))
						{
							m_dwRVAOffset = (m_dwAPIIndex * 0x04) + objImportDescriptor.FirstThunk + m_dwImageBase;
							if(CheckFurtherForVirus())
							{
								_tcscpy_s(m_szVirusName, MAX_VIRUS_NAME, _T("W32.Vulcas"));
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
	Function		: ReadRVAValues
	In Parameters	: bool bn,DWORD dwBufferSize,DWORD dwIncCounter,NameTableAPI *stAPITable,bool bPickGreater
	Out Parameters	: 0 for failure else file offse
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: To read the RVA values from the Import Directory Table and the API RVA values
--------------------------------------------------------------------------------------*/
DWORD CPolyVulcas::ReadRVAValues(bool bn,DWORD dwBufferSize,DWORD dwIncCounter,NameTableAPI *stAPITable,bool bPickGreater)
{
	DWORD	dwIndex = 0x00, dwOrdinalflag = 0x00;
	bool	bPickAll = true;

	if(bn)
	{ 
		if(dwBufferSize > 0x10000)
		{
			return 0;
		}

		BYTE *byAPINamesbuff= new BYTE[dwBufferSize];
		if(byAPINamesbuff)
		{
			if(m_pMaxPEFile->ReadBuffer(byAPINamesbuff, m_dwKernelNameOffset, dwBufferSize, dwBufferSize))
			{		
				while((dwIndex + dwIncCounter) < dwBufferSize && ((*(DWORD*)&byAPINamesbuff[dwIndex] > 0x00) && ((*(DWORD*)&byAPINamesbuff[dwIndex]&0x7FFFFFFF)<(m_pSectionHeader[m_wImportSection].VirtualAddress+m_pSectionHeader[m_wImportSection].Misc.VirtualSize))) )
				{
					if(dwIndex==MAX_RVA_VALUES * dwIncCounter)
					{
						break;
					}
					//To check if ordinal is not present
					if(((IMAGE_ORDINAL_FLAG32 & *(DWORD*)&byAPINamesbuff[dwIndex]) != IMAGE_ORDINAL_FLAG32) && bPickAll )
					{
						stAPITable[(dwIndex-dwOrdinalflag)/dwIncCounter].dwRVAValues = *(DWORD*)&byAPINamesbuff[dwIndex];
						stAPITable[(dwIndex-dwOrdinalflag)/dwIncCounter].Index = dwIndex/dwIncCounter;
						if(bPickGreater)
						{
							bPickAll = false;
						}
					}
					else if(bPickGreater && ((IMAGE_ORDINAL_FLAG32&*(DWORD*)&byAPINamesbuff[dwIndex])!=IMAGE_ORDINAL_FLAG32) && (*(DWORD*)&byAPINamesbuff[dwIndex]> stAPITable[0].dwRVAValues))
					{
						stAPITable[(dwIndex-dwOrdinalflag)/dwIncCounter].dwRVAValues = *(DWORD*)&byAPINamesbuff[dwIndex];
						stAPITable[(dwIndex-dwOrdinalflag)/dwIncCounter].Index = dwIndex/dwIncCounter;
					}
					else 
					{
						dwOrdinalflag += 0x04;
					}
					dwIndex += dwIncCounter;
				}					
			}
			if(byAPINamesbuff)
			{
				delete[] byAPINamesbuff;
				byAPINamesbuff=NULL;
			}
		}
	}
	else
	{
		DWORD dwAPINames = 0;
		while(1)
		{
			if(m_pMaxPEFile->ReadBuffer(&dwAPINames, m_dwKernelNameOffset + dwIndex, 0x04, 0x04))
			{					
				if((dwAPINames == 0x00) || dwAPINames > (m_pSectionHeader[m_wImportSection].VirtualAddress + m_pSectionHeader[m_wImportSection].Misc.VirtualSize))
				{
					break;
				}

				if(dwIndex == MAX_RVA_VALUES * dwIncCounter)
				{
					break;
				}

				if(((IMAGE_ORDINAL_FLAG32 & dwAPINames) != IMAGE_ORDINAL_FLAG32) && bPickAll)
				{
					stAPITable[(dwIndex - dwOrdinalflag) / dwIncCounter].dwRVAValues = dwAPINames;
					stAPITable[(dwIndex - dwOrdinalflag) / dwIncCounter].Index = dwIndex/dwIncCounter;
					if(bPickGreater)
					{
						bPickAll = false;
					}
				}
				else if(bPickGreater && ((IMAGE_ORDINAL_FLAG32&dwAPINames)!=IMAGE_ORDINAL_FLAG32) && dwAPINames> stAPITable[0].dwRVAValues)
				{
					stAPITable[(dwIndex-dwOrdinalflag)/dwIncCounter].dwRVAValues=dwAPINames;
					stAPITable[(dwIndex-dwOrdinalflag)/dwIncCounter].Index=dwIndex/dwIncCounter;
				}
				else
				{
					dwOrdinalflag+=0x04;
				}
				dwIndex+=dwIncCounter;
			}
		}
	}
	return ((dwIndex-dwOrdinalflag)/dwIncCounter);
}


/*-------------------------------------------------------------------------------------
	Function		: SortRVAValues
	In Parameters	: NameTableAPI *stAPITable,DWORD dwSize
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: To sort the RVA values
--------------------------------------------------------------------------------------*/
void CPolyVulcas::SortRVAValues(NameTableAPI *stAPITable,DWORD dwSize)
{
	bool bflag = true;
	while(bflag)
	{
		bflag = false;
		for(DWORD i = 1; i <= dwSize - 0x01; i++)
		{

			if(stAPITable[i-0x01].dwRVAValues > stAPITable[i].dwRVAValues)
			{
				stAPITable[i-0x01].dwRVAValues += stAPITable[i].dwRVAValues;
				stAPITable[i].dwRVAValues = stAPITable[i-0x01].dwRVAValues-stAPITable[i].dwRVAValues;
				stAPITable[i-0x01].dwRVAValues -= stAPITable[i].dwRVAValues;

				stAPITable[i-0x01].Index += stAPITable[i].Index;
				stAPITable[i].Index = stAPITable[i-0x01].Index-stAPITable[i].Index;
				stAPITable[i-0x01].Index -= stAPITable[i].Index;

				bflag = true;
			}
		}
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckForValidAPI
	In Parameters	: NameTableAPI *stAPITable,DWORD dwSize,bool bNotAPIIndex
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Check for valid API
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::CheckForValidAPI(NameTableAPI *stAPITable,DWORD dwSize,bool bNotAPIIndex)
{
	CHAR APINames[0x0A][0x15]={"GetProcessHeap", 
		"GetVersion",
		"GetStartupInfoA",
		"GetStartupInfoW",
		"GetCommandLineA",
		"GetCommandLineW",
		"GetCurrentProcess",
		"CreateThread",
		"GetModuleHandleA",
		"GetModuleHandleW"
	};

	BYTE byAPISize[0x0A]={0x0E,0x0A,0x0F,0x0F,0x0F,0x0F,0x11,0x0C,0x10,0x10};

	//last 0x40 is for the last API
	DWORD dwtempBuffsize=stAPITable[dwSize-0x01].dwRVAValues-stAPITable[0x00].dwRVAValues+0x40;
	if(dwtempBuffsize > 0x10000)
	{
		return false;
	}

	BYTE *bytemp=new BYTE[dwtempBuffsize];
	if(!bytemp)
	{
		return false;
	}

	DWORD dwAPINameStartOffset = 0;
	BYTE byflag = 0x00, *bytemp1 = NULL;
	if(m_pMaxPEFile->Rva2FileOffset(stAPITable[0].dwRVAValues,&dwAPINameStartOffset)>=0)
	{
		if(m_pMaxPEFile->ReadBuffer(bytemp,dwAPINameStartOffset,dwtempBuffsize,dwtempBuffsize))
		{
			bytemp1=bytemp;
			DWORD dwAPIPlusSize;
			for(DWORD i=0x00;i<0x0A;i++)
			{
				bytemp=bytemp1;
				dwAPIPlusSize=0x00;
				for(DWORD j=0x00;j<dwSize;j++)
				{
					byflag=0x00;
					if(stAPITable[j].dwRVAValues%2==0x01)
					{
						byflag=0x01;
					}

					dwAPIPlusSize+=DWORD(0x02+byflag+strlen((char*)(bytemp+byflag+0x02))+CheckOddEven(strlen((char*)(bytemp+byflag+0x02))%2));
					if(dwAPIPlusSize>=(dwtempBuffsize))
					{
						break;
					}
					if(memcmp(bytemp+0x02+byflag,APINames[i],byAPISize[i])==0x00)
					{
						if(strlen((char*)(bytemp+byflag+0x02))==byAPISize[i])
						{
							if(bytemp)
							{
								bytemp=bytemp1;
								delete[] bytemp;
								bytemp=NULL;
							}

							if(bNotAPIIndex)
							{
								m_dwAPIIndex=j;
							}
							else
							{
								m_dwAPIIndex=stAPITable[j].Index;
							}
							return true; 
						}
					}
					if(j==dwSize-0x01)
					{
						break;
					}
					bytemp+=(stAPITable[j+0x01].dwRVAValues-stAPITable[j].dwRVAValues);
				}
			}
		}
	}
	if(bytemp)
	{
		bytemp=bytemp1;
		delete[] bytemp;
		bytemp=NULL;
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckOddEven
	In Parameters	: BYTE Size
	Out Parameters	: 1 or 2
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Odd / Even check
--------------------------------------------------------------------------------------*/
DWORD CPolyVulcas::CheckOddEven(BYTE Size)
{
	return Size ? 0x01 : 0x02;
}

/*-------------------------------------------------------------------------------------
	Function		: CheckFurtherForVirus
	In Parameters	: 
	Out Parameters	: true if success else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Detection routine for different varients of Vulcas Family
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::CheckFurtherForVirus()
{
	DWORD dwBuffSize = m_pMaxPEFile->m_stPEHeader.SizeOfCode;
	m_dwStartFileOffset = 0x00;
	if(dwBuffSize < m_pMaxPEFile->m_dwFileSize)
	{
		DWORD dwBaseOfCode = 0;
		if(!m_pMaxPEFile->ReadBuffer(&dwBaseOfCode, m_pMaxPEFile->m_stPEHeader.e_lfanew + 0x2C, 4, 4))
		{
			return false;
		}
		if(m_pMaxPEFile->Rva2FileOffset(dwBaseOfCode, &m_dwStartFileOffset)>=0)
		{
			DWORD dwChunks = 0x10000;
			m_pbyBuff = new BYTE[dwChunks];
			for(DWORD dwCounter = 0x00; dwCounter < (dwBuffSize/dwChunks) + 1; dwCounter++)
			{
				if(dwCounter==(dwBuffSize/dwChunks)&& (dwBuffSize%dwChunks!=0x00))
				{
					dwChunks=dwBuffSize%dwChunks;
					if(m_pbyBuff)
					{
						delete[] m_pbyBuff;
						m_pbyBuff=NULL;
					}
					m_pbyBuff=new BYTE[dwChunks];
				}

				if(!GetBuffer(m_dwStartFileOffset,dwChunks,dwChunks))
				{
					return false;
				}

				for(m_dwCntInChunks=0;m_dwCntInChunks<(dwChunks-0x06);m_dwCntInChunks++)
				{
					if((m_pbyBuff[m_dwCntInChunks]==0xE8||m_pbyBuff[m_dwCntInChunks]==0xE9) && m_pbyBuff[m_dwCntInChunks+0x05]==0x90)
					{
						//Jump should take one to the last section PRD
						if( (m_dwStartFileOffset+m_dwCntInChunks+*(DWORD*)&m_pbyBuff[m_dwCntInChunks+0x01]+0x05)==m_pSectionHeader[m_wNoOfSections-0x01].VirtualAddress)
						{
							memset(byJumptoVirus,0,0x06);
							*(DWORD*)&byJumptoVirus[0x02]=m_pSectionHeader[m_wNoOfSections-0x01].PointerToRawData;
							byJumptoVirus[0x00]=m_pbyBuff[m_dwCntInChunks];
							if(m_pbyBuff)
							{
								delete[] m_pbyBuff;
								m_pbyBuff=NULL;
							}
							if(m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData > 0x10000)
							{
								return false;
							}
							m_pbyBuff=new BYTE[m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData];         

							if(!GetBuffer(m_pSectionHeader[m_wNoOfSections-0x01].PointerToRawData,m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData,m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData))
							{
								return false;
							}

							m_dwVirusOffset=0x00;
							CheckParameters();
							if(m_dwVirusOffset+0x05<m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
							{
								if(m_pbyBuff[m_dwVirusOffset]==0xE8 && *(DWORD*)&m_pbyBuff[m_dwVirusOffset+0x01]==0x1910)
								{   
									m_dwVirusOffset+=0x05;
									return true;
								}
							}
						}
					}
				}
				m_dwStartFileOffset+=dwChunks;
				dwChunks=0x10000;
			}
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: CleanVirus
	In Parameters	: 
	Out Parameters	: Status : REPAIR_SUCCESS or REPAIR_FAILED
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Repair routine for different varients of Vulcas Family
--------------------------------------------------------------------------------------*/
int CPolyVulcas::CleanVirus()
{	
	if(m_dwVirusOffset+0x1910<m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
	{
		m_dwVirusOffset+=0x1910;
		CheckParameters();
		if(m_dwVirusOffset+0xC<m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
		{
			if(*(DWORD*)&m_pbyBuff[m_dwVirusOffset]==0x00006E860 && 
				*(DWORD*)&m_pbyBuff[m_dwVirusOffset+0x04]==0x648B0000 &&
				*(DWORD*)&m_pbyBuff[m_dwVirusOffset+0x08]==0x0CEB0824)
			{
				if(byJumptoVirus[0x00]==0xE8)
				{
					*(WORD*)&byJumptoVirus[0x00]=0x15FF;
				}
				else
				{
					*(WORD*)&byJumptoVirus[0x00]=0x25FF;
				}
				*(DWORD*)&byJumptoVirus[0x02]=m_dwRVAOffset;
				if(m_pMaxPEFile->WriteBuffer(byJumptoVirus,m_dwStartFileOffset+m_dwCntInChunks,sizeof(byJumptoVirus),sizeof(byJumptoVirus)))
				{
					if(m_pMaxPEFile->FillWithZeros(m_pSectionHeader[m_wNoOfSections-0x01].PointerToRawData,m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData))
					{
						//Changing the value of SRD of last section to prevent file from scanning again
						if(m_pMaxPEFile->WriteSectionCharacteristic(m_wNoOfSections-0x01,m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData-0x01,0x10))
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
	Function		: CheckParameters
	In Parameters	: 
	Out Parameters	: 
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Validates the structure read from file
--------------------------------------------------------------------------------------*/
void CPolyVulcas::CheckParameters()
{
	if(Rem7Operation()  || Rem0Operation() || Rem1Operation() || Rem2Operation() ||Rem5Operation() || Rem3Operation() || Rem4Operation())
	{
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem0Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 0
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem0Operation()
{
	if(m_dwVirusOffset + 0x05 < m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
	{
		if( m_pbyBuff[m_dwVirusOffset]==0xB8 || m_pbyBuff[m_dwVirusOffset]==0x05 || m_pbyBuff[m_dwVirusOffset]==0x15 ||
			m_pbyBuff[m_dwVirusOffset]==0x2D || m_pbyBuff[m_dwVirusOffset]==0x1D || m_pbyBuff[m_dwVirusOffset]==0x0D ||
			m_pbyBuff[m_dwVirusOffset]==0x35 || m_pbyBuff[m_dwVirusOffset]==0x25 || m_pbyBuff[m_dwVirusOffset]==0xA9 ||
			m_pbyBuff[m_dwVirusOffset]==0x3D )
		{
			m_dwVirusOffset+=0x05;
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem1Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 1
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem1Operation()
{
	DWORD dwTempVirusOffset = m_dwVirusOffset;
	if( Rem3Operation() && Rem12Operation())
	{
		return true;
	}
	m_dwVirusOffset = dwTempVirusOffset;
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem12Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 0
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem12Operation()
{
	if(m_dwVirusOffset+0x02<m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
	{
		if((m_pbyBuff[m_dwVirusOffset]==0x8B || m_pbyBuff[m_dwVirusOffset]==0x03 || m_pbyBuff[m_dwVirusOffset]==0x13 || m_pbyBuff[m_dwVirusOffset]==0x2B || 
			m_pbyBuff[m_dwVirusOffset]==0x1B || m_pbyBuff[m_dwVirusOffset]==0x0B || m_pbyBuff[m_dwVirusOffset]==0x33 || m_pbyBuff[m_dwVirusOffset]==0x23) &&
			((m_pbyBuff[m_dwVirusOffset+0x01]&0xC0)==0xC0))
		{
			m_dwVirusOffset+=0x02;
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem2Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 0
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem2Operation()
{
	DWORD dwTempVirusOffset=m_dwVirusOffset;
	if( Rem12Operation() && Rem3Operation())
	{
		return true;
	}
	m_dwVirusOffset=dwTempVirusOffset;
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem3Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 3
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem3Operation()
{
	if(m_dwVirusOffset+0x01<m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
	{
		if( m_pbyBuff[m_dwVirusOffset]==0x90 || m_pbyBuff[m_dwVirusOffset]==0x48 || m_pbyBuff[m_dwVirusOffset]==0xD6 ||
			m_pbyBuff[m_dwVirusOffset]==0x40 || m_pbyBuff[m_dwVirusOffset]==0xF8 || m_pbyBuff[m_dwVirusOffset]==0x98 ||
			m_pbyBuff[m_dwVirusOffset]==0xF9 || m_pbyBuff[m_dwVirusOffset]==0xFC )
		{
			m_dwVirusOffset+=0x01;
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem4Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 4
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem4Operation()
{ 
	DWORD dwTempVirusOffset=m_dwVirusOffset;
	if( Rem12Operation())
	{
		return true;
	}
	m_dwVirusOffset=dwTempVirusOffset;
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: RemAllOperations
	In Parameters	: 
	Out Parameters	: RemAllOperations
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: 
--------------------------------------------------------------------------------------*/
void CPolyVulcas::RemAllOperations()
{
	if(Rem0Operation() || Rem1Operation() || Rem12Operation() || Rem2Operation() || Rem5Operation() || Rem3Operation() || Rem4Operation())
	{
	}
	return;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem5Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 5
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem5Operation()
{
	if(m_dwVirusOffset + 0x03 < m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
	{
		if(*(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xC0C1 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xE0C1 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xD0C1 || 
			*(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xC8C1 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xE8C1 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xF8C1 || 
			*(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xD8C1 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xC083 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xC883 || 
			*(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xD083 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xD883 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xE083 ||  
			*(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xE883 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xF083 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0xF883 || 
			*(WORD*)&m_pbyBuff[m_dwVirusOffset]==0x72F8 || *(WORD*)&m_pbyBuff[m_dwVirusOffset]==0x73F9 ) 
		{
			m_dwVirusOffset+=0x03;
			return true;
		}
	}
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: Rem7Operation
	In Parameters	: 
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: remainder 7
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::Rem7Operation()
{ 
	DWORD dwTempVirusOffset = m_dwVirusOffset;
	RemAllOperations();
	if(m_dwVirusOffset + 0x05 < m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
	{
		if(m_pbyBuff[m_dwVirusOffset] == 0xE8)
		{
			m_dwVirusOffset += 0x05;
			RemAllOperations();
			if(m_dwVirusOffset + 0x05 < m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
			{
				if(m_pbyBuff[m_dwVirusOffset] == 0xE9)
				{
					m_dwVirusOffset += 0x05;
					RemAllOperations();
					RemAllOperations();
					if(m_dwVirusOffset + 0x01 < m_pSectionHeader[m_wNoOfSections-0x01].SizeOfRawData)
					{
						if(m_pbyBuff[m_dwVirusOffset] == 0xC3)
						{
							m_dwVirusOffset++;
							RemAllOperations();
							RemAllOperations();
							return true;
						}
					}
				}
			}
		}
	}
	m_dwVirusOffset = dwTempVirusOffset;
	return false;
}

/*-------------------------------------------------------------------------------------
	Function		: GetImportAndNameTableRVA
	In Parameters	: char* szDllName, IMAGE_IMPORT_DESCRIPTOR &objIMPORTTable,DWORD *pdwIndexOffset
	Out Parameters	: true if sucess else false
	Purpose			: 
	Author			: Tushar Kadam + Virus Analysis Team
	Description		: Get Import and Name Table RVA
--------------------------------------------------------------------------------------*/
bool CPolyVulcas::GetImportAndNameTableRVA(char* szDllName, IMAGE_IMPORT_DESCRIPTOR &objIMPORTTable,DWORD *pdwIndexOffset/* = NULL*/)
{
	bool bRetStatus = false;
	if(szDllName == NULL)
	{
		return bRetStatus;
	}

	DWORD dwImpDirTableSize = m_pMaxPEFile->m_stPEHeader.DataDirectory[1].Size, dwImpDirTableOff = 0x00;
	m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.DataDirectory[1].VirtualAddress, &dwImpDirTableOff);
	if(dwImpDirTableOff == 0x00 || dwImpDirTableSize > 0x10000)
	{
		return bRetStatus;
	}

	BYTE *byBuffer = new BYTE[dwImpDirTableSize];
	if(byBuffer == NULL)
	{
		return bRetStatus;
	}
	if(m_pMaxPEFile->ReadBuffer(byBuffer, dwImpDirTableOff, dwImpDirTableSize, dwImpDirTableSize))
	{
		DWORD dwDLLNameLen = strlen(szDllName);
		if(dwDLLNameLen < 100)
		{
			_strlwr_s(szDllName, dwDLLNameLen + 1);

			char szReadDllName[100] = {0};
			DWORD dwReadDllNameOff = 0x00;

			for(DWORD iCnt = 0; iCnt < dwImpDirTableSize; iCnt += 20)
			{
				memset(&szReadDllName[0], 0, 100);
				dwReadDllNameOff = 0;
				m_pMaxPEFile->Rva2FileOffset(*((DWORD*)&byBuffer[iCnt + 12]), &dwReadDllNameOff);
				if(dwReadDllNameOff != 0)
				{					
					if(m_pMaxPEFile->ReadBuffer(&szReadDllName[0], dwReadDllNameOff, dwDLLNameLen, dwDLLNameLen))
					{
						_strlwr_s(szReadDllName, 100);
						if(strcmp(szDllName, szReadDllName) == 0x00)
						{
							memcpy(&objIMPORTTable, &byBuffer[iCnt], sizeof(IMAGE_IMPORT_DESCRIPTOR));
							if(pdwIndexOffset)
							{
								*pdwIndexOffset=iCnt/20;
							}
							bRetStatus = true;

							break;
						}
					}
				}
			}
		}
	}
	if(byBuffer)
	{
		delete []byBuffer;
		byBuffer = NULL;
	}
	return bRetStatus;
}





