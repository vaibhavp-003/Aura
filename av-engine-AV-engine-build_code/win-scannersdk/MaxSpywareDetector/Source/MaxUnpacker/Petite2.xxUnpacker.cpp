#pragma once
#include "Petite2.xxUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CPetite2xxUnpacker::CPetite2xxUnpacker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
	m_dwOffset=0x00;
	m_pStructPetCopyBlockInfo=NULL;
	m_pStructPetDecompressBlockInfo=NULL;
	m_pStructPetDecompressBlockInfoe1A0=NULL;
}

CPetite2xxUnpacker::~CPetite2xxUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
	m_pStructPetCopyBlockInfo=NULL;
	m_pStructPetDecompressBlockInfo=NULL;
	m_pStructPetDecompressBlockInfoe1A0=NULL;
}

bool CPetite2xxUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 2 && 
		BYTE(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint)%0x42 == 0x00 || 
		BYTE(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint)%0x42 == 0x04)
	{	
		m_pbyBuff = new BYTE[255];
		BYTE byPetite2xxbuff[]={0x64,0xFF,0x35,0x00,0x00,0x00,0x00,0x64,0x89,0x25,0x00,0x00,0x00,0x00,0x66,0x9C};
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x1A,0x1A))
		{
			return false;
		}
		if(m_pbyBuff[0]==0xB8 && m_pbyBuff[5]==0x68 && memcmp(&m_pbyBuff[0xA],byPetite2xxbuff,sizeof(byPetite2xxbuff))==0x00)
		{
			return true;
		}
	}
	return false;
}

bool CPetite2xxUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName, true, false))
	{
		return false;
	}
	BYTE *byFullFilebuff=NULL;
	if(!(byFullFilebuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize)))
	{
		return false;
	}
	if(!m_objTempFile.ReadBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	m_dwOffset=*(DWORD*)&m_pbyBuff[1]-m_dwImageBase;
	m_dwSEHHandler=*(DWORD*)&m_pbyBuff[6]-m_dwImageBase;

	//To reach the point of the structure which signifies the addresses of the decompression/copy
	//m_dwOffset+=0x1B8;
	//m_dwOffset+=0x1A0;
	DWORD dwTempOffset=0x00;
	DWORD dwFinalReadOffset=0x00;
	dwTempOffset+=0x1C;
	DWORD dwDLLCounter=0x0;
	DWORD dwDLLCounter2=0x00;
	DWORD dwDLLCounter3=0x00;
	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset+0x02>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	if(*(WORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset]==0xD88B)
	{
		dwTempOffset+=0x11;
	}

	dwTempOffset+=0x15;
	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset+0x01>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	if((byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset]&0x50)==0x50)
	{
		dwTempOffset+=0x01;
	}
	dwTempOffset+=0x0E;

	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset+0x07>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwDLLCounter=byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset];
	dwDLLCounter2=byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset+0x02];
	if(byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset+0x06]==0x68)
	{
		dwTempOffset+=0x04;
	}
	dwTempOffset+=0x17;

	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwDLLCounter3=*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset];
	dwTempOffset+=0x0B;

	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//dwTempOffset+=0x30;

	if(*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset]==0x1B8)
	{
	 m_ePetite2xxType=e1B8;
	}
	else if(*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset]==0x1A0)
	{
		m_ePetite2xxType=e1A0;
	}
	else
	{
		//Unhandled Type
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	m_dwOffset=*(DWORD*)&m_pbyBuff[1]-m_dwImageBase+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwTempOffset];

	if(m_dwOffset>m_objTempFile.m_dwFileSize || m_dwSEHHandler>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}


	DWORD dwCounter=0x00;

	/*****************************************************************************************/
	if(m_ePetite2xxType==e1A0)
	{
		while(m_dwOffset+dwCounter+sizeof(PETDECOMPRESSBLOCKINFOe1A0)<=m_objTempFile.m_dwFileSize)
		{
			m_pStructPetDecompressBlockInfoe1A0=(PETDECOMPRESSBLOCKINFOe1A0 *)&byFullFilebuff[m_dwOffset+dwCounter];
			if(m_pStructPetDecompressBlockInfoe1A0->dwSrcRVA==0x00)
			{
				break;
			}
			if(m_pStructPetDecompressBlockInfoe1A0->dwUBlockSize!=0x00)
			{
				
				BYTE *byDestbuff=NULL;
				DWORD dwDestSize=m_pStructPetDecompressBlockInfoe1A0->dwUBlockSize;
				if(!(byDestbuff=(BYTE*)MaxMalloc(dwDestSize)))
				{
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}

				if(!PetiteUncompress(m_pStructPetDecompressBlockInfoe1A0->dwSrcSize*0x04,&dwDestSize,0x00,0x00,&byFullFilebuff[m_pStructPetDecompressBlockInfoe1A0->dwSrcRVA],byDestbuff,0,0xC350,0))
				{
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					free(byDestbuff);
					byDestbuff=NULL;
					return false;
				}

				//Writing the decompressed buffer back to the FileBuffer
				for(DWORD i=0;i<dwDestSize;i++)
				{
					byFullFilebuff[m_pStructPetDecompressBlockInfoe1A0->dwDestRVA+i]=byDestbuff[i];
				}

				if(byDestbuff)
				{
					free(byDestbuff);
					byDestbuff=NULL;
				}

			}
			dwCounter+=sizeof(PETDECOMPRESSBLOCKINFOe1A0);

		}
	}
	/*****************************************************************************************/

	/******************************************************************************/
	//Case for m_ePetite2xxType=e1B8;
	else if(m_ePetite2xxType==e1B8)
	{
		while(m_dwOffset+dwCounter+sizeof(PETCOPYBLOCKINFO)<=m_objTempFile.m_dwFileSize)
		{
			m_pStructPetCopyBlockInfo=(PETCOPYBLOCKINFO *)&byFullFilebuff[m_dwOffset+dwCounter];

			if(m_pStructPetCopyBlockInfo->dwBlockSize!=0x00)
			{
				if((m_pStructPetCopyBlockInfo->dwBlockSize&IMAGE_ORDINAL_FLAG32)==IMAGE_ORDINAL_FLAG32)
				{
					//Simple Copy
					//Write Buffer to another offset
					if(m_pStructPetCopyBlockInfo->dwDestRVA-(m_pStructPetCopyBlockInfo->dwBlockSize&0x7FFFFFFF-1)*0x04<m_objTempFile.m_dwFileSize &&
						m_pStructPetCopyBlockInfo->dwDestRVA-(m_pStructPetCopyBlockInfo->dwBlockSize&0x7FFFFFFF-1)*0x04>0)
					{
						for(DWORD i=0;i<(m_pStructPetCopyBlockInfo->dwBlockSize&0x7FFFFFFF)*0x04;i+=4)
						{
							*(DWORD*)&byFullFilebuff[m_pStructPetCopyBlockInfo->dwDestRVA-i]=*(DWORD*)&byFullFilebuff[m_pStructPetCopyBlockInfo->dwSrcRVA-i];
						}
					}
					else
					{
						free(byFullFilebuff);
						byFullFilebuff=NULL;
						return false;
					}
				}
				else
				{
					if(m_dwOffset+dwCounter+sizeof(PETDECOMPRESSBLOCKINFO)>m_objTempFile.m_dwFileSize)
					{
						free(byFullFilebuff);
						byFullFilebuff=NULL;
						return false;
					}				
					BYTE *byDestbuff=NULL;
					m_pStructPetCopyBlockInfo=NULL;
					m_pStructPetDecompressBlockInfo=(PETDECOMPRESSBLOCKINFO*)&byFullFilebuff[dwCounter+m_dwOffset];

					if(m_pStructPetDecompressBlockInfo->dwBlockSize!=0x00)
					{
						DWORD dwDestSize=m_pStructPetDecompressBlockInfo->dwBlockSize;
						if(!(byDestbuff=(BYTE*)MaxMalloc(dwDestSize)))
						{
							free(byFullFilebuff);
							byFullFilebuff=NULL;
							return false;
						}

						if(!PetiteUncompress(m_pStructPetDecompressBlockInfo->dwBlockSize,&dwDestSize,0x00,0x00,&byFullFilebuff[m_pStructPetDecompressBlockInfo->dwSrcRVA],byDestbuff,1))
						{
							free(byFullFilebuff);
							byFullFilebuff=NULL;
							free(byDestbuff);
							byDestbuff=NULL;
							return false;
						}

						//Writing the decompressed buffer back to the FileBuffer
						for(DWORD i=0;i<dwDestSize;i++)
						{
							byFullFilebuff[m_pStructPetDecompressBlockInfo->dwDestRVA+i]=byDestbuff[i];
						}

						if(byDestbuff)
						{
							free(byDestbuff);
							byDestbuff=NULL;
						}
					}
					//Incrementing by 0x04 and down by sizeof(PETCOPYBLOCKINFO)
					dwCounter+=0x04;
				}
			}
			else
			{
				break;
			}

			dwCounter+=sizeof(PETCOPYBLOCKINFO);
			m_pStructPetDecompressBlockInfo=NULL;
			m_pStructPetCopyBlockInfo=NULL;
		}
	}
	else
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	/************************************************************************************/

	/******Handling SEH Interrupt**********/

	DWORD dwOffset=0x54;
	if(m_ePetite2xxType==e1A0)
	{
		dwOffset+=0x02;
	}

	if(m_dwSEHHandler+0x54+dwOffset+0x29>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwDecryptionSize=*(DWORD*)&byFullFilebuff[m_dwSEHHandler+0x54+dwOffset];
	DWORD dwAEPHelpCounter=byFullFilebuff[m_dwSEHHandler+0x54+dwOffset-0x05];
	DWORD dwROLXey = byFullFilebuff[m_dwSEHHandler+0x54+dwOffset+0x28];

	if(m_ePetite2xxType==e1A0)
	{
	  m_dwOffset-=0x1A0;
	  m_dwOffset+=0x3D;
	}
	else if(m_ePetite2xxType==e1B8)
	{
	 m_dwOffset-=0x1B8;
	 m_dwOffset+=0x39;
	}

	//Not needed Implemented incase of actual running of file
	/*for(DWORD i=0;i<0x0E;i++)
	{
	byFullFilebuff[m_dwOffset+i]=byFullFilebuff[m_dwSEHHandler+0x05+i];
	}*/



	/******Handling SEH interrupt ends**********/



	/*****Decryption to get the AEP************/

	DWORD dwXORValue=0x00;

	if(m_dwSEHHandler+dwDecryptionSize+0x05+0x0E+1>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	for(;dwDecryptionSize>0; dwDecryptionSize--)
	{
		dwXORValue|=WORD(0x0001);
		*(BYTE*)&dwXORValue=BYTE(dwXORValue)^byFullFilebuff[m_dwSEHHandler+dwDecryptionSize+0x05+0x0E];
		MAX_ROL(dwXORValue,dwROLXey);
	}

	dwXORValue|=WORD(0x0001);
	*(BYTE*)&dwXORValue=BYTE(dwXORValue)^byFullFilebuff[m_dwSEHHandler+dwDecryptionSize+0x05+0x0E];
	MAX_ROL(dwXORValue,dwROLXey);

	
	dwDecryptionSize=*(DWORD*)&byFullFilebuff[m_dwSEHHandler+0x54+dwOffset];
	m_dwOrigAEP=*(DWORD*)&byFullFilebuff[m_dwSEHHandler+0x05+0x0A]^dwXORValue;
	//m_dwOrigAEP=*(DWORD*)&byFullFilebuff[m_dwSEHHandler+*(DWORD*)&byFullFilebuff[m_dwSEHHandler+0x54+0x54]+0x05+0x0E+0x01]^dwXORValue;


	DWORD dwSEHHandler2=0x0;
	BYTE byCompare=0x0;
	
	/********AEP Finding ends****************/

	if(m_ePetite2xxType==e1A0)
	{
		dwSEHHandler2=*(DWORD*)&byFullFilebuff[m_dwSEHHandler+0x54+0x0E];
		dwSEHHandler2+=(m_dwSEHHandler+0x05);
		if(dwSEHHandler2+0x60+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		byCompare=byFullFilebuff[dwSEHHandler2+0x60];
		m_dwOffset-=0x3D;
		m_dwOffset+=0x1A0;
	}
	else if(m_ePetite2xxType==e1B8)
	{
		m_dwOffset-=0x39;
		m_dwOffset+=0x1B8;
    }

	dwCounter=0x00;
	while(m_dwOffset+dwCounter+sizeof(PETCOPYBLOCKINFO)<=m_objTempFile.m_dwFileSize)
	{
		m_pStructPetCopyBlockInfo=(PETCOPYBLOCKINFO *)&byFullFilebuff[dwCounter+m_dwOffset];

		if(m_pStructPetCopyBlockInfo->dwBlockSize!=0x00)
		{
			if(((m_pStructPetCopyBlockInfo->dwBlockSize&IMAGE_ORDINAL_FLAG32)!=IMAGE_ORDINAL_FLAG32 && m_ePetite2xxType==e1B8)||
				(m_ePetite2xxType==e1A0))
			{
				m_pStructPetCopyBlockInfo=NULL;
				m_pStructPetDecompressBlockInfo=(PETDECOMPRESSBLOCKINFO*)&byFullFilebuff[dwCounter+m_dwOffset];
				if((m_pStructPetDecompressBlockInfo->dwFillWithZeroSize&0x00000001)==0x00000001)
				{
					if(m_pStructPetDecompressBlockInfo->dwDestRVA+m_pStructPetDecompressBlockInfo->dwBlockSize<m_objTempFile.m_dwFileSize && 
						m_pStructPetDecompressBlockInfo->dwBlockSize>=0x06)
					{
						if(!ResolveE8E9Calls(&byFullFilebuff[m_pStructPetDecompressBlockInfo->dwDestRVA],m_pStructPetDecompressBlockInfo->dwBlockSize,byCompare))
						{
							free(byFullFilebuff);
							byFullFilebuff=NULL;
							return false;

						}
					}
				}
				//Fill with Zeroes
				if(m_pStructPetDecompressBlockInfo->dwDestRVA+m_pStructPetDecompressBlockInfo->dwBlockSize+m_pStructPetDecompressBlockInfo->dwFillWithZeroSize<m_objTempFile.m_dwFileSize)
				{
					for(DWORD i=0;i<(m_pStructPetDecompressBlockInfo->dwFillWithZeroSize>>1);i++)
					{
						byFullFilebuff[m_pStructPetDecompressBlockInfo->dwDestRVA+m_pStructPetDecompressBlockInfo->dwBlockSize+i]=0x00;
					}
				}
				if(m_ePetite2xxType==e1A0)
				{
					dwCounter+=0x04;
				}
				dwCounter+=0x04;
			}
		}
		else
		{
			break;
		}
		dwCounter+=sizeof(PETCOPYBLOCKINFO);
		m_pStructPetDecompressBlockInfo=NULL;
		m_pStructPetCopyBlockInfo=NULL;
	}	

	//Rebuilding Import Table

	BYTE *byImportTablebuf=NULL;
	DWORD dwImportSizeBuild=0x00;
	dwCounter=0x00;
	DWORD dwImportSize=m_objTempFile.m_stPEHeader.SectionAlignment;
	if(!(byImportTablebuf=(BYTE*)MaxMalloc(dwImportSize)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(m_ePetite2xxType==e1B8)
	{
		m_dwOffset-=0x1B8;
		dwOffset+=0x79;
	}
	else if(m_ePetite2xxType==e1A0)
	{
		m_dwOffset-=0x1A0;
		dwOffset+=0x52;
		dwOffset+=0x28;
	}
	memset(byImportTablebuf,0,dwImportSize);
	DWORD dwAEPHelp=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+m_dwImageBase+0x05;
	
	DWORD dwImportDLLTableOffset=*(DWORD*)&byFullFilebuff[m_dwOffset]+m_dwOffset+dwDLLCounter2*0x04+dwDLLCounter3;
	//*(DWORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x1]-m_dwImageBase]+(*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x1]-m_dwImageBase)+24+0x124;
	DWORD dwImportAPITableOffset=*(DWORD*)&byFullFilebuff[m_dwSEHHandler+0x54+dwOffset];
	DWORD dwDLLSize=dwDLLCounter*0x04;

	
	if(m_dwOffset+0x0E+0x171>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(*(DWORD*)&byFullFilebuff[m_dwOffset]+m_dwOffset+dwDLLCounter2*0x04+dwDLLCounter3+dwDLLSize>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	for(DWORD i=0;i<0x171;i++)
	{
		byFullFilebuff[m_dwOffset+0x0E+i]=0x00;
	}

	DWORD dwDLLLength=0x00;
	while(1)
	{
		dwDLLLength=0;
		while(byFullFilebuff[dwImportDLLTableOffset+dwDLLLength]!=0x00 && dwImportDLLTableOffset+dwDLLLength<
			*(DWORD*)&byFullFilebuff[m_dwOffset]+m_dwOffset+dwDLLCounter2*0x04+dwDLLCounter3+dwDLLSize)
		{
			dwDLLLength++;
		}
		if(dwDLLLength==0x00)
		{
			break;
		}

		while(dwImportSizeBuild+0x14>dwImportSize)
		{
			if(!(byImportTablebuf=(BYTE*)realloc(byImportTablebuf, dwImportSize+m_objTempFile.m_stPEHeader.SectionAlignment)))
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				free(byImportTablebuf);
				byImportTablebuf=NULL;
				return false;
			}
			memset(&byImportTablebuf[dwImportSize],0,m_objTempFile.m_stPEHeader.SectionAlignment);
			dwImportSize+=m_objTempFile.m_stPEHeader.SectionAlignment;
		}

		*(DWORD*)&byImportTablebuf[dwImportSizeBuild+0x0C]=dwImportDLLTableOffset;
		if(dwImportAPITableOffset+dwCounter+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			free(byImportTablebuf);
			byImportTablebuf=NULL;
			return false;
		}
		*(DWORD*)&byImportTablebuf[dwImportSizeBuild+0x10]=*(DWORD*)&byFullFilebuff[dwImportAPITableOffset];
		while(*(DWORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwImportAPITableOffset]+dwCounter]!=0x00)
		{
			if((*(DWORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwImportAPITableOffset]+dwCounter]&IMAGE_ORDINAL_FLAG32)!=IMAGE_ORDINAL_FLAG32)
			{
				dwAEPHelpCounter--;
				if(dwAEPHelpCounter==0xFFFFFFFF)
				{
					dwAEPHelp+=0x05;
					dwAEPHelpCounter=dwAEPHelp&0x07;
					m_dwOrigAEP--;
				}
				*(DWORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwImportAPITableOffset]+dwCounter]-=0x02;
			}
			m_dwOrigAEP--;
			MAX_ROR(m_dwOrigAEP,3);
			dwCounter+=0x04;
		}
		dwImportAPITableOffset+=0x04;
		dwImportDLLTableOffset+=dwDLLLength+1;
		dwImportSizeBuild+=0x014;
		dwCounter=0x00;
	}

	//Incrementing the no. of sections by 1 and pointing the Import Table to the new offset
	*(WORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NumberOfSections]=m_objTempFile.m_stPEHeader.NumberOfSections+1;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=m_objTempFile.m_dwFileSize;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=m_dwOrigAEP+0x05+m_objTempFile.m_stPEHeader.AddressOfEntryPoint;

	//Writing the complete buffer with all the new changes except the Import Table
	if(!m_objTempFile.WriteBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff = NULL;
		free(byImportTablebuf);
		byImportTablebuf=NULL;
		return false;
	}

	if(byFullFilebuff)
	{
		free(byFullFilebuff);
		byFullFilebuff = NULL;
	}

	//Closing and Opening the file to reflect the changes
	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		free(byImportTablebuf);
		byImportTablebuf=NULL;
		return false;
	}

	//Adding a new Section
	if(!AddNewSection(dwImportSize,1))
	{
		free(byImportTablebuf);
		byImportTablebuf=NULL;
		return false;
	}

	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		free(byImportTablebuf);
		byImportTablebuf=NULL;
		return false;
	}

	//Writing the basic Import Directory Table buffer to memory
	if(!m_objTempFile.WriteBuffer(byImportTablebuf, m_objTempFile.m_dwFileSize, dwImportSize, dwImportSize))
	{
		free(byImportTablebuf);
		byImportTablebuf=NULL;
		return false;
	}	

	if(byImportTablebuf)
	{
		free(byImportTablebuf);
		byImportTablebuf=NULL;
	}

	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		free(byImportTablebuf);
		byImportTablebuf=NULL;
		return false;
	}

	if(!ReOrganizeFile(szTempFileName, false))
	{
		return false;
	}

	if(!m_objTempFile.CalculateImageSize())
	{
		return false;
	}
	return true;
}

bool CPetite2xxUnpacker::ResolveE8E9Calls(BYTE *bybuff, DWORD dwSize,BYTE byCompare)
{
	dwSize-=0x06;
	for(DWORD dwCounter=0;dwCounter<=dwSize;dwCounter++)
	{
		if(bybuff[dwCounter]==0xE8 || bybuff[dwCounter]==0xE9)
		{
			if(byCompare)
			{
				if(byCompare==bybuff[dwCounter+0x01])
				{
					*(DWORD*)&bybuff[dwCounter+0x01]=HIWORD(*(DWORD*)&bybuff[dwCounter+0x01])|ntohs(LOWORD(*(DWORD*)&bybuff[dwCounter+0x01])&0xFF00);
					MAX_ROL(*(DWORD*)&bybuff[dwCounter+0x01],0x10);
					*(DWORD*)&bybuff[dwCounter+0x01]=ntohs(HIWORD(*(DWORD*)&bybuff[dwCounter+0x01]))|LOWORD(*(DWORD*)&bybuff[dwCounter+0x01]);
					*(DWORD*)&bybuff[dwCounter+0x01]-=(dwCounter+0x05);

				}
				
			}
			else
			{
				*(DWORD*)&bybuff[dwCounter+1]-=dwCounter;
			}
			dwCounter+=0x04;
		}
		else if(bybuff[dwCounter]==0x0F)
		{
			if(bybuff[dwCounter+1]>=0x80 && bybuff[dwCounter+1]<=0x8F)
			{
				if(byCompare)
				{
					if(byCompare==bybuff[dwCounter+0x02])
					{
						*(DWORD*)&bybuff[dwCounter+0x02]=HIWORD(*(DWORD*)&bybuff[dwCounter+0x02])|ntohs(LOWORD(*(DWORD*)&bybuff[dwCounter+0x02])&0xFF00);
						MAX_ROL(*(DWORD*)&bybuff[dwCounter+0x02],0x10);
						*(DWORD*)&bybuff[dwCounter+0x02]=ntohs(HIWORD(*(DWORD*)&bybuff[dwCounter+0x02]))|LOWORD(*(DWORD*)&bybuff[dwCounter+0x02]);
						*(DWORD*)&bybuff[dwCounter+0x02]-=(dwCounter+0x06);
					}
				}
				else
				{
					*(DWORD*)&bybuff[dwCounter+2]-=dwCounter;
				}
				dwCounter+=0x05;		
			}
		}
	}

	return true;
}