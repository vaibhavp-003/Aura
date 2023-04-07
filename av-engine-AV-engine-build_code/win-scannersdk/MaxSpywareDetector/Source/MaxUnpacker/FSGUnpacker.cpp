#include "FSGUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CFSGUnpacker::CFSGUnpacker(CMaxPEFile *pMaxPEFile, int iCurrentLevel): 
CUnpackBase(pMaxPEFile, iCurrentLevel)
{
	m_pStructDecompressBlockInfo=NULL;
	iType=0;
}

CFSGUnpacker::~CFSGUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
	m_pStructDecompressBlockInfo=NULL;
}

bool CFSGUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 && 
		(m_iCurrentLevel > 0 || 
		((m_pMaxPEFile->m_dwAEPMapped < m_pMaxPEFile->m_stPEHeader.SizeOfHeaders || m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) &&	
		m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData==0x00)))
	{
		m_pbyBuff = new BYTE[255];
		m_dwOffset=0;
		if(m_pMaxPEFile->m_dwAEPMapped>m_pMaxPEFile->m_stPEHeader.SizeOfHeaders)
		{
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x0B,0x0B))
			{
				return false;
			}

			if(m_pbyBuff[0]==0xE9)
			{
				m_dwOffset=*(DWORD*)&m_pbyBuff[1]+0x05;		
			}
			else if((m_pbyBuff[0]==0xBE && *(DWORD*)&m_pbyBuff[5]==0x97AD93AD && *(WORD*)&m_pbyBuff[9]==0x56AD && (iType=MOV)))
			{
				m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
                return true;
			}
		}
		m_dwOffset+=CUnpackBase::m_iDataCnt*0x28+m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;

		if(m_dwOffset>m_pMaxPEFile->m_stPEHeader.SizeOfHeaders)
		{
			return false;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwOffset,0xC,0xC))
		{
			return false;
		}

		if(*(WORD*)&m_pbyBuff[0]==0x2587 && *(WORD*)&m_pbyBuff[0x6]==0x9461 && *(DWORD*)&m_pbyBuff[0x08]==0x80B6A455)
		{
			return true;
		}
	}	
	return false;
}

bool CFSGUnpacker::Unpack(LPCTSTR szTempFileName)
{	
	
	if(!ReOrganizeFile(szTempFileName,true,false))
	{
		return false;
	}

	BYTE *byFullFilebuff=NULL;
	//Just allocating a buffer of 30h extra for the length of the max_instruction
	if(!(byFullFilebuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize+0x30)))
	{
		return false;
	}
	//Filling the extra 30h bytes with zeroes
	memset(&byFullFilebuff[m_objTempFile.m_dwFileSize],0x00,0x30);
	if(!m_objTempFile.ReadBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	
	DWORD dwOffsetInFile=0;
	BYTE *byImportbuff=NULL;
	DWORD dwImportSize=0;

	if(iType==XCHG)
	{
		dwOffsetInFile=*(DWORD*)&m_pbyBuff[0x02];
		dwOffsetInFile-=m_dwImageBase;

		if(dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		dwOffsetInFile=*(DWORD*)&byFullFilebuff[dwOffsetInFile];
		dwOffsetInFile-=m_dwImageBase;


		if(dwOffsetInFile+sizeof(BlockInfo)>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		m_pStructDecompressBlockInfo=(BlockInfo*)&byFullFilebuff[dwOffsetInFile];
		m_pStructDecompressBlockInfo->dwDestRVA-=m_dwImageBase;
		m_pStructDecompressBlockInfo->dwSrcRVA-=m_dwImageBase;
		if(m_pStructDecompressBlockInfo->dwSrcRVA > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		m_pStructDecompressBlockInfo->ImportOffset-=m_dwImageBase;

		DWORD dwSrcSize=0;
		DWORD dwDestSizeAllocated=m_objTempFile.m_dwFileSize-m_pStructDecompressBlockInfo->dwDestRVA;
		DWORD dwDestSize=dwDestSizeAllocated;
		BYTE *byDestbuff=NULL;

		if(!(byDestbuff=(BYTE*)MaxMalloc(dwDestSizeAllocated)))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		memset(byDestbuff,0,dwDestSize);

		dwSrcSize=m_objTempFile.m_dwFileSize-m_pStructDecompressBlockInfo->dwSrcRVA;
        
		if(!(~(dwDestSize=APLIBDecompress(dwSrcSize,dwDestSize,0,0,byDestbuff,0,&byFullFilebuff[m_pStructDecompressBlockInfo->dwSrcRVA]))))
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		for(DWORD i=0;i<dwDestSize;i++)
		{
			byFullFilebuff[m_pStructDecompressBlockInfo->dwDestRVA+i]=byDestbuff[i];
		}

		if(byDestbuff)
		{
			free(byDestbuff);
			byDestbuff=NULL;
		}

		if(dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveImports(&byImportbuff,dwImportSize,m_pStructDecompressBlockInfo->ImportOffset,byFullFilebuff))
		{
			if(byImportbuff)
			{
				free(byImportbuff);
				byImportbuff=NULL;
			}
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=m_pStructDecompressBlockInfo->dwAEP-m_dwImageBase;
	}
	else if(iType==MOV)
	{
		dwOffsetInFile=*(DWORD*)&m_pbyBuff[0x01];
		dwOffsetInFile-=m_dwImageBase;
		dwOffsetInFile+=(CUnpackBase::m_iDataCnt*0x28);

		dwOffsetInFile+=0x04;
		if(dwOffsetInFile+0x08>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		DWORD dwDestRVA=0;
		DWORD dwSrcRVA=0;
		DWORD dwDestSize=0;
		DWORD dwSrcSize=0;
		DWORD dwDestSizeAllocated=0;
		DWORD dwImportOffset=0;
		BYTE *byDestbuff=new BYTE(1);
		boolean bIncrement8=true;

		dwSrcRVA=*(DWORD*)&byFullFilebuff[dwOffsetInFile+0x04]-m_dwImageBase;
		if(dwSrcRVA > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff = NULL;
			free(byDestbuff);
			byDestbuff = NULL;
			
			return false;
		}
        
		while(*(DWORD*)&byFullFilebuff[dwOffsetInFile]!=0x01)
		{
			dwSrcSize=m_objTempFile.m_dwFileSize-dwSrcRVA;
			if(dwSrcSize==0x00)
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			if(*(DWORD*)&byFullFilebuff[dwOffsetInFile]==0x00)
			{
				dwOffsetInFile+=0x04;
				if(dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
				{
					free(byDestbuff);
					byDestbuff=NULL;
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}
				dwImportOffset=*(DWORD*)&byFullFilebuff[dwOffsetInFile]-m_dwImageBase;
			}

			dwDestRVA=*(DWORD*)&byFullFilebuff[dwOffsetInFile]-m_dwImageBase;
			if(!bIncrement8 && *(DWORD*)&byFullFilebuff[dwOffsetInFile-0x04]!=0x00)
			{
				dwDestRVA-=0x01;
			}
			
			if(dwDestSizeAllocated<m_objTempFile.m_dwFileSize-dwDestRVA)
			{
				if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_objTempFile.m_dwFileSize-dwDestRVA)))
				{
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}
				dwDestSizeAllocated=m_objTempFile.m_dwFileSize-dwDestRVA;
			}
			memset(byDestbuff,0,dwDestSizeAllocated);

			if(!(~(dwDestSize=APLIBDecompress(dwSrcSize,dwDestSizeAllocated,0,0,byDestbuff,0,&byFullFilebuff[dwSrcRVA],&dwSrcSize))))
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}

			for(DWORD i=0;i<dwDestSize;i++)
			{
				byFullFilebuff[dwDestRVA+i]=byDestbuff[i];
			}
			dwSrcRVA+=dwSrcSize;
			
			if(bIncrement8)
			{
			 dwOffsetInFile+=0x04;
			 bIncrement8=false;
			}
			dwOffsetInFile+=0x04;
			if(dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}

		}

		if(byDestbuff)
		{
			free(byDestbuff);
			byDestbuff=NULL;
		}

		if(!ResolveImportsMOV(&byImportbuff,dwImportSize,dwImportOffset+0x01,byFullFilebuff))
		{
			if(byImportbuff)
			{
				free(byImportbuff);
				byImportbuff=NULL;
			}
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		if(m_dwOffset+0xA1+0x06>m_objTempFile.m_dwFileSize)
		{
			if(byImportbuff)
			{
				free(byImportbuff);
				byImportbuff=NULL;
			}
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}


	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=m_dwOffset+0xA1+*(DWORD*)&byFullFilebuff[m_dwOffset+0xA1+0x02]+0x06;
     
	}

	*(WORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NumberOfSections]=m_objTempFile.m_stPEHeader.NumberOfSections+1;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=/**/(m_objTempFile.m_dwFileSize);


	//Writing the complete buffer back to file
	if(!m_objTempFile.WriteBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(byFullFilebuff)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
	}

	if(dwImportSize!=0x00)
	{
		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			free(byImportbuff);
			byImportbuff=NULL;
			return false;
		}

		//Adding a new Section
		if(!AddNewSection(dwImportSize,1))
		{
			free(byImportbuff);
			byImportbuff=NULL;
			return false;
		}

		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			free(byImportbuff);
			byImportbuff=NULL;
			return false;
		}

		//Writing the basic Import Directory Table buffer to memory
		if(!m_objTempFile.WriteBuffer(byImportbuff, /**/(m_objTempFile.m_dwFileSize), dwImportSize, dwImportSize))
		{
			free(byImportbuff);
			byImportbuff=NULL;
			return false;
		}	

		if(byImportbuff)
		{
			free(byImportbuff);
			byImportbuff=NULL;
		}

	}
	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	if(!ReOrganizeFile(szTempFileName, false))
	{
		return false;
	}

	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	if(!m_objTempFile.CalculateImageSize())
	{
		return false;
	}

	return true;
}



bool CFSGUnpacker::ResolveImportsMOV(BYTE **byImportbuff, DWORD &dwImportSize, DWORD dwImportOffset,BYTE *byFullFilebuff)
{
	*byImportbuff=new BYTE[1];
	DWORD dwWriteAPIRVACounter=0;
	while(1)
	{
		if(dwImportOffset+0x04>m_objTempFile.m_dwFileSize)
		{
			return false;
		}

		if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,dwImportSize+0x14)))
		{
			return false;
		}
		memset(&(*byImportbuff)[dwImportSize],0,0x14);
		*(DWORD*)&(*byImportbuff)[dwImportSize+0x10]=*(DWORD*)&byFullFilebuff[dwImportOffset]-m_dwImageBase;
		*(DWORD*)&(*byImportbuff)[dwImportSize+0x0C]=dwImportOffset+0x04;
		dwImportOffset+=0x04;
		
		if(dwImportOffset+0x01>m_objTempFile.m_dwFileSize)
		{
			return false;
		}

		while(byFullFilebuff[dwImportOffset]!=0x00)
		{
			dwImportOffset++;
			if(dwImportOffset+0x01>m_objTempFile.m_dwFileSize)
			{
				return false;
			}
		}
		dwImportOffset++;

		if(dwImportOffset+0x01>m_objTempFile.m_dwFileSize)
		{
			return false;
		}


		dwWriteAPIRVACounter=0;
		while(byFullFilebuff[dwImportOffset]!=0x01)
		{
			byFullFilebuff[dwImportOffset]-=0x01;
			
			if(byFullFilebuff[dwImportOffset]==0x01)
			{
				dwImportSize+=0x14;
				if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,SA(dwImportSize+0x14))))
				{
					return false;
				}
				memset(&(*byImportbuff)[dwImportSize],0,SA(dwImportSize+0x14)-dwImportSize);
				dwImportSize=SA(dwImportSize+0x14);
				return true;
			}

			if((byFullFilebuff[dwImportOffset]&0x80)==0x80)
			{
				if(dwImportOffset+0x01+0x04>m_objTempFile.m_dwFileSize)
				{
					return false;
				}
				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportbuff)[dwImportSize+0x10]+dwWriteAPIRVACounter]=*(DWORD*)&byFullFilebuff[dwImportOffset+0x01]|IMAGE_ORDINAL_FLAG32;
				dwImportOffset+=0x01;
				dwImportOffset+=0x04;
			}
			else
			{
				if(dwImportOffset+0x01>m_objTempFile.m_dwFileSize)
				{
					return false;
				}
				byFullFilebuff[dwImportOffset]-=0x01;
				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportbuff)[dwImportSize+0x10]+dwWriteAPIRVACounter]=dwImportOffset-2;
	
				while(byFullFilebuff[dwImportOffset]!=0x00)
				{
					dwImportOffset++;
					if(dwImportOffset+0x01>m_objTempFile.m_dwFileSize)
					{
						return false;
					}
				}
			}
			dwImportOffset++;
			if(*(DWORD*)&(*byImportbuff)[dwImportSize+0x0C]+dwWriteAPIRVACounter+0x04>m_objTempFile.m_dwFileSize)
			{
				return false;
			}
			dwWriteAPIRVACounter+=0x04;
		}
		dwImportOffset+=0x01;
		dwImportSize+=0x14;
	}
}


bool CFSGUnpacker::ResolveImports(BYTE **byImportbuff, DWORD &dwImportSize, DWORD dwImportOffset,BYTE *byFullFilebuff)
{
	*byImportbuff=new BYTE[1];
	DWORD dwWriteAPIRVACounter=0;
	while(1)
	{
		if(m_pStructDecompressBlockInfo->ImportOffset+0x08>m_objTempFile.m_dwFileSize)
		{
			return false;
		}

		if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,dwImportSize+0x14)))
		{
			return false;
		}
		memset(&(*byImportbuff)[dwImportSize],0,0x14);
		*(DWORD*)&(*byImportbuff)[dwImportSize+0x10]=*(DWORD*)&byFullFilebuff[m_pStructDecompressBlockInfo->ImportOffset]-m_dwImageBase;
		*(DWORD*)&(*byImportbuff)[dwImportSize+0x0C]=*(DWORD*)&byFullFilebuff[m_pStructDecompressBlockInfo->ImportOffset+0x04]-m_dwImageBase;
		dwImportOffset=*(DWORD*)&(*byImportbuff)[dwImportSize+0x10];
		
		if(dwImportOffset+0x04>m_objTempFile.m_dwFileSize)
		{
			return false;
		}

		dwWriteAPIRVACounter=0;
		while(*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]!=0x7FFFFFFF)
		{
			if(*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]==0xFFFFFFFF)
			{
				*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]=0x00;
				dwImportSize+=0x14;
				if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,SA(dwImportSize+0x14))))
				{
					return false;
				}
				memset(&(*byImportbuff)[dwImportSize],0,SA(dwImportSize+0x14)-dwImportSize);
				dwImportSize=SA(dwImportSize+0x14);
				return true;
			}
			if(*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]<m_dwImageBase)
			{
				*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]+=1;
				*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]|=IMAGE_ORDINAL_FLAG32;
			}
			else
			{
				*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]-=m_dwImageBase+1;
			}
			if(dwImportOffset+dwWriteAPIRVACounter+0x04>m_objTempFile.m_dwFileSize)
			{
				return false;
			}
			dwWriteAPIRVACounter+=0x04;
		}	
		*(DWORD*)&byFullFilebuff[dwImportOffset+dwWriteAPIRVACounter]=0x00;
		m_pStructDecompressBlockInfo->ImportOffset+=0x08;
		dwImportSize+=0x14;
	}
}