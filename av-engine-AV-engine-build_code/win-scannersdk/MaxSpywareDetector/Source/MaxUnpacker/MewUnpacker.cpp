#include "MewUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CMewUnpacker::CMewUnpacker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
	m_pStructLZMABlockInfo=NULL;
}

CMewUnpacker::~CMewUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
	m_pStructLZMABlockInfo=NULL;
}

bool CMewUnpacker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(m_pMaxPEFile->m_dwAEPMapped < m_pMaxPEFile->m_stPEHeader.SizeOfHeaders || 
		m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) &&
		((m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData==0x00)||m_iCurrentLevel>0))
	{
		m_dwOffset=m_pMaxPEFile->m_dwAEPMapped;
		if(m_dwOffset<m_pMaxPEFile->m_stPEHeader.SizeOfHeaders)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
			m_dwOffset+=CUnpackBase::m_iDataCnt*0x28;
			
		}

		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwOffset,0x0E,0x0E))
		{
			return false;
		}

		if(m_pbyBuff[0]==0xE9)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&m_pbyBuff[1]+0x05;
			if(m_dwOffset>m_pMaxPEFile->m_stPEHeader.SizeOfHeaders)
			{
				return false;
			}
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwOffset,0xE,0xE))
			{
				return false;
			}
		}
		if(m_pbyBuff[0]==0xBE && *(WORD*)&m_pbyBuff[0x05]==0xDE8B && *(DWORD*)&m_pbyBuff[0x07]==0xAD50ADAD && m_pbyBuff[0xB]==0x97 && *(WORD*)&m_pbyBuff[0xC]==0x80B2)
		{
			return true;
		}
	}
	return false;
}

bool CMewUnpacker::Unpack(LPCTSTR szTempFileName)
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

	DWORD dwOffsetInFile=*(DWORD*)&m_pbyBuff[0x01];
	dwOffsetInFile-=m_dwImageBase;
	
	if(dwOffsetInFile+0x0C>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=*(DWORD*)&byFullFilebuff[dwOffsetInFile+0x04]-m_dwImageBase;
	dwOffsetInFile+=0x08;
	DWORD dwSrcSize=0;
	DWORD dwDestSize=0;
	DWORD dwDestSizeAllocated=m_objTempFile.m_dwFileSize-(*(DWORD*)&byFullFilebuff[dwOffsetInFile]-m_dwImageBase);
	DWORD dwRVADest=0;
	BYTE *byDestbuff=NULL;

	if(!(byDestbuff=(BYTE*)MaxMalloc(dwDestSizeAllocated)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	while(*(DWORD*)&byFullFilebuff[dwOffsetInFile]!=0x00)
	{
		dwSrcSize=m_objTempFile.m_dwFileSize-(dwOffsetInFile+0x04);
		dwRVADest=*(DWORD*)&byFullFilebuff[dwOffsetInFile]-m_dwImageBase;
		if(dwRVADest > m_objTempFile.m_dwFileSize)
		{
			if(byDestbuff)
			{
				free(byDestbuff);
				byDestbuff=NULL;
			}
			if(byFullFilebuff)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
			}
			return false;
		}

		if(dwSrcSize + dwOffsetInFile > m_objTempFile.m_dwFileSize)
		{
			if(byDestbuff)
			{
				free(byDestbuff);
				byDestbuff=NULL;
			}
			if(byFullFilebuff)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
			}
			return false;
		}

		dwDestSize=m_objTempFile.m_dwFileSize-dwRVADest;
		dwOffsetInFile+=0x04;	
		
		memset(byDestbuff,0,dwDestSize);

		if(!(~(dwDestSize=APLIBDecompress(dwSrcSize,dwDestSize,0,0,byDestbuff,0,&byFullFilebuff[dwOffsetInFile],&dwSrcSize))))
		{
			if(byDestbuff)
			{
				free(byDestbuff);
				byDestbuff=NULL;
			}
			if(byFullFilebuff)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
			}
			return false;
		}

		if(dwRVADest + dwDestSize > m_objTempFile.m_dwFileSize)
		{
			if(byDestbuff)
			{
				free(byDestbuff);
				byDestbuff=NULL;
			}
			if(byFullFilebuff)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
			}
			return false;
		}

		for(DWORD i=0;i<dwDestSize;i++)
		{
			byFullFilebuff[dwRVADest+i]=byDestbuff[i];
		}
		dwOffsetInFile+=dwSrcSize;

		if(dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
		{
			if(byDestbuff)
			{
				free(byDestbuff);
				byDestbuff=NULL;
			}
			if(byFullFilebuff)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
			}
			return false;
		}
	}

	m_dwOffset+=CUnpackBase::m_iDataCnt*0x28;
	m_dwOffset+=0x7B;

	if(m_dwOffset+0x01>m_objTempFile.m_dwFileSize)
	{
		if(byDestbuff)
		{
			free(byDestbuff);
			byDestbuff=NULL;
		}
		if(byFullFilebuff)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
		}
		return false;
	}

	dwOffsetInFile+=0x04;
	if(byFullFilebuff[m_dwOffset]==0xE8) //LZMA Decompression to be performed
	{
		if(dwOffsetInFile+0x11>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		dwOffsetInFile+=0x04;
		m_pStructLZMABlockInfo=(LZMABlockInfo*)&byFullFilebuff[dwOffsetInFile];
		if(m_pStructLZMABlockInfo->dwDestSize>m_dwImageBase)
		{
			m_pStructLZMABlockInfo=(LZMABlockInfo*)&byFullFilebuff[dwOffsetInFile+0x04];
			dwOffsetInFile+=0x04;
		}
		m_pStructLZMABlockInfo->dwDestRVA-=m_dwImageBase;

		if(m_pStructLZMABlockInfo->dwDestSize>dwDestSizeAllocated)
		{
			if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_pStructLZMABlockInfo->dwDestSize)))
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			memset(byDestbuff,0,m_pStructLZMABlockInfo->dwDestSize);
		}

		BYTE byLZMAProp[0x04]={0};
		byLZMAProp[0]=0x5E;
		dwOffsetInFile+=sizeof(LZMABlockInfo)+1;
		if(!(m_pStructLZMABlockInfo->dwDestSize=LZMADecompress(byLZMAProp,m_pStructLZMABlockInfo->dwSrcSize,m_pStructLZMABlockInfo->dwDestSize,0,0,byDestbuff,&byFullFilebuff[dwOffsetInFile])))
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		dwOffsetInFile+=m_pStructLZMABlockInfo->dwSrcSize;

		if(dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(*(DWORD*)&byFullFilebuff[dwOffsetInFile]==0x00)
		{
			dwOffsetInFile+=0x04;
		}
		else
		{
			if(!ResolveCalls(byDestbuff,m_pStructLZMABlockInfo->dwDestSize))
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
		}

		for(DWORD i=0;i<m_pStructLZMABlockInfo->dwDestSize;i++)
		{
			byFullFilebuff[m_pStructLZMABlockInfo->dwDestRVA+i]=byDestbuff[i];
		}
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


	BYTE *byImportbuff=NULL;
	DWORD dwImportSize=0;

	if(!ResolveImports(&byImportbuff,dwImportSize,*(DWORD*)&byFullFilebuff[dwOffsetInFile]-m_dwImageBase,byFullFilebuff))
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

bool CMewUnpacker::ResolveCalls(BYTE *bybuff, DWORD dwSize)
{
	for(DWORD i=0;i<=(dwSize-0x05);i++)
	{
		if(bybuff[i]==0xE8 || bybuff[i]==0xE9)
		{
			*(DWORD*)&bybuff[i+1]=ntohl(*(DWORD*)&bybuff[i+1]);
			*(DWORD*)&bybuff[i+1]-=(i+1);
			i+=0x04;
		}

	}
	return true;
}

bool CMewUnpacker::ResolveImports(BYTE **byImportbuff, DWORD &dwImportSize, DWORD dwImportOffset,BYTE *byFullFilebuff)
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
		dwImportOffset+=0x04;
		*(DWORD*)&(*byImportbuff)[dwImportSize+0xC]=dwImportOffset;
		
		

		if(dwImportOffset+1>m_objTempFile.m_dwFileSize)
		{
			return false;
		}

		while(byFullFilebuff[dwImportOffset]!=0x00)
		{
			if(dwImportOffset+1>m_objTempFile.m_dwFileSize)
			{
				return false;
			}
			dwImportOffset++;			
		}
		dwImportOffset++;

		if(dwImportOffset+4>m_objTempFile.m_dwFileSize)
		{
			return false;			
		}
		//true condition to exit
		dwWriteAPIRVACounter=0;
		while(*(DWORD*)&byFullFilebuff[dwImportOffset]!=0xFFFFFFFF)
		{
			if(ntohl(*(DWORD*)&byFullFilebuff[dwImportOffset])==0x80000000 || *(DWORD*)&byFullFilebuff[dwImportOffset]==0x00)
			{
				dwImportSize+=0x14;
				if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,SA(dwImportSize+0x14))))
				{
					return false;
				}
				memset(&(*byImportbuff)[dwImportSize],0,SA(dwImportSize+0x14)-(dwImportSize));
				dwImportSize=SA(dwImportSize+0x14);
				return true;
			}
			if(*(DWORD*)&(*byImportbuff)[dwImportSize+0x10]+dwWriteAPIRVACounter+0x04>m_objTempFile.m_dwFileSize)
			{
				return false;	
			}
			if((byFullFilebuff[dwImportOffset]&0x80)!=0x80)
			{
				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportbuff)[dwImportSize+0x10]+dwWriteAPIRVACounter]=(ntohl(*(DWORD*)&byFullFilebuff[dwImportOffset])+1)|IMAGE_ORDINAL_FLAG32;
				dwImportOffset+=0x03;
			}
			else
			{
				
				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportbuff)[dwImportSize+0x10]+dwWriteAPIRVACounter]=dwImportOffset-0x01;
				
				dwImportOffset+=0x01;
				if(dwImportOffset+1>m_objTempFile.m_dwFileSize)
				{
					return false;
				}

				while(byFullFilebuff[dwImportOffset]!=0x00)
				{
					if(dwImportOffset+1>m_objTempFile.m_dwFileSize)
					{
						return false;
					}
					dwImportOffset++;			
				}
			}
			dwImportOffset++;
			dwWriteAPIRVACounter+=0x04;	
			if(dwImportOffset+4>m_objTempFile.m_dwFileSize)
			{
				return false;			
			}
		}
		dwImportOffset+=0x04;
		dwImportSize+=0x14;
	}
}