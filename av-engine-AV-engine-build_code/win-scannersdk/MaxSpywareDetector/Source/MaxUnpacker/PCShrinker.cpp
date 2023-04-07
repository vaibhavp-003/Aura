#include "PCShrinker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CPCShrinkerUnpacker::CPCShrinkerUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{	
	m_pStructDecompressInfo=NULL;
	m_pStructSimpleMoveInfo=NULL;
}

CPCShrinkerUnpacker::~CPCShrinkerUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CPCShrinkerUnpacker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		(m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) && 
		(memcmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Name,"pcs",0x03)==0) )
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}

		if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pMaxPEFile->m_dwAEPMapped, 0x22,0x22))
		{
			if( m_pbyBuff[0]==0x9C && *(WORD*)&m_pbyBuff[1]==0xBD60 && *(WORD*)&m_pbyBuff[7]==0xAD01 &&
				*(WORD*)&m_pbyBuff[0xD]==0xB5FF && *(WORD*)&m_pbyBuff[0x13]==0x406A )
			{
				return true;
			}
		}
	}
	
	return false;
}


bool CPCShrinkerUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName))
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

	DWORD dwOffset=*(DWORD*)&m_pbyBuff[0xF]+*(DWORD*)&m_pbyBuff[0x3]-m_dwImageBase;

	if(dwOffset+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwEBPOffset=*(DWORD*)&m_pbyBuff[0x1E];
	DWORD dwBuffSizeALLOperations=*(DWORD*)&byFullFilebuff[dwOffset];
	

	dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x22+0x17;

	if(dwOffset-0x09+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwSrcSize=*(DWORD*)&byFullFilebuff[dwOffset-0x9]*0x04;

	if(dwOffset+0xF+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	
	dwSrcSize-=*(DWORD*)&byFullFilebuff[dwOffset+0x9];
	dwEBPOffset+=*(DWORD*)&byFullFilebuff[dwOffset+0x9];
    dwBuffSizeALLOperations-=*(DWORD*)&byFullFilebuff[dwOffset+0x9];
	dwOffset+=*(DWORD*)&byFullFilebuff[dwOffset+0x9];

	BYTE *byDestbuff=NULL;

	if(!(byDestbuff=(BYTE*)MaxMalloc(dwBuffSizeALLOperations)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwLoaderDestSize=0;

	if(dwOffset+dwSrcSize>m_objTempFile.m_dwFileSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(!(~(dwLoaderDestSize=APLIBDecompress(dwSrcSize,dwBuffSizeALLOperations,0,0,byDestbuff,1,&byFullFilebuff[dwOffset]))))
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(dwOffset<0x08 || dwLoaderDestSize<0x04)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwOffset=*(DWORD*)&byDestbuff[0x3]-dwEBPOffset;

	NoDecompressCompareInfo *m_pStructNoDecompressCompareInfo=(NoDecompressCompareInfo*)&byDestbuff[dwOffset-0x08];

	if(dwOffset+sizeof(DecompressInfo)>dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//Actual Decompression
	DWORD dwActualDestSize=0;
	while(*(DWORD*)&byDestbuff[dwOffset]!=0x00)
	{
		m_pStructDecompressInfo=(DecompressInfo*)&byDestbuff[dwOffset];

		if(m_pStructNoDecompressCompareInfo->dwRVA==m_pStructDecompressInfo->dwSrcRVA)
		{
			m_pStructDecompressInfo->dwSrcRVA+=m_pStructNoDecompressCompareInfo->dwSize;
			m_pStructDecompressInfo->dwSrcSize-=m_pStructNoDecompressCompareInfo->dwSize;
		}

		if(m_pStructDecompressInfo->dwSrcRVA-m_dwImageBase+dwSrcSize>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		//APLIB Decompression
		if(!(~(dwActualDestSize=APLIBDecompress(m_pStructDecompressInfo->dwSrcSize,dwBuffSizeALLOperations-dwLoaderDestSize,0,0,&byDestbuff[dwLoaderDestSize],1,&byFullFilebuff[m_pStructDecompressInfo->dwSrcRVA-m_dwImageBase]))))
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(m_pStructDecompressInfo->dwSrcRVA-m_dwImageBase+dwActualDestSize>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		//Writing back decompressed data to buffer
		for(DWORD i=0;i<dwActualDestSize;i++)
		{
			byFullFilebuff[m_pStructDecompressInfo->dwSrcRVA-m_dwImageBase+i]=byDestbuff[dwLoaderDestSize+i];
		}

		//Incrementing by 8 to go to next offset
		dwOffset+=sizeof(DecompressInfo);

		if(dwOffset+sizeof(DecompressInfo)>dwBuffSizeALLOperations)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
	}

	//Simple Move Code and Fill With Zeroes
	dwOffset=0xE;

	if(dwOffset+0x01 > dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwOffset+=byDestbuff[dwOffset]+0x01;

	dwOffset+=0x05;
	if(dwOffset+sizeof(DWORD)>dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwOffset=*(DWORD*)&byDestbuff[dwOffset]-dwEBPOffset;

	if(dwOffset+sizeof(SimpleMoveInfo)>dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	while(*(DWORD*)&byDestbuff[dwOffset]!=0x00)
	{
		m_pStructSimpleMoveInfo=(SimpleMoveInfo*)&byDestbuff[dwOffset];
		m_pStructSimpleMoveInfo->dwSrcRVA-=m_dwImageBase;
		m_pStructSimpleMoveInfo->dwDestRVA-=m_dwImageBase;
		if(m_pStructSimpleMoveInfo->dwSrcRVA+m_pStructSimpleMoveInfo->dwSize>m_objTempFile.m_dwFileSize ||
			m_pStructSimpleMoveInfo->dwDestRVA+m_pStructSimpleMoveInfo->dwSize+m_pStructSimpleMoveInfo->dwFillWithZeroSize>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(m_pStructSimpleMoveInfo->dwSrcRVA < m_pStructSimpleMoveInfo->dwDestRVA &&
		   m_pStructSimpleMoveInfo->dwSrcRVA+m_pStructSimpleMoveInfo->dwSize > m_pStructSimpleMoveInfo->dwDestRVA)
		{
			if(m_pStructSimpleMoveInfo->dwSize >dwBuffSizeALLOperations)
			{
				if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_pStructSimpleMoveInfo->dwSize)))
				{
					free(byDestbuff);
					byDestbuff=NULL;
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}
			
				dwBuffSizeALLOperations=m_pStructSimpleMoveInfo->dwSize;
			}

			for(DWORD i=0;i<m_pStructSimpleMoveInfo->dwSize;i++)
			{
				byDestbuff[dwLoaderDestSize+i]=byFullFilebuff[m_pStructSimpleMoveInfo->dwSrcRVA+i];
			}

			for(DWORD i=0;i<m_pStructSimpleMoveInfo->dwSize;i++)
			{
				byFullFilebuff[m_pStructSimpleMoveInfo->dwDestRVA+i]=byDestbuff[dwLoaderDestSize+i];
			}
		}
		else
		{
			//Writing back decompressed data to buffer
			for(DWORD i=0;i<m_pStructSimpleMoveInfo->dwSize;i++)
			{
				byFullFilebuff[m_pStructSimpleMoveInfo->dwDestRVA+i]=byFullFilebuff[m_pStructSimpleMoveInfo->dwSrcRVA+i];
			}
		}

		for(DWORD i=0;i<m_pStructSimpleMoveInfo->dwFillWithZeroSize;i++)
		{
			byFullFilebuff[m_pStructSimpleMoveInfo->dwDestRVA+m_pStructSimpleMoveInfo->dwSize+i]=0x0;
		}

		m_pStructSimpleMoveInfo->dwFillWithZeroSize=m_pStructSimpleMoveInfo->dwSize;

		if(m_pStructSimpleMoveInfo->dwSrcRVA>m_pStructSimpleMoveInfo->dwDestRVA &&
			m_pStructSimpleMoveInfo->dwDestRVA+m_pStructSimpleMoveInfo->dwSize>m_pStructSimpleMoveInfo->dwSrcRVA)
		{
			m_pStructSimpleMoveInfo->dwFillWithZeroSize=m_pStructSimpleMoveInfo->dwSrcRVA-m_pStructSimpleMoveInfo->dwDestRVA;
			m_pStructSimpleMoveInfo->dwSrcRVA=m_pStructSimpleMoveInfo->dwDestRVA+m_pStructSimpleMoveInfo->dwSize;
		}
		else if(m_pStructSimpleMoveInfo->dwSrcRVA<m_pStructSimpleMoveInfo->dwDestRVA &&
			m_pStructSimpleMoveInfo->dwSrcRVA+m_pStructSimpleMoveInfo->dwSize>m_pStructSimpleMoveInfo->dwDestRVA)
		{
			m_pStructSimpleMoveInfo->dwFillWithZeroSize=m_pStructSimpleMoveInfo->dwDestRVA-m_pStructSimpleMoveInfo->dwSrcRVA;
		}

		for(DWORD i=0;i<m_pStructSimpleMoveInfo->dwFillWithZeroSize;i++)
		{
			byFullFilebuff[m_pStructSimpleMoveInfo->dwSrcRVA+i]=0x0;
		}


		//Incrementing by 8 to go to next offset
		dwOffset+=sizeof(SimpleMoveInfo);

		if(dwOffset+sizeof(SimpleMoveInfo)>dwBuffSizeALLOperations)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
	}

	dwOffset=0xE;
	dwOffset+=byDestbuff[dwOffset]+0x01;
	dwOffset+=0x0D;

	if(dwOffset+0x01>dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwOffset+=byDestbuff[dwOffset]+0x01;


	if(dwOffset+0x05 > dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwOffset+=*(DWORD*)&byDestbuff[dwOffset+1]+0x05;


	if(dwOffset+0x6 > dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(*(DWORD*)&byDestbuff[dwOffset+2]-dwEBPOffset+0x04 > dwBuffSizeALLOperations)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=*(DWORD*)&byDestbuff[dwOffset-0x06]-m_dwImageBase;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=*(DWORD*)&byDestbuff[*(DWORD*)&byDestbuff[dwOffset+2]-dwEBPOffset];

	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff=NULL;
	}

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

	return true;
}
