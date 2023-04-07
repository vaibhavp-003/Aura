#include "KbyshooUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CKbyshooUnpacker::CKbyshooUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{	
	m_pStructDecompressInfo=NULL;
	m_pStructMoveBytesInfo=NULL;
}

CKbyshooUnpacker::~CKbyshooUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CKbyshooUnpacker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		(m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) && 
		(memcmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Name,".shooo",0x06)==0) )
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}

		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x12,0x12))
		{
			return false;
		}

		if(m_pbyBuff[0]==0xB8 && m_pbyBuff[0x5]==0xBA && *(DWORD*)&m_pbyBuff[0xA]==0xE0FFC203)
		{
			return true;
		}
	}
	return false;	
}


bool CKbyshooUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName,true,false))
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
	DWORD dwOffset=*(DWORD*)&m_pbyBuff[0xE];

	if(dwOffset+sizeof(DecompressInfo) > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	BYTE byStructDecompressInfo[sizeof(DecompressInfo)]={0};
	memcpy(byStructDecompressInfo,&byFullFilebuff[dwOffset],sizeof(DecompressInfo));

	m_pStructDecompressInfo=(DecompressInfo*)&byStructDecompressInfo;

	BYTE byLZMAProp[0x04]={0};
	byLZMAProp[0]=0x5D;
	BYTE *byDestbuff=NULL;
	if(!(byDestbuff=(BYTE*)MaxMalloc(m_pStructDecompressInfo->dwDestSize)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwDestSize;
	if(!(dwDestSize = LZMADecompress(byLZMAProp, m_pStructDecompressInfo->dwSrcSize, m_pStructDecompressInfo->dwDestSize, 0x00, 0x00, byDestbuff,&byFullFilebuff[m_pStructDecompressInfo->dwSrvRVA])))
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(m_pStructDecompressInfo->dwOffsettoStartResolve+(0x180*0x04)>m_objTempFile.m_dwFileSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//Fill this area with zeroes
	for(DWORD i=0;i<0x180;i++)
	{
		*(DWORD*)&byFullFilebuff[m_pStructDecompressInfo->dwOffsettoStartResolve+i*0x04]=0x00;
	}

	dwOffset=0;
	if(dwOffset+1>m_pStructDecompressInfo->dwDestSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwMoveBytesCounter=byDestbuff[dwOffset];

	dwOffset=1;	


	for(DWORD i=0;i<dwMoveBytesCounter;i++)
	{
		if(dwOffset+sizeof(MoveBytesInfo)>m_pStructDecompressInfo->dwDestSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		m_pStructMoveBytesInfo=(MoveBytesInfo*)&byDestbuff[dwOffset];
		dwOffset+=sizeof(MoveBytesInfo);

		if(dwOffset+m_pStructMoveBytesInfo->dwSize>m_pStructDecompressInfo->dwDestSize ||
		   m_pStructMoveBytesInfo->dwDestRVA+m_pStructMoveBytesInfo->dwSize>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;			
		}

		for(DWORD j=0;j<m_pStructMoveBytesInfo->dwSize;j++)
		{
			byFullFilebuff[m_pStructMoveBytesInfo->dwDestRVA+j]=byDestbuff[dwOffset+j];
		}

		dwOffset+=m_pStructMoveBytesInfo->dwSize;
	}

	if(!ResolveCalls(byFullFilebuff,m_pStructDecompressInfo->ResolveCallsCounter,m_pStructDecompressInfo->dwBytetoCompareResolve))
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;	
	}

	BYTE *byImportbuff=NULL;
	DWORD dwImportSize=0;

	if(!ResolveImports(&byImportbuff,byDestbuff,byFullFilebuff,dwOffset,&dwImportSize))
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		if(byImportbuff)
		{
			free(byImportbuff);
			byImportbuff=NULL;
		}
		return false;	

	}

	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff=NULL;
	}

	*(WORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NumberOfSections]=m_objTempFile.m_stPEHeader.NumberOfSections+1;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=/**/(m_objTempFile.m_dwFileSize);
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=m_pStructDecompressInfo->dwAEP;

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



bool CKbyshooUnpacker::ResolveCalls(BYTE *byBuff,DWORD dwCallsCounter,DWORD dwByteToCompare)
{
	for(DWORD dwCounter=0;dwCounter+m_pStructDecompressInfo->dwOffsettoStartResolve<=m_objTempFile.m_dwFileSize-0x05 && dwCallsCounter>0;dwCounter++)
	{
		if(byBuff[dwCounter+m_pStructDecompressInfo->dwOffsettoStartResolve]==0xE8 || byBuff[dwCounter+m_pStructDecompressInfo->dwOffsettoStartResolve]==0xE9)
		{
			if(byBuff[dwCounter+1+m_pStructDecompressInfo->dwOffsettoStartResolve]==BYTE(dwByteToCompare))
			{
				byBuff[dwCounter+1+m_pStructDecompressInfo->dwOffsettoStartResolve]=0;
				*(DWORD*)&byBuff[dwCounter+1+m_pStructDecompressInfo->dwOffsettoStartResolve]=ntohl(*(DWORD*)&byBuff[dwCounter+1+m_pStructDecompressInfo->dwOffsettoStartResolve]);
				*(DWORD*)&byBuff[dwCounter+1+m_pStructDecompressInfo->dwOffsettoStartResolve]-=(dwCounter+1);
				dwCounter+=0x04;
				dwCallsCounter--;
			}
		}
	}
	return true;
}


bool CKbyshooUnpacker::ResolveImports(BYTE **byImportbuff,BYTE *byDestbuff,BYTE *byFullFilebuff,DWORD dwDestbuffOffset,DWORD *dwImportSize)
{
	BYTE *byImportAPIbuff=NULL;
	DWORD dwAPIRVAOffsets=0;
	DWORD dwAPIWritingOffsets=0;
	DWORD dwSize=m_objTempFile.m_stPEHeader.SectionAlignment;
	DWORD dwActualImportSize=0x0;
	DWORD dwActualDLLSize=0;
	DWORD dwIndividualDLLAPISize=0;
	if(!(*byImportbuff=(BYTE*)MaxMalloc(1)))
	{
		return false;
	}

	if(!(byImportAPIbuff=(BYTE*)MaxMalloc(dwSize)))
	{
		return false;
	}

	memset(byImportAPIbuff,0,dwSize);

	if(dwDestbuffOffset+0x04 > m_pStructDecompressInfo->dwDestSize)
	{
		free(byImportAPIbuff);
		byImportAPIbuff=NULL;
		return false;
	}

	while(*(DWORD*)&byDestbuff[dwDestbuffOffset]!=0x00)
	{
		if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,dwActualDLLSize+0x14)))
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}
		memset(&((*byImportbuff)[dwActualDLLSize]),0,0x14);
		dwActualDLLSize+=0x14;
		
		if(dwDestbuffOffset+0x05 > m_pStructDecompressInfo->dwDestSize)
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}

		*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x08])=dwAPIWritingOffsets;
		*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])=*(DWORD*)&byDestbuff[dwDestbuffOffset];

		dwDestbuffOffset+=0x04;


	    dwIndividualDLLAPISize=0;
		while(byDestbuff[dwDestbuffOffset+dwIndividualDLLAPISize]!=0x00)
		{
			dwIndividualDLLAPISize++;
			if(dwDestbuffOffset+dwIndividualDLLAPISize>m_pStructDecompressInfo->dwDestSize)
			{
				free(byImportAPIbuff);
				byImportAPIbuff=NULL;
				return false;
			}
		}

		while(dwAPIWritingOffsets+dwIndividualDLLAPISize+1>dwSize)
		{
			if(!(byImportAPIbuff=(BYTE*)realloc(byImportAPIbuff,dwSize+m_objTempFile.m_stPEHeader.SectionAlignment)))
			{
				free(byImportAPIbuff);
				byImportAPIbuff=NULL;
				return false;
			}
			memset(byImportAPIbuff,0,m_objTempFile.m_stPEHeader.SectionAlignment);
			dwSize+=m_objTempFile.m_stPEHeader.SectionAlignment;
		}

		memcpy(&byImportAPIbuff[dwAPIWritingOffsets],&byDestbuff[dwDestbuffOffset],dwIndividualDLLAPISize);
		dwAPIWritingOffsets+=dwIndividualDLLAPISize;
		dwDestbuffOffset+=dwIndividualDLLAPISize;
		byImportAPIbuff[dwAPIWritingOffsets]=0;
		dwAPIWritingOffsets+=1;
		dwDestbuffOffset++;


		if(dwDestbuffOffset+0x04 > m_pStructDecompressInfo->dwDestSize)
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}
		dwAPIRVAOffsets=0;

		while(*(DWORD*)&byDestbuff[dwDestbuffOffset]!=0x00)
		{
			if((*(DWORD*)&byDestbuff[dwDestbuffOffset]&IMAGE_ORDINAL_FLAG32)==IMAGE_ORDINAL_FLAG32)
			{
				if(*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])+dwAPIRVAOffsets+0x04>m_objTempFile.m_dwFileSize)
				{
					free(byImportAPIbuff);
					byImportAPIbuff=NULL;
					return false;
				}
				*(DWORD*)&byFullFilebuff[*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])+dwAPIRVAOffsets]=*(DWORD*)&byDestbuff[dwDestbuffOffset];
				dwDestbuffOffset+=0x04;
			}
			else
			{
				dwIndividualDLLAPISize=0;
				while(byDestbuff[dwDestbuffOffset+dwIndividualDLLAPISize]!=0x00)
				{
					dwIndividualDLLAPISize++;
					if(dwDestbuffOffset+dwIndividualDLLAPISize>m_pStructDecompressInfo->dwDestSize)
					{
						free(byImportAPIbuff);
						byImportAPIbuff=NULL;
						return false;
					}

				}

				while(dwAPIWritingOffsets+dwIndividualDLLAPISize+2>dwSize)
				{
					if(!(byImportAPIbuff=(BYTE*)realloc(byImportAPIbuff,dwSize+m_objTempFile.m_stPEHeader.SectionAlignment)))
					{
						free(byImportAPIbuff);
						byImportAPIbuff=NULL;
						return false;
					}
					memset(&byImportAPIbuff[dwSize],0,m_objTempFile.m_stPEHeader.SectionAlignment);
					dwSize+=m_objTempFile.m_stPEHeader.SectionAlignment;
				}

				*(WORD*)&byImportAPIbuff[dwAPIWritingOffsets]=0;
				memcpy(&byImportAPIbuff[dwAPIWritingOffsets+2],&byDestbuff[dwDestbuffOffset],dwIndividualDLLAPISize);
				if(*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])+dwAPIRVAOffsets+0x04>m_objTempFile.m_dwFileSize)
				{
					free(byImportAPIbuff);
					byImportAPIbuff=NULL;
					return false;
				}
				*(DWORD*)&byFullFilebuff[*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])+dwAPIRVAOffsets]=dwAPIWritingOffsets;


				dwAPIWritingOffsets+=dwIndividualDLLAPISize;
				dwDestbuffOffset+=dwIndividualDLLAPISize;

				dwAPIWritingOffsets+=2;
				dwDestbuffOffset++;
			}


			dwAPIRVAOffsets+=0x04;

			if(dwDestbuffOffset+0x04 > m_pStructDecompressInfo->dwDestSize)
			{
				free(byImportAPIbuff);
				byImportAPIbuff=NULL;
				return false;
			}
		}
		
		
		*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x0C])=dwAPIRVAOffsets/0x04;
		dwAPIWritingOffsets+=1;
		dwDestbuffOffset+=0x04;
		if(dwDestbuffOffset+0x04 > m_pStructDecompressInfo->dwDestSize)
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}

	}


	if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,dwActualDLLSize+0x14)))
	{
		return false;
	}
	memset(&((*byImportbuff)[dwActualDLLSize]),0,0x14);
	dwActualDLLSize+=0x14;

	DWORD dwCounter=(dwActualDLLSize/0x14)-1;
	while(dwCounter>0)
	{
		*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x08])+=dwActualDLLSize+m_objTempFile.m_dwFileSize;
		for(;*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x0C])>0;(*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x0C]))--)
		{
			*(DWORD*)&byFullFilebuff[*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x04])+(*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x0C])-1)*0x04]+=dwActualDLLSize+m_objTempFile.m_dwFileSize;
		}
		dwCounter--;
	}


	*dwImportSize=SA(dwActualDLLSize+dwAPIWritingOffsets);
	if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,*dwImportSize)))
	{
		free(byImportAPIbuff);
		byImportAPIbuff=NULL;
		return false;
	}

	memcpy(&((*byImportbuff)[dwActualDLLSize]),byImportAPIbuff,dwAPIWritingOffsets);
	memset(&((*byImportbuff)[dwActualDLLSize+dwAPIWritingOffsets]),0,*dwImportSize-(dwActualDLLSize+dwAPIWritingOffsets));
	if(byImportAPIbuff)
	{
		free(byImportAPIbuff);
		byImportAPIbuff=NULL;
	}

	return true;
}
