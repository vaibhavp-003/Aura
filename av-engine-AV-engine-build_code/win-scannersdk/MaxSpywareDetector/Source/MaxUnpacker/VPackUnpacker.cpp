#include "VPackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CVPackUnpacker::CVPackUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{
	m_pStructDecompressInfo=NULL;
	m_pStructBlockDecompressInfo=NULL;
}

CVPackUnpacker::~CVPackUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CVPackUnpacker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		(m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) && 
		(memcmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Name,".Mybr",0x05)==0) )
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}

		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x11,0x11))
		{
			return false;
		}

		if(*(WORD*)&m_pbyBuff[0]==0xE860 && m_pbyBuff[0x6]==0xE8 && m_pbyBuff[0xB]==0xE8 && m_pbyBuff[0x10]==0xC3)
		{
			return true;
		}
	}
	return false;	
}


bool CVPackUnpacker::Unpack(LPCTSTR szTempFileName)
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
	DWORD dwOffset=*(DWORD*)&m_pbyBuff[0xC]+0x10+m_objTempFile.m_stPEHeader.AddressOfEntryPoint;

	dwOffset+=0x23;

	if(dwOffset+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=false;
		return false;
	}
	dwOffset+=*(DWORD*)&byFullFilebuff[dwOffset]+0x04;
	dwOffset+=0x09;

	if(dwOffset+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=false;
		return false;
	}
	dwOffset=*(DWORD*)&byFullFilebuff[dwOffset];

	if(dwOffset+sizeof(DecompressInfo)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	m_pStructDecompressInfo=(DecompressInfo*)&byFullFilebuff[dwOffset];

	if(dwOffset+m_pStructDecompressInfo->dwOffsetofCode+sizeof(BlockDecompressInfo)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	m_pStructBlockDecompressInfo=(BlockDecompressInfo*)&byFullFilebuff[dwOffset+m_pStructDecompressInfo->dwOffsetofCode];
	BYTE *byDestbuff=NULL;
	DWORD dwDestSize=0x1000;

	if(!(byDestbuff=(BYTE*)MaxMalloc(dwDestSize)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	

	for(DWORD dwCounter=0;dwCounter<m_pStructDecompressInfo->dwNoofBlocks;dwCounter++)
	{
		if(m_pStructBlockDecompressInfo->dwOffsettoSourceRVA+m_pStructBlockDecompressInfo->dwSrcSize+dwOffset+m_pStructDecompressInfo->dwOffsetofCode>m_objTempFile.m_dwFileSize ||
			m_pStructBlockDecompressInfo->dwDestRVA+m_pStructBlockDecompressInfo->dwDestSize>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			return false;
		}
		if(dwDestSize<m_pStructBlockDecompressInfo->dwDestSize)
		{
			if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_pStructBlockDecompressInfo->dwDestSize)))
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
		        return false;
			}
			dwDestSize=m_pStructBlockDecompressInfo->dwDestSize;
		}
		
		
		memset(byDestbuff,0,dwDestSize);
       		
		if(!(~APLIBDecompress(m_pStructBlockDecompressInfo->dwSrcSize,m_pStructBlockDecompressInfo->dwDestSize,0,0,byDestbuff,0,&byFullFilebuff[m_pStructBlockDecompressInfo->dwOffsettoSourceRVA+dwOffset+m_pStructDecompressInfo->dwOffsetofCode])))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			return false;
		}

		for(DWORD i=0;i<m_pStructBlockDecompressInfo->dwDestSize;i++)
		{
			byFullFilebuff[m_pStructBlockDecompressInfo->dwDestRVA+i]=byDestbuff[i];
		}



		if(dwOffset+m_pStructDecompressInfo->dwOffsetofCode+(dwCounter*sizeof(BlockDecompressInfo)+(dwCounter*1)) + (sizeof(BlockDecompressInfo)+1)>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		m_pStructBlockDecompressInfo=(BlockDecompressInfo*)&byFullFilebuff[dwOffset+m_pStructDecompressInfo->dwOffsetofCode+(dwCounter*sizeof(BlockDecompressInfo)+(dwCounter*1)) + (sizeof(BlockDecompressInfo)+1)];

	}

	//Resolve Imports

	if(m_pStructDecompressInfo->dwOffsetofImport+m_pStructDecompressInfo->dwSizeofImport+dwOffset>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byDestbuff);
		byDestbuff=NULL;
		return false;
	}

	if(m_pStructDecompressInfo->dwSizeofImport>m_pStructBlockDecompressInfo->dwDestSize)
	{
		if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_pStructDecompressInfo->dwSizeofImport)))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			return false;
		}
		dwDestSize=m_pStructDecompressInfo->dwSizeofImport;
	}
    memset(byDestbuff,0,dwDestSize);

	if(!(~APLIBDecompress(m_pStructDecompressInfo->dwSizeofImport,m_pStructDecompressInfo->dwSizeofImport,0,0,byDestbuff,0,&byFullFilebuff[m_pStructDecompressInfo->dwOffsetofImport+dwOffset])))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byDestbuff);
		byDestbuff=NULL;
		return false;
	}
	BYTE *byImportbuff=NULL;
	DWORD dwImportSize=0;

	if(!ResolveImports(&byImportbuff,byDestbuff,byFullFilebuff,0,&dwImportSize))
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
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x04]=m_pStructDecompressInfo->dwExportRVAx1;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x08]=m_pStructDecompressInfo->dwExportSize1;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x14]=m_pStructDecompressInfo->dwResourcesRVAx2;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x18]=m_pStructDecompressInfo->dwResourcesSizex2;	
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x04+0x08*0x0D]=m_pStructDecompressInfo->dwDelayImportDescRVAxD;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x04+0x08*0x0D+0x04]=m_pStructDecompressInfo->dwDelayImportDescSizexD;
    

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


bool CVPackUnpacker::ResolveImports(BYTE **byImportbuff,BYTE *byDestbuff,BYTE *byFullFilebuff,DWORD dwDestbuffOffset,DWORD *dwImportSize)
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

	if(dwDestbuffOffset+0x08 > m_pStructDecompressInfo->dwSizeofImport)
	{
		free(byImportAPIbuff);
		byImportAPIbuff=NULL;
		return false;
	}

	while(*(DWORD*)&byDestbuff[dwDestbuffOffset]!=0x00)
	{

		DWORD dwCounterofAPI=*(DWORD*)&byDestbuff[dwDestbuffOffset+0x04];


		if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,dwActualDLLSize+0x14)))
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}
		memset(&((*byImportbuff)[dwActualDLLSize]),0,0x14);
		dwActualDLLSize+=0x14;

		*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x08])=dwAPIWritingOffsets;
		*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])=*(DWORD*)&byDestbuff[dwDestbuffOffset];

		dwDestbuffOffset+=0x08;


		dwIndividualDLLAPISize=0;
		while(byDestbuff[dwDestbuffOffset+dwIndividualDLLAPISize]!=0x00)
		{
			dwIndividualDLLAPISize++;
			if(dwDestbuffOffset+dwIndividualDLLAPISize>m_pStructDecompressInfo->dwSizeofImport)
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


		if(dwDestbuffOffset+0x04 > m_pStructDecompressInfo->dwSizeofImport)
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}
		dwAPIRVAOffsets=0;

		while(dwCounterofAPI!=0x00)
		{

			if((*(DWORD*)&byDestbuff[dwDestbuffOffset]&0xFFFF0000)==0x00)
			{
				*(DWORD*)&byFullFilebuff[*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])+dwAPIRVAOffsets]=(*(DWORD*)&byDestbuff[dwDestbuffOffset]|0x80000000);
				dwAPIRVAOffsets+=0x04;
				dwDestbuffOffset+=0x04;
			}
			else
			{
				dwIndividualDLLAPISize=0;
				while(byDestbuff[dwDestbuffOffset+dwIndividualDLLAPISize]!=0x00)
				{
					dwIndividualDLLAPISize++;
					if(dwDestbuffOffset+dwIndividualDLLAPISize>m_pStructDecompressInfo->dwSizeofImport)
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
				*(DWORD*)&byFullFilebuff[*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x04])+dwAPIRVAOffsets]=dwAPIWritingOffsets;
				dwAPIRVAOffsets+=0x04;

				dwAPIWritingOffsets+=dwIndividualDLLAPISize;
				dwDestbuffOffset+=dwIndividualDLLAPISize;

				dwAPIWritingOffsets+=2;
				dwDestbuffOffset++;

				if(dwDestbuffOffset+0x04 > m_pStructDecompressInfo->dwSizeofImport)
				{
					free(byImportAPIbuff);
					byImportAPIbuff=NULL;
					return false;
				}

			}
			dwCounterofAPI--;
		}

		*(DWORD*)&((*byImportbuff)[dwActualDLLSize-0x0C])=dwAPIRVAOffsets/0x04;
		dwAPIWritingOffsets+=1;

		if(dwDestbuffOffset+0x04>m_pStructDecompressInfo->dwSizeofImport)
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}
		if(*(DWORD*)&byDestbuff[dwDestbuffOffset]==0x00)
		{
			break;
		}

		if(dwDestbuffOffset+0x08 > m_pStructDecompressInfo->dwSizeofImport)
		{
			free(byImportAPIbuff);
			byImportAPIbuff=NULL;
			return false;
		}
	}

	if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,dwActualDLLSize+0x14)))
	{
		free(byImportAPIbuff);
		byImportAPIbuff=NULL;
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
			if((*(DWORD*)&byFullFilebuff[*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x04])+(*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x0C])-1)*0x04]&0x80000000)==0x00)
			{
				*(DWORD*)&byFullFilebuff[*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x04])+(*(DWORD*)&((*byImportbuff)[(dwCounter)*0x14-0x0C])-1)*0x04]+=dwActualDLLSize+m_objTempFile.m_dwFileSize;
			}
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
