#include "BitArtsUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CBitArtsUnpack::CBitArtsUnpack(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
	m_pStructDecryptBlockInfo=NULL;
}

CBitArtsUnpack::~CBitArtsUnpack(void)
{
	m_pStructDecryptBlockInfo=NULL;
	m_objTempFile.CloseFile();

}

bool CBitArtsUnpack::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 2 && (m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint%0x1000)==0x00 &&
		(memcmp(m_pMaxPEFile->m_stSectionHeader[0].Name,"BitArts",7)==0x00 || m_iCurrentLevel>0) )
	{
		const BYTE bySigbuff[]={0xE8, 0x00 ,0x00 ,0x00 ,0x00 ,0x5D ,0x83 ,0xED ,0x06 ,0x8B ,0xC5 ,0x55 ,0x60};
		BYTE pbyBuff[sizeof(bySigbuff)] = {0};
		
		if(!m_pMaxPEFile->ReadBuffer(pbyBuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(bySigbuff)+0x01, sizeof(bySigbuff)+0x01))
		{
			return false;
		}

		if(pbyBuff[0]==0x55 && memcmp(&pbyBuff[1], bySigbuff, sizeof(bySigbuff))==0x00)
		{
			return true;
		}
	}
	return false;
}

bool CBitArtsUnpack::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	BYTE *byFullFilebuff=NULL;
	if(!(byFullFilebuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize+0x30)))
	{
		return false;
	}
	memset(&byFullFilebuff[m_objTempFile.m_dwFileSize],0x00,0x30);
	if(!m_objTempFile.ReadBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;

	if(dwOffset+0x22+0x04>m_objTempFile.m_dwFileSize || *(DWORD*)&byFullFilebuff[dwOffset+0x22]+dwOffset>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//Case if already unpacked
	if(*(DWORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwOffset+0x22]+dwOffset]==0x01)
	{
		if(dwOffset+0x36+0x04>m_objTempFile.m_dwFileSize || *(DWORD*)&byFullFilebuff[dwOffset+0x36]+dwOffset>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!m_objTempFile.WriteAEP(*(DWORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwOffset+0x36]+dwOffset]))
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

	dwOffset+=0xC4;
	BYTE *byDestbuff=NULL;
	DWORD dwDestSize=0;
	DWORD dwDestSizeAllocated=0x3000;
	if(!(byDestbuff=(BYTE*)MaxMalloc(dwDestSizeAllocated)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	if(!(~(dwDestSize=APLIBDecompress(m_objTempFile.m_dwFileSize-dwOffset,0x3000,0,0,byDestbuff,1,&byFullFilebuff[dwOffset]))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byDestbuff);
		byDestbuff=NULL;		
		return false;
	}

	if(dwOffset+dwDestSize>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byDestbuff);
		byDestbuff=NULL;		
		return false;
	}
	for(DWORD i=0;i<dwDestSize;i++)
	{
		byFullFilebuff[dwOffset+i]=byDestbuff[i];
	}
	dwOffset-=0xC4;

	//*****************Decryption of Sections**********************************

	if(dwOffset+0x2986+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byDestbuff);
		byDestbuff=NULL;	
		return false;
	}


	WORD wNoOfSections=*(WORD*)&byFullFilebuff[dwOffset+0x2444];

	DWORD dwSrcDestRVA=0;
	DWORD dwCounter=0;

	while(wNoOfSections!=0x00)
	{
		if(*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x2446]==0x01)
		{
			dwSrcDestRVA=*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x27A6];
			if(*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x24E6])
			{
				dwDestSize=*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x24E6];
			}
			else
			{
				dwDestSize=*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x2986];
			}

			if(dwDestSize>0)
			{
				if(dwDestSize+dwSrcDestRVA>m_objTempFile.m_dwFileSize)
				{
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					free(byDestbuff);
					byDestbuff=NULL;	
					return false;
				}
				for(DWORD i=0;i<dwDestSize;i++)
				{
					byFullFilebuff[dwSrcDestRVA+i]^=byFullFilebuff[(dwOffset+0x23A0)+(i%0x28)];
				}

			}

		}

		if(dwCounter+dwOffset+0x08 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;	
			return false;
		}
		dwCounter+=0x04;

		wNoOfSections--;
	}

	//***************Decryption Of Sections End********************


	//***************Decompression of Sections**************************

	dwCounter=0;
	wNoOfSections=*(WORD*)&byFullFilebuff[dwOffset+0x2444];
	while(wNoOfSections!=0x00)
	{
		if(*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x2446]==0x01)
		{
			dwSrcDestRVA=*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x27A6];
			dwDestSize=*(DWORD*)&byFullFilebuff[dwOffset+dwCounter+0x2846];
			if(dwDestSize>0)
			{
				if(dwDestSize+0x1000>dwDestSizeAllocated)
				{
					if(!(byDestbuff=(BYTE*)realloc(byDestbuff,dwDestSize+0x1000)))
					{
						free(byFullFilebuff);
						byFullFilebuff=NULL;
						return false;
					}
					dwDestSizeAllocated=dwDestSize+0x1000;
				}
				memset(byDestbuff,0,dwDestSizeAllocated);
				if(!(~(dwDestSize=APLIBDecompress(m_objTempFile.m_dwFileSize-dwSrcDestRVA,dwDestSizeAllocated,0,0,byDestbuff,1,&byFullFilebuff[dwSrcDestRVA]))))
				{
					if(byDestbuff)
					{
						free(byDestbuff);
						byDestbuff=NULL;
					}
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}

				if(dwDestSize+dwSrcDestRVA>m_objTempFile.m_dwFileSize)
				{
					if(byDestbuff)
					{
						free(byDestbuff);
						byDestbuff=NULL;
					}
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}

				for(DWORD i=0;i<dwDestSize;i++)
				{
					byFullFilebuff[dwSrcDestRVA+i]=byDestbuff[i];
				}
				
			}
		}
		dwCounter+=0x04;
		wNoOfSections--;
	}

	//***************Decompression of Sections End**************************


	//Setting the Import Table RVA and the AEP
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=*(DWORD*)&byFullFilebuff[dwOffset+0x227B];
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=*(DWORD*)&byFullFilebuff[dwOffset+0x228F];

	if(!m_objTempFile.WriteBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		if(byDestbuff)
		{
			free(byDestbuff);
			byDestbuff=NULL;
		}
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