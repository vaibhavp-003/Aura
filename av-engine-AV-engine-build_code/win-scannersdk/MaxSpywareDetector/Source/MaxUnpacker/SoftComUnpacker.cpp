#include "SoftComUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CSoftComUnpack::CSoftComUnpack(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
}

CSoftComUnpack::~CSoftComUnpack(void)
{	
	m_objTempFile.CloseFile();
}

bool CSoftComUnpack::IsPacked() 
{	
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(m_pMaxPEFile->m_wAEPSec == m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x02) &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Name, "SoftComp", 8) == 0) &&
		*(DWORD*)&m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRelocations==0x4C4C442E )
	{
		BYTE byBuff[0x10] = {0};
		if(!m_pMaxPEFile->ReadBuffer(byBuff,m_pMaxPEFile->m_dwAEPMapped,0x0D,0x0D))
		{
			return false;
		}

		if( byBuff[0]==0xE8 && *(DWORD*)&byBuff[0x1]==0x0 && byBuff[0x5]==0x81 &&
			*(WORD*)&byBuff[6]==0x242C && byBuff[0xC]==0x5D )
		{
			return true;
		}
	}
	return false;
}

bool CSoftComUnpack::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}
	DWORD dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;

	DWORD dwEBPValue=dwOffset+0x05;

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

	if(dwOffset+0x0C>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwEBPValue-=(*(DWORD*)&byFullFilebuff[dwOffset+0x08]-m_dwImageBase);
	dwOffset+=0x76;
	if(dwOffset+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	BYTE *byDestbuff=NULL;
	
	if(!(byDestbuff=(BYTE*)MaxMalloc(0x2000)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	memset(byDestbuff,0,0x2000);
	DWORD dwDestSize=0x0;

	if(dwOffset+0x04>m_objTempFile.m_dwFileSize || *(DWORD*)&byFullFilebuff[dwOffset]+dwEBPValue-m_dwImageBase>m_objTempFile.m_dwFileSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwSrcRVA=*(DWORD*)&byFullFilebuff[dwOffset]+dwEBPValue-m_dwImageBase;

	if(dwSrcRVA>m_objTempFile.m_dwFileSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(!(~(dwDestSize=APLIBDecompress(m_objTempFile.m_dwFileSize-dwSrcRVA,0x2000,0,0,byDestbuff,0,&byFullFilebuff[dwSrcRVA]))))
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwDestbuffOffset=0;
	if(dwDestbuffOffset+0x08 > dwDestSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwRVASize=0;
	DWORD dwDestSizeAllocated=0;
	BYTE *bybuffMainFileD=NULL;
	if(!(bybuffMainFileD=(BYTE*)MaxMalloc(0x01)))
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	while(*(DWORD*)&byDestbuff[dwDestbuffOffset]!=0x00)
	{
		dwSrcRVA=*(DWORD*)&byDestbuff[dwDestbuffOffset]-m_dwImageBase;
		dwRVASize=*(DWORD*)&byDestbuff[dwDestbuffOffset+0x04];

		if(dwSrcRVA>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(dwRVASize>dwDestSizeAllocated)
		{
			if(!(bybuffMainFileD=(BYTE*)realloc(bybuffMainFileD,dwRVASize)))
			{
				if (byDestbuff)
				{
					free(byDestbuff);
					byDestbuff=NULL;
				}
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			memset(bybuffMainFileD,0,dwRVASize);
			dwDestSizeAllocated=dwRVASize;
		}

		if(!(~(dwRVASize=APLIBDecompress(m_objTempFile.m_dwFileSize-dwSrcRVA,dwDestSizeAllocated,0,0,bybuffMainFileD,0,&byFullFilebuff[dwSrcRVA]))))
		{
			free(bybuffMainFileD);
			bybuffMainFileD=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(dwRVASize+dwSrcRVA>m_objTempFile.m_dwFileSize)
		{
			free(bybuffMainFileD);
			bybuffMainFileD=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		for(DWORD i=0;i<dwRVASize;i++)
		{
			byFullFilebuff[dwSrcRVA+i]=bybuffMainFileD[i];
		}

		dwDestbuffOffset+=0x08;

		if(dwDestbuffOffset+0x08>m_objTempFile.m_dwFileSize)
		{
			free(bybuffMainFileD);
			bybuffMainFileD=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

	}

	if(bybuffMainFileD)
	{
		free(bybuffMainFileD);
		bybuffMainFileD=NULL;
	}

	dwDestbuffOffset=0;
	if(dwOffset+0x1D> m_objTempFile.m_dwFileSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(dwDestbuffOffset+*(DWORD*)&byFullFilebuff[dwOffset+0x19]+byFullFilebuff[dwOffset+0x11]+0x10>dwDestSize)
	{
		free(byDestbuff);
		byDestbuff=NULL;
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=*(DWORD*)&byDestbuff[dwDestbuffOffset+*(DWORD*)&byFullFilebuff[dwOffset+0x19]+byFullFilebuff[dwOffset+0x11]];
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=*(DWORD*)&byDestbuff[dwDestbuffOffset+*(DWORD*)&byFullFilebuff[dwOffset+0x19]+byFullFilebuff[dwOffset+0x11]+0x0C];

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