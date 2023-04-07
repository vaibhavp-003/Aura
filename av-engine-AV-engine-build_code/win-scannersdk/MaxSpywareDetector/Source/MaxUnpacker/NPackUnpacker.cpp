#include "NPackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CNPackUnpacker::CNPackUnpacker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
	m_pbyBuff = NULL;
}

CNPackUnpacker::~CNPackUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
}

bool CNPackUnpacker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		(m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData==m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize==0x1000 &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Characteristics==0xC0000040 )		
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x24,0x24))
		{
			return false;
		}
		if(*(WORD*)&m_pbyBuff[0]==0x3D83 && m_pbyBuff[0x6]==0x00 && *(DWORD*)&m_pbyBuff[0x7]==0x01E90575 && *(DWORD*)&m_pbyBuff[0xB]==0xC3000000)
		{
			return true;
		}
	}
	return false;
}

bool CNPackUnpacker::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	DWORD dwoffset=0x20;
	
	dwoffset=*(DWORD*)&m_pbyBuff[dwoffset];
	dwoffset-=0x08;
	dwoffset-=m_dwImageBase;

	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwoffset,&dwoffset))
	{
		return false;
	}
	DWORD dwDestSize=0;

	if(!(~(dwDestSize=APLIBDecompress(0x24,0x24,dwoffset,0,m_pbyBuff,0,NULL))))
	{
		return false;
	}

	DecompressInfo* m_pStructDecompressInfo=(DecompressInfo*)&m_pbyBuff[0x0];
	
	dwDestSize=0;
	BYTE *byDestbuff=NULL;
	byDestbuff=new BYTE[1];
	bool bResources=true;
	for(DWORD i=0;i<m_objTempFile.m_stPEHeader.NumberOfSections-0x01;i++)
	{
		if(m_pMaxPEFile->m_stSectionHeader[i].Misc.VirtualSize>dwDestSize)
		{
			if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_pMaxPEFile->m_stSectionHeader[i].Misc.VirtualSize)))
			{
				free(byDestbuff);
				byDestbuff=NULL;
				return false;
			}
		}
		memset(byDestbuff,0,dwDestSize);
        
		dwDestSize=0;
		if( m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData!=0x00 && 
			m_pMaxPEFile->m_stSectionHeader[i].PointerToRawData!=0x00 && 
			(m_pMaxPEFile->m_stSectionHeader[i].Characteristics&0x00010000)==0x00 && 
			(((m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress>m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress || m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData<=m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress && (bResources=false)) || m_pStructDecompressInfo->dwResourcesSize!=0x00) )
			&& (m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress>m_pMaxPEFile->m_stPEHeader.DataDirectory[0].VirtualAddress || m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData<=m_pMaxPEFile->m_stPEHeader.DataDirectory[0].VirtualAddress) &&
			(!(~(dwDestSize=APLIBDecompress(m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData-(bResources*m_pStructDecompressInfo->dwResourcesSize),m_pMaxPEFile->m_stSectionHeader[i].Misc.VirtualSize,
			m_pMaxPEFile->m_stSectionHeader[i].PointerToRawData+((bResources*m_pStructDecompressInfo->dwResourcesSize)),0,byDestbuff)))) )
		{
			return false;
		}

		if(dwDestSize && m_pStructDecompressInfo->dwDecryptValue!=0x00)
		{
			for(DWORD j=0;j<dwDestSize;j++)
			{
				byDestbuff[j]^=BYTE(m_pStructDecompressInfo->dwDecryptValue);
			}

			if(!m_objTempFile.WriteBuffer(byDestbuff,m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress,dwDestSize,dwDestSize))
			{
				free(byDestbuff);
				byDestbuff=NULL;
				return false;
			}
		}		
		dwDestSize=m_pMaxPEFile->m_stSectionHeader[i].Misc.VirtualSize;
		bResources=true;
	}

	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff=NULL;
	}
	

	if(!m_objTempFile.WriteBuffer(&m_pStructDecompressInfo->dwResolveImports,m_objTempFile.m_stPEOffsets.NoOfDataDirs+(sizeof(DWORD)*0x03),sizeof(DWORD),sizeof(DWORD)))
	{
		return false;
	}

	
	if(!m_objTempFile.WriteAEP(m_pStructDecompressInfo->dwAEP))
	{
		return false;
	}
	return true;
}

