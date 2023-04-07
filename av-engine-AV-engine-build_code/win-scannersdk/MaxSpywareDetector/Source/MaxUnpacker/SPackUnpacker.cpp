#include "SPackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CSPackUnpacker::CSPackUnpacker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
}

CSPackUnpacker::~CSPackUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
}

bool CSPackUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 0x05 && 
		memcmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec - 0x02].Name, ".spack", 6) == 0 &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData > 0x13)
	{
		m_pbyBuff = new BYTE[0x10];		
		if(!m_pbyBuff)
		{
			return false;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped, 0x10, 0x10))
		{
			return false;
		}
		if(*(DWORD*)&m_pbyBuff[0] == 0x790B72F9 && m_pbyBuff[4]==0xFB)
		{
			if(*(WORD*)&m_pbyBuff[5]==0xB842 && *(WORD*)&m_pbyBuff[0xB]==0x7734)
			{
				return true;
			}
		}
	}
	return false;
}

bool CSPackUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!CopyFile(m_pMaxPEFile->m_szFilePath, szTempFileName, false))
	{
		return false;
	}
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	DWORD dwOffset =(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint&0xFFFFFF00);
	DWORD dwRVADecryptStart=dwOffset;
	if(OUT_OF_FILE==m_pMaxPEFile->Rva2FileOffset(dwOffset,&dwOffset))
	{
		return false;
	}
	DWORD dwCounter=0x00;
	DWORD dwOrigAEP=0x00;
	if(!m_pMaxPEFile->ReadBuffer(&dwOrigAEP,dwOffset+0xFC,0x04,0x04))
	{
		return false;
	}
	dwOrigAEP+=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint&0xFFFFFF00;
	if(!m_pMaxPEFile->ReadBuffer(&dwCounter,dwOffset,0x04,0x04))
	{
		return false;
	}	
	dwOffset+=0x04;
	dwRVADecryptStart+=0x04;
	DecryptParam objDecryptParam;
	BYTE *bySrcbuff=NULL;

	for(;dwCounter>0;dwCounter--)
	{
		if(!m_pMaxPEFile->ReadBuffer(&objDecryptParam,dwOffset,0x08,0x08))
		{
			return false;
		}
		objDecryptParam.Size *= 0x04;
		if(!(bySrcbuff=(BYTE*)MaxMalloc(objDecryptParam.Size)))
		{
			return false;
		}
		DWORD dwFileOffset=dwRVADecryptStart+objDecryptParam.RVAStart;        
		if(OUT_OF_FILE==m_pMaxPEFile->Rva2FileOffset(dwFileOffset,&dwFileOffset))
		{
			free(bySrcbuff);
			bySrcbuff=NULL;
			return false;
		}

		if(!m_pMaxPEFile->ReadBuffer(bySrcbuff,dwFileOffset,objDecryptParam.Size,objDecryptParam.Size))
		{
			free(bySrcbuff);
			bySrcbuff=NULL;
			return false;
		}

		for(DWORD i=0;i<objDecryptParam.Size;i+=4)
		{
			*(DWORD*)&bySrcbuff[i]-=0x492B45A4;
		}

		if(!m_objTempFile.WriteBuffer(bySrcbuff,dwRVADecryptStart+objDecryptParam.RVAStart,objDecryptParam.Size,objDecryptParam.Size))
		{
			free(bySrcbuff);
			bySrcbuff=NULL;
			return false;
		}
		dwRVADecryptStart+=0x08;
		dwOffset+=0x08;
		free(bySrcbuff);
		bySrcbuff=NULL;
	}	
	if(m_objTempFile.WriteAEP(dwOrigAEP+0x100))
	{
		return true;
	}
	return false;
}

