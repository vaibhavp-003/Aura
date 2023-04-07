#include "PePackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CPePackUnpacker::CPePackUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{
	m_pbyBuff = new BYTE[255];
}

CPePackUnpacker::~CPePackUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CPePackUnpacker::IsPacked() 
{
	if(!m_pbyBuff)
	{
		return false;
	}

	m_dwOffset=m_pMaxPEFile->m_dwAEPMapped;
	BYTE byPePackbuff[]={0x60,0xE8,0x00,0x00,0x00,0x00,0x5D,0x83,0xED,0x06,0x80,0xBD};
	if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwOffset, sizeof(byPePackbuff),sizeof(byPePackbuff)))
	{
		if(*(WORD*)&m_pbyBuff[0] == 0x0074 && m_pbyBuff[2]==0xE9)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + 0x07 + *(DWORD*)&m_pbyBuff[3];
			if(m_pMaxPEFile->Rva2FileOffset(m_dwOffset, &m_dwOffset) == OUT_OF_FILE)
			{
				return false;
			}
		}
	}
	if(m_dwOffset != m_pMaxPEFile->m_dwAEPMapped)
	{
		if(!(m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwOffset, sizeof(byPePackbuff),sizeof(byPePackbuff))))
		{
			return false;
		}
	}
	if(memcmp(m_pbyBuff, byPePackbuff, sizeof(byPePackbuff)) == 0x00)
	{
		return true;
	}
	return false;
}


bool CPePackUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	BYTE UnpackInfo[0x0C]={0};
	if(!m_pMaxPEFile->ReadBuffer(UnpackInfo, m_dwOffset + 0x557, 0x0C, 0x0C))
	{
		return false;
	}

	DWORD dwImportOffset=0x00;
	if(!m_pMaxPEFile->ReadBuffer(&dwImportOffset, m_dwOffset + 0x56F, 0x04, 0x04))
	{
		return false;
	}

	DWORD dwOrigAEP = *(DWORD*)&UnpackInfo[0x00];
	DWORD dwDestSize = *(DWORD*)&UnpackInfo[0x08];
	DWORD dwCompressedDataStruct = *(DWORD*)&UnpackInfo[0x4];

	m_dwOffset += dwCompressedDataStruct;

	BYTE *bySrcBuff = NULL;
	BYTE *byDestbuff  = NULL;
	if(!(byDestbuff = (BYTE *)MaxMalloc(dwDestSize)))
	{
		return false;
	}

	DWORD dwUnCompressedSize;
	DWORD dwRead;
	bool bRet = false;
	while(1)
	{
		memset(byDestbuff, 0, dwDestSize);
		if(!m_pMaxPEFile->ReadBuffer(UnpackInfo, m_dwOffset, 0x0C, 0x0C))
		{
			break;
		}

		if(*(DWORD*)&UnpackInfo[0] == 0x00)
		{
			bRet = true;
			break;
		}
		if(!(bySrcBuff = (BYTE *)MaxMalloc(*(DWORD*)&UnpackInfo[0x04])))
		{
			break;
		}
		if(m_pMaxPEFile->Rva2FileOffset(*(DWORD*)&UnpackInfo[0x0],&dwRead) == OUT_OF_FILE)
		{
			break;
		}
		if(!(~(dwUnCompressedSize = APLIBDecompress(*(DWORD*)&UnpackInfo[0x04], dwDestSize,dwRead, 0x00, byDestbuff, 1))))
		{
			break;
		}
		if(!m_objTempFile.WriteBuffer(byDestbuff, *(DWORD*)&UnpackInfo[0], dwUnCompressedSize, dwUnCompressedSize))
		{
			break;
		}
		m_dwOffset += 0x0C;
	}
	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff = NULL;
	}

	if(bySrcBuff)
	{
		free(bySrcBuff);
		bySrcBuff = NULL;
	}
	if(bRet)
	{
		if(m_objTempFile.WriteBuffer(&dwImportOffset, m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0x68, 0x04, 0x04))
		{
			if(m_objTempFile.WriteAEP(dwOrigAEP))
			{
				return true;
			}
		}
	}
	return false;
}
