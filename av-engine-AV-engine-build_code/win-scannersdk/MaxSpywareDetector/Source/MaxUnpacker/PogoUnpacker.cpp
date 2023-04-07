#include "PogoUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CPogoUnpacker::CPogoUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{	
}

CPogoUnpacker::~CPogoUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CPogoUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".POGO", 5) == 0) && 
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[1].Name, ".POGO", 5) == 0))
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}
		BYTE byPogobuff[0x11]={0x60,0xE8,0x00,0x00,0x00,0x00,0x5B,0x8D,0x5B,0xC6,0x01,0x1B,0x8B,0x13,0x8D,0x73,0x14};
		if(m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,sizeof(byPogobuff),sizeof(byPogobuff)))
		{
			if(*(WORD *)&m_pbyBuff[0] == 0xE860)
			{
				if(memcmp(m_pbyBuff, byPogobuff, sizeof(byPogobuff)) == 0x00)
				{
					return true;
				}
			}
		}
	}
	return false;
}

bool CPogoUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pMaxPEFile->m_dwAEPMapped + 0x12, 0x01, 0x01))
	{
		return false;
	}
	DWORD dwSize = m_pbyBuff[0] * 0x04 + 0x08;

	BYTE *UnpackInfo = NULL;
	if(!(UnpackInfo = (BYTE *)MaxMalloc(dwSize)))
	{
		return false;
	}
	DWORD dwCompressedInfo = m_pMaxPEFile->m_dwAEPMapped + 0x06 - 0x3A + 0x0C;
	if(!m_pMaxPEFile->ReadBuffer(UnpackInfo, dwCompressedInfo, dwSize, dwSize))
	{
		free(UnpackInfo);
		UnpackInfo = NULL;		
		return false;
	}
	
	DWORD dwOrigAEP = *(DWORD *)UnpackInfo + m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + 0x05;
	DWORD dwRead = *(DWORD *)(&UnpackInfo[0x14]) - 0x0C;
	DWORD dwReadRVA = *(DWORD *)(&UnpackInfo[0xC]);
	
	free(UnpackInfo);
	UnpackInfo = NULL;
	
	if(dwRead > m_objTempFile.m_dwFileSize)
	{
		return false;
	}
	if(!m_objTempFile.WriteBuffer(&dwRead, m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0x68, 0x04, 0x04))
	{
		return false;
	}	
	if(!m_objTempFile.WriteAEP(dwOrigAEP))
	{
		return false;
	}
	DWORD dwReadFileOffset = 0;
	if(m_pMaxPEFile->Rva2FileOffset(dwReadRVA, &dwReadFileOffset) == OUT_OF_FILE)
	{
		return false;
	}
	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwReadFileOffset, 0x08, 0x08))
	{
		return false;
	}
	
	DWORD dwWrite = *(DWORD *)&m_pbyBuff[0];
	DWORD dwSrcSize = *(DWORD *)&m_pbyBuff[4];
	BYTE *byDestbuff = NULL;
	DWORD dwNextRead = 0, dwDestSize = 0, dwNextSrcSize = 0, dwNextWrite = 0, dwSizeUncompressed = 0;
	bool bEndflag = false, bSuccess = true;

	while(bEndflag == false || dwReadRVA < m_pMaxPEFile->m_stSectionHeader[1].VirtualAddress)
	{
		dwNextRead = dwReadRVA + dwSrcSize + 0x08;
		if(m_pMaxPEFile->Rva2FileOffset(dwNextRead, &dwNextRead) == OUT_OF_FILE)
		{
			return false;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, dwNextRead, 0x08, 0x08))
		{
			return false;
		}
		if(*(DWORD *)&m_pbyBuff[0] == 0x00)  //Loop Breaking Condition
		{
			bEndflag = true;
		}
		
		dwNextWrite = *(DWORD *)&m_pbyBuff[0];		
		dwNextSrcSize = *(DWORD *)&m_pbyBuff[4];
		if((dwNextWrite & 0x80000000) == 0x80000000)
		{
			dwNextSrcSize *= 0x04;
		}
		
		if(bEndflag)
		{
			dwDestSize = (m_pMaxPEFile->m_stSectionHeader[1].VirtualAddress & 0x7FFFFFFF) - dwWrite;
		}
		else
		{
			dwDestSize = (dwNextWrite & 0x7FFFFFFF) - dwWrite;
		}
		
		if((dwWrite & 0x80000000) == 0x80000000)
		{
			if(!(byDestbuff = (BYTE*)MaxMalloc(dwSrcSize)))
			{
				return false;
			}
			if(!m_pMaxPEFile->ReadBuffer(byDestbuff,dwReadFileOffset+0x08,dwSrcSize,dwSrcSize))
			{
				free(byDestbuff);
				byDestbuff = NULL;
				return false;
			}
			dwSizeUncompressed = dwSrcSize;
		}
		else 
		{
			if(!(byDestbuff = (BYTE *)MaxMalloc(dwDestSize)))
			{
				return false;
			}
			if(!(~(dwSizeUncompressed = APLIBDecompress(dwSrcSize, dwDestSize, dwReadFileOffset + 0x08, dwWrite, byDestbuff))))
			{
				free(byDestbuff);
				byDestbuff = NULL;
				return false;
			}
			if(!ResolveE8E9Calls(byDestbuff,dwWrite,dwSizeUncompressed))
			{
				free(byDestbuff);
				byDestbuff = NULL;
				return false;
			}
		}
		
		if(!m_objTempFile.WriteBuffer(byDestbuff, dwWrite & 0x7FFFFFFF, dwSizeUncompressed, dwSizeUncompressed))
		{
			free(byDestbuff);
			byDestbuff = NULL;
			return false;
		}

		free(byDestbuff);
		byDestbuff=NULL;
		
		dwReadRVA += dwSrcSize + 0x08;
		dwWrite = dwNextWrite;
		dwSrcSize = dwNextSrcSize;
		dwReadFileOffset = dwNextRead;
	}	
	return true;
}

bool CPogoUnpacker::ResolveE8E9Calls(BYTE *bySrcbuff, DWORD dwStart, DWORD dwSize)
{
	DWORD dwInitSub = -0x04, dwtemp = 0x0;
	bool bFlag = false;
	
	//Start Resolving
	for(DWORD dwCounter = 0; dwCounter <= (dwSize - 5); dwCounter++)
	{
		if(bySrcbuff[dwCounter] == 0xE8 || bySrcbuff[dwCounter] == 0xE9 || ((WORD(*(DWORD *)&(bySrcbuff[dwCounter]) & 0xFFFFF0FF) == 0x800F)&& (bFlag = true)))
		{
			if(bFlag)
			{
				bFlag = false;
				if(dwCounter == dwSize - 0x05)
				{
					return false;
				}
				dwCounter += 0x01;
			}
			dwtemp = (dwCounter - dwInitSub) ^ 0x03;
			dwInitSub = dwCounter;
			if(bySrcbuff[dwCounter + 0x04] == 0x00 || bySrcbuff[dwCounter + 0x04] == 0xFF)
			{
				while(1)
				{
					*(DWORD *)&(bySrcbuff[dwCounter + 0x01]) -= dwStart;
					*(DWORD *)&(bySrcbuff[dwCounter + 0x01]) -= (dwCounter+0x01);
					if(dwtemp > 0x03)
					{
						if((bySrcbuff[dwCounter + 0x04] & 0x01) == 0x01)
						{
							bySrcbuff[dwCounter + 0x04] = 0xFF;					  
						}
						else
						{
							bySrcbuff[dwCounter + 0x04] = 0x00;					 
						}
					}
					else
					{
						DWORD dwtemp1 = dwtemp << 0x03;
						DWORD dwtemp2 = 0xFF << (BYTE)dwtemp1;
						dwtemp2 ^= *(DWORD *)&(bySrcbuff[dwCounter + 0x01]);
						dwtemp1 = dwtemp + dwCounter + 0x01;
						if((BYTE)dwtemp1 == 0x00 || (BYTE)dwtemp1 == 0xFF)
						{
							*(DWORD *)&bySrcbuff[dwCounter + 0x01] = dwtemp2;
							continue;
						}
					}
					break;
				}
				dwCounter += 0x04;	
			}
		}
	}
	return true;
}
