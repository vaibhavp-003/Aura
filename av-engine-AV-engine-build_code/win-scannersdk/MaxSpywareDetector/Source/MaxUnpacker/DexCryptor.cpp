#include "DexCryptor.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CDexCryptor::CDexCryptor(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
	m_dwOffset = 0x00;
	m_dwIncrementSize = 0x00;
	m_pbyBuff = NULL;
}

CDexCryptor::~CDexCryptor(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CDexCryptor::IsPacked() 
{
	bool bIsPacked = false;
	if(m_pMaxPEFile->m_wAEPSec > 0x02 && 
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData < 0x120 &&
		((m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize==0x1000) ||  (m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData==m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize))&& 		
		(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Characteristics&0x60000020)==0x60000020)
	{
		DWORD dwAEPSecSRD = m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData;
		m_pbyBuff = new BYTE[dwAEPSecSRD + 0x30];		
		if(!m_pbyBuff)
		{
			return false;
		}
		memset(m_pbyBuff, 0, dwAEPSecSRD + 0x30);

		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pMaxPEFile->m_dwAEPMapped, dwAEPSecSRD, dwAEPSecSRD))
		{
			return false;
		}
		m_eCrypt_Type = POPAD;
		if(*(DWORD*)&m_pbyBuff[0] == 0x4F242C83)
		{
			m_eCrypt_Type = SUB;
		}
		else if(*(DWORD*)&m_pbyBuff[0] == 0x30FFC48B)
		{
			m_eCrypt_Type = VCrypt;
		}

		if(m_pbyBuff[0] == 0xEB)
		{
			m_dwOffset += m_pbyBuff[1] + 0x02;
		}
		WaitForSingleObject(CUnpackBase::m_hEvent, INFINITE);
		bIsPacked  = _IsPacked();
		SetEvent(CUnpackBase::m_hEvent);
	}	
	return bIsPacked;
}

bool CDexCryptor::_IsPacked() 
{
	CEmulate objEmulate(m_pMaxPEFile);
	
	DWORD	dwLength = 0, dwInstructionCountFound = 0;
	char	szInstruction[1024] = {0x00};
	
	while(m_dwOffset < m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData)
	{
		dwLength = objEmulate.DissassemBuffer((char*)&m_pbyBuff[m_dwOffset],szInstruction);

		if(dwInstructionCountFound==0x00 && strstr(szInstruction,"PUSH") && dwLength==0x05)
		{
			m_dwOrigAEP = *(DWORD*)&m_pbyBuff[m_dwOffset+0x01] - m_dwImageBase;
			dwInstructionCountFound++;
		}

		if(dwInstructionCountFound==0x01 && m_pbyBuff[m_dwOffset]==0xB8)
		{
			if(m_pbyBuff[m_dwOffset+0x05]==0x3D && *(DWORD*)&m_pbyBuff[m_dwOffset+0xA]==0x30800674)
			{
				return true;
			}
			else if((m_pbyBuff[m_dwOffset+0x05]==0x90 && m_pbyBuff[m_dwOffset+0x06]==0x3D && *(DWORD*)&m_pbyBuff[m_dwOffset+0xB]==0x30800674))
			{
				m_dwIncrementSize=1;
				return true;
			}
			else if(m_pbyBuff[m_dwOffset+0x05]==0x3D && *(WORD*)&m_pbyBuff[m_dwOffset+0x0A]==0x0774)
			{
				return true;
			}
		} 
		m_dwOffset+=dwLength;
	}		
	return false;
}

bool CDexCryptor::Unpack(LPCTSTR szTempFileName)
{
	DWORD dwRVADecryptStart = 0, dwRVADecryptEnd = 0;

	if(!CopyFile(m_pMaxPEFile->m_szFilePath, szTempFileName, false))
	{
		return false;
	}
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	DWORD dwLimit = m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData - m_dwOffset;
	
	BYTE *byDexCryptorbuff = new BYTE[dwLimit];
	BYTE  byXORKey=0x00;
	if(!byDexCryptorbuff)
	{
		return false;
	}
	if(m_pMaxPEFile->ReadBuffer(byDexCryptorbuff, m_pMaxPEFile->m_dwAEPMapped+m_dwOffset-(m_eCrypt_Type/0x03), dwLimit, dwLimit))
	{			
		for(DWORD dwCounter = 0; (dwCounter + m_dwIncrementSize + 0x12+((m_eCrypt_Type/0x03)*0x03)) <= dwLimit - 1 - ((m_eCrypt_Type==SUB)* 5); dwCounter += m_dwIncrementSize+0x12+((m_eCrypt_Type/0x03)*0x03))
		{		
			if(byDexCryptorbuff[dwCounter+(m_eCrypt_Type/0x03)] == 0xB8 && (byDexCryptorbuff[dwCounter + m_dwIncrementSize + 0x05+(m_eCrypt_Type/0x03)] == 0x3D))
			{
				dwRVADecryptStart = *(DWORD*)&byDexCryptorbuff[dwCounter + 0x01+(m_eCrypt_Type/0x03)] - m_dwImageBase;
				dwRVADecryptEnd = *(DWORD*)&byDexCryptorbuff[dwCounter + 0x06 + m_dwIncrementSize+(m_eCrypt_Type/0x03)] - m_dwImageBase;
				if(m_eCrypt_Type!=VCrypt)
				{
					byXORKey = byDexCryptorbuff[dwCounter + m_dwIncrementSize + 0xE];
				}
				else
				{
					byXORKey = byDexCryptorbuff[dwCounter];
				}
				if(!DecryptParts(dwRVADecryptStart, dwRVADecryptEnd, byXORKey,m_eCrypt_Type))
				{
					break;
				}
			}

			if((byDexCryptorbuff[dwCounter + m_dwIncrementSize + 0x12] == 0xE8 && m_eCrypt_Type == SUB) || (byDexCryptorbuff[dwCounter + m_dwIncrementSize + 0x12] == 0xC3 && (m_eCrypt_Type == POPAD)) ||
				(byDexCryptorbuff[dwCounter + 0x14]==0xE8 && m_eCrypt_Type==VCrypt))
			{
				if(m_objTempFile.WriteAEP(m_dwOrigAEP))
				{
					free(byDexCryptorbuff);
					byDexCryptorbuff = NULL;
					return true;
				}
			}	

		}
	}
	free(byDexCryptorbuff);
	byDexCryptorbuff = NULL;
	return false;
}

bool CDexCryptor::DecryptParts(DWORD dwSrcStart, DWORD dwSrcEnd, BYTE byXORKey,int iType)
{
	bool bRet = false;
	BYTE *bySrcbuff = NULL;
	DWORD dwSize = dwSrcEnd - dwSrcStart;
	if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSize)))
	{
		return false;
	}
	memset(bySrcbuff, 0x00, dwSize);

	if(m_pMaxPEFile->Rva2FileOffset(dwSrcStart,&dwSrcStart)>=0)
	{
		if(m_pMaxPEFile->ReadBuffer(bySrcbuff,dwSrcStart,dwSize,dwSize))
		{	
			if(iType==0x03)
			{
				for(DWORD i=0;i<dwSize;i++)
				{
					*(bySrcbuff+i)^=byXORKey;
					MAX_ROL(byXORKey,1);
				}
			}
			else
			{
				for(DWORD i=0;i<dwSize;i++)
				{
					*(bySrcbuff+i)^=byXORKey;
				}
			}
			bRet = m_objTempFile.WriteBuffer(bySrcbuff,dwSrcStart,dwSize,dwSize);			
		}
	}
	free(bySrcbuff);
	bySrcbuff = NULL;
	return bRet;
}