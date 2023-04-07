#include "RPCryptDeJunker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CRPCryptDeJunker::CRPCryptDeJunker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
}

CRPCryptDeJunker::~CRPCryptDeJunker(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CRPCryptDeJunker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		(m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData<m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize==0x1000 &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData<0x200 && 
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Characteristics==0x60000020 )		
	{
		m_pbyBuff = new BYTE[0x255];
		if(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData+0x30>0x255)
		{
			return false;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData,m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData,m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData))
		{
			return false;
		}

		//Just checking for zeroes 
		for(DWORD i=0;i<0x30;i++)
		{
			if(m_pbyBuff[i]!=0x00)
			{
				return false;
			}
		}
		return true;
	}	
	return false;
}

bool CRPCryptDeJunker::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	DWORD dwOffset=m_pMaxPEFile->m_dwAEPMapped-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData;
	DWORD dwAEP=0xFFFFFFFF;
	
	DWORD dwLength = 0, dwInstructionCountFound = 0;
	char	szInstruction[1024] = {0x00};
	bool bContinue=false;
	DWORD dwRVADecryptStart=0x00;
	DWORD dwRVADecryptEnd=0x00;
	bool bXOR=false;
	BYTE byXORKey=0x00;

	CEmulate objEmulate(m_pMaxPEFile);

	while(dwOffset <= m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData)
	{
		dwLength = objEmulate.DissassemBuffer((char*)&m_pbyBuff[dwOffset],szInstruction);
		if(strstr(szInstruction,"PUSH") && dwLength==0x05 && m_pbyBuff[dwOffset]==0x68)
		{
			if(*(DWORD*)&m_pbyBuff[dwOffset+1]-m_dwImageBase<m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress)
			{
                dwAEP=*(DWORD*)&m_pbyBuff[dwOffset+1]-m_dwImageBase;
				if(*(WORD*)&m_pbyBuff[dwOffset+0x05]==0x00B8)
				{
					dwInstructionCountFound++;
					if(m_pbyBuff[dwOffset+0x0A]==0x3D && *(WORD*)&m_pbyBuff[dwOffset+0x0F]==0x0674)
					{
						byXORKey=m_pbyBuff[dwOffset+0x13];
						dwRVADecryptStart=*(DWORD*)&m_pbyBuff[dwOffset+0x6]-m_dwImageBase;
						dwRVADecryptEnd=*(DWORD*)&m_pbyBuff[dwOffset+0xB]-m_dwImageBase;
					}

				}
				break;
			}
			else if(*(DWORD*)&m_pbyBuff[dwOffset+1]-m_dwImageBase>m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress &&
				*(DWORD*)&m_pbyBuff[dwOffset+1]-m_dwImageBase<m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData)
			{
				dwOffset=*(DWORD*)&m_pbyBuff[dwOffset+1]-m_dwImageBase-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress;
				dwOffset-=dwLength;
			}
			else
			{
				return false;
			}

		}
		else if(strstr(szInstruction,"JMP") && dwLength==0x02 && *(WORD*)&m_pbyBuff[dwOffset]==0x00EB)
		{
			dwInstructionCountFound++;
		}
		
		else if(strstr(szInstruction,"XCHG") && dwLength==0x01 && (m_pbyBuff[dwOffset]&0x90)==0x90)
		{
			dwInstructionCountFound++;
		}
		dwOffset+=dwLength;

	}

	if(dwAEP==0xFFFFFFFF || dwInstructionCountFound<0x01)
	{
		return false;
	}

	if(byXORKey)
	{
		if(dwRVADecryptEnd>m_objTempFile.m_dwFileSize)
		{
			return false;
		}
		BYTE *bybuff=NULL;
		if(!(bybuff=(BYTE*)MaxMalloc(dwRVADecryptEnd-dwRVADecryptStart)))
		{
			return false;
		}
		if(!m_objTempFile.ReadBuffer(bybuff,dwRVADecryptStart,dwRVADecryptEnd-dwRVADecryptStart,dwRVADecryptEnd-dwRVADecryptStart))
		{
			free(bybuff);
			bybuff=NULL;
			return false;
		}
		for(DWORD i=0;i<dwRVADecryptEnd-dwRVADecryptStart;i++)
		{
			bybuff[i]^=byXORKey;
		}
		if(!m_objTempFile.WriteBuffer(bybuff,dwRVADecryptStart,dwRVADecryptEnd-dwRVADecryptStart,dwRVADecryptEnd-dwRVADecryptStart))
		{
			free(bybuff);
			bybuff=NULL;
			return false;
		}
		if(bybuff)
		{
			free(bybuff);
			bybuff=NULL;
		}
	}

	if(!m_objTempFile.WriteAEP(dwAEP))
	{
		return false;
	}
	return true;
}

