#include "PECryptCFDecrypt.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CPECryptCFDecrypt::CPECryptCFDecrypt(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
	m_pStructDecryptBlockInfo=NULL;
}

CPECryptCFDecrypt::~CPECryptCFDecrypt(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pStructDecryptBlockInfo=NULL;
	m_objTempFile.CloseFile();

}

bool CPECryptCFDecrypt::IsPacked() 
{	
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint&0x000000FF) < 0x60)
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x10,0x10))
		{
			return false;
		}
		m_dwOffset=0;

		//Look for CLC,JNB
		if(*(WORD*)&m_pbyBuff[0]==0x73F8)
		{
			m_dwOffset=2;
			if(m_dwOffset+0x01>0x10)
			{
				return false;			
			}
			m_dwOffset+=m_pbyBuff[m_dwOffset]+0x01;
			if(m_dwOffset+0x01>0x10)
			{
				return false;
			}
			//Look for PUSHAD
			if(m_pbyBuff[m_dwOffset]==0x60)
			{
				m_dwOffset+=0x01;
				return true;
			}
		}
	}
	return false;
}


bool CPECryptCFDecrypt::Unpack(LPCTSTR szTempFileName)
{	
	if(!CopyFile(m_pMaxPEFile->m_szFilePath, szTempFileName, false))
	{
		return false;
	}
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	BYTE *bySrcbuff=NULL;
	DWORD dwSize=0x1000;
	if(!(bySrcbuff=(BYTE*)MaxMalloc(dwSize)))
	{
		return false;
	}

	if(!m_objTempFile.ReadBuffer(bySrcbuff,(m_objTempFile.m_dwAEPMapped&0xFFFFFF00),dwSize,dwSize))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		return false;
	}

	m_dwOffset+=(m_objTempFile.m_dwAEPMapped&0x000000FF);
	DWORD dwOrigAEP=0;
	DWORD dwDecryptionKey=0;

	DWORD dwLength = 0, dwInstructionCountFound = 0;
	char	szInstruction[1024] = {0x00};

	CEmulate objEmulate(m_pMaxPEFile);

	while(m_dwOffset+0x30 < 0x1000)
	{
		dwLength = objEmulate.DissassemBuffer((char*)&bySrcbuff[m_dwOffset],szInstruction);
		if(strstr(szInstruction,"JMP") && dwLength==0x02)
		{
			m_dwOffset+=bySrcbuff[m_dwOffset+0x01];
			dwInstructionCountFound++;
		}

		else if(strstr(szInstruction,"CALL") && dwLength==0x05)
		{
			m_dwOffset+=*(DWORD*)&bySrcbuff[m_dwOffset+0x01];
		}

		else if(strstr(szInstruction,"JZ") && dwLength==0x06)
		{
			dwOrigAEP=m_dwOffset;
			m_dwOffset+=*(DWORD*)&bySrcbuff[m_dwOffset+0x02];

		}

		else if(strstr(szInstruction,"JB") && dwLength==0x02)
		{
			m_dwOffset+=bySrcbuff[m_dwOffset+0x01];
			dwInstructionCountFound++;
		}

		else if(strstr(szInstruction,"SUB") && dwLength==0x06)
		{
			dwDecryptionKey=*(DWORD*)&bySrcbuff[m_dwOffset+0x02];
			break;
		}

		//E9 jump goes to AEP
		else if((strstr(szInstruction,"JMP") && dwLength==0x05))
		{
			m_dwOffset+=*(DWORD*)&bySrcbuff[m_dwOffset+0x01];
			m_dwOffset+=(m_objTempFile.m_stPEHeader.AddressOfEntryPoint&0xFFFFFF00);
			m_dwOffset+=0x05;
			dwOrigAEP^=m_dwOffset;
			m_dwOffset^=dwOrigAEP;
			dwOrigAEP^=m_dwOffset;
			m_dwOffset+=0x01;
			dwInstructionCountFound=0;
		}
		m_dwOffset+=dwLength;
	}

	if(dwDecryptionKey && dwOrigAEP)
	{
		m_dwOffset=0x00;
		DWORD dwCounter=*(DWORD*)&bySrcbuff[0];
		m_dwOffset+=0x04;
		BYTE *byDestbuff=NULL;

		if(!(byDestbuff=(BYTE*)MaxMalloc(0x01)))
		{
			free(bySrcbuff);
			bySrcbuff=NULL;
			return false;
		}
		while(m_dwOffset+sizeof(DecryptBlock) <= 0x1000 && dwCounter!=0x00)
		{
			m_pStructDecryptBlockInfo=(DecryptBlock*)&bySrcbuff[m_dwOffset];

			if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_pStructDecryptBlockInfo->dwSize*0x04)))
			{
				free(bySrcbuff);
				bySrcbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				return false;
			}

			if(OUT_OF_FILE==m_objTempFile.Rva2FileOffset(m_pStructDecryptBlockInfo->dwRVA+m_dwOffset+(m_objTempFile.m_stPEHeader.AddressOfEntryPoint&0xFFFFFF00),&m_pStructDecryptBlockInfo->dwRVA))
			{
				free(bySrcbuff);
				bySrcbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				return false;
			}

			if(!m_objTempFile.ReadBuffer(byDestbuff,m_pStructDecryptBlockInfo->dwRVA,m_pStructDecryptBlockInfo->dwSize*0x04,m_pStructDecryptBlockInfo->dwSize*0x04))
			{
				free(bySrcbuff);
				bySrcbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				return false;
			}

			//Performing the Decryption
			for(DWORD i=0;i<m_pStructDecryptBlockInfo->dwSize;i++)
			{
				*(DWORD*)&byDestbuff[i*0x04]-=dwDecryptionKey;
			}

			if(!m_objTempFile.WriteBuffer(byDestbuff,m_pStructDecryptBlockInfo->dwRVA,m_pStructDecryptBlockInfo->dwSize*0x04,m_pStructDecryptBlockInfo->dwSize*0x04))
			{
				free(bySrcbuff);
				bySrcbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				return false;
			}
			m_dwOffset+=sizeof(DecryptBlock);
			dwCounter--;
		}

		if(m_objTempFile.WriteAEP(dwOrigAEP))
		{
			if(bySrcbuff)
			{
				free(bySrcbuff);
				bySrcbuff=NULL;
			}
			if(byDestbuff)
			{
				free(byDestbuff);
				byDestbuff=NULL;
			}
			return true;
		}
	}
	else
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		return false;
	}	
	return false;
}