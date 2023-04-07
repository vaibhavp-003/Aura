#include "VGCryptDecrypt.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CVGCryptDecrypt::CVGCryptDecrypt(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
	m_pStructDecryptBlockInfo=NULL;
}

CVGCryptDecrypt::~CVGCryptDecrypt(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pStructDecryptBlockInfo=NULL;
	m_objTempFile.CloseFile();

}

bool CVGCryptDecrypt::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize-m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint==0x158 )
	{
		m_pbyBuff = new BYTE[255];
		BYTE bySigbuff[]={0x55, 0xE8,0xEC ,0x00 ,0x00 ,0x00 ,0x87 ,0xD5 ,0x5D ,0x60 ,0x87 ,0xD5 ,0x80 ,0xBD};
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,sizeof(bySigbuff)+0x01,sizeof(bySigbuff)+0x01))
		{
			return false;
		}

		if(m_pbyBuff[0]==0x9C && memcmp(&m_pbyBuff[1],bySigbuff,sizeof(bySigbuff))==0x00)
		{
			return true;
		}
	}
	return false;
}

bool CVGCryptDecrypt::Unpack(LPCTSTR szTempFileName)
{	
	if(!CopyFile(m_pMaxPEFile->m_szFilePath, szTempFileName, false))
	{
		return false;
	}
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	DWORD dwOffset=m_pMaxPEFile->m_dwAEPMapped+0x23;

	if(!m_objTempFile.ReadBuffer(m_pbyBuff,dwOffset,0xCE))
	{
		return false;
	}

	BYTE byFirstKey=m_pbyBuff[0xCA];
	DWORD dwSecondKey=0;

	//First Decryption
	for(DWORD i=0;i<0xCA;i++)
	{
		m_pbyBuff[i]^=byFirstKey;
		byFirstKey++;
		MAX_ROL(byFirstKey,2);
		byFirstKey+=0x90;
	}


	DWORD dwCounter=0xCE-0x48;
	BYTE *byDesbuff=NULL;

	if(!(byDesbuff=(BYTE*)MaxMalloc(0x01)))
	{
		return false;
	}

	while(dwCounter+sizeof(DecryptBlock)<=(0xCE-0x0C))
	{
		m_pStructDecryptBlockInfo=(DecryptBlock*)&m_pbyBuff[dwCounter];

		//Actual true case to break
		if(m_pStructDecryptBlockInfo->dwRVA==0x00)
		{
			break;
		}

		if(OUT_OF_FILE==m_objTempFile.Rva2FileOffset(m_pStructDecryptBlockInfo->dwRVA,&m_pStructDecryptBlockInfo->dwRVA))
		{
			if(byDesbuff)
			{
				free(byDesbuff);
				byDesbuff=NULL;
			}
			return false;
		}

		if(!(byDesbuff=(BYTE*)realloc(byDesbuff,m_pStructDecryptBlockInfo->dwSize)))
		{
			if(byDesbuff)
			{
				free(byDesbuff);
				byDesbuff=NULL;
			}
			return false;
		}

		//Reading the buffer to be decrypted from the file
		if(!m_objTempFile.ReadBuffer(byDesbuff,m_pStructDecryptBlockInfo->dwRVA,m_pStructDecryptBlockInfo->dwSize))
		{
			if(byDesbuff)
			{
				free(byDesbuff);
				byDesbuff=NULL;
			}
			return false;

		}

		dwSecondKey=*(DWORD*)&m_pbyBuff[0xCA];
		//Second Decryption
		for(DWORD i=0;i<(m_pStructDecryptBlockInfo->dwSize/0x04);i++)
		{
			*(DWORD*)&byDesbuff[i*0x04]+=dwSecondKey;
			*(DWORD*)&byDesbuff[i*0x04]^=dwSecondKey;
			MAX_ROR(dwSecondKey,1);
			dwSecondKey-=0x90807066;
			dwSecondKey+=dwSecondKey;
		}

		//Writing the Decrypted buffer back to file
		if(!m_objTempFile.WriteBuffer(byDesbuff,m_pStructDecryptBlockInfo->dwRVA,m_pStructDecryptBlockInfo->dwSize,m_pStructDecryptBlockInfo->dwSize))
		{
			if(byDesbuff)
			{
				free(byDesbuff);
				byDesbuff=NULL;
			}
			return false;
		}

		dwCounter+=sizeof(DecryptBlock);
	}

	if(byDesbuff)
	{
		free(byDesbuff);
		byDesbuff=NULL;
	}

	//Writing AEP
	if(m_objTempFile.WriteAEP(*(DWORD*)&m_pbyBuff[0xCE-0x0C]))
	{
		return true;
	}

	return false;
}