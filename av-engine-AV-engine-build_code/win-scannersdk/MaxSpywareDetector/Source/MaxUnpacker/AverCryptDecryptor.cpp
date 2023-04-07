#include "AverCryptDecryptor.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CAverCryptDecryptor::CAverCryptDecryptor(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
}

CAverCryptDecryptor::~CAverCryptDecryptor(void)
{
	m_objTempFile.CloseFile();
}

bool CAverCryptDecryptor::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 && (memcmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Name,".avc",4)==0x00))
	{
		const BYTE bySigbuff[]={0xE8,0x00,0x00,0x00,0x00,0x5D,0x81,0xED,0x0C,0x17,0x40};
		BYTE byBuff[sizeof(bySigbuff)] = {0};

		if(!m_pMaxPEFile->ReadBuffer(byBuff,m_pMaxPEFile->m_dwAEPMapped,sizeof(bySigbuff)+1,sizeof(bySigbuff)+1))
		{
			return false;
		}

		if(byBuff[0]==0x60 && memcmp(&byBuff[1],bySigbuff,sizeof(bySigbuff))==0x00)
		{
			return true;
		}
	}
	return false;
}

bool CAverCryptDecryptor::Unpack(LPCTSTR szTempFileName)
{	
	if(!CopyFile(m_pMaxPEFile->m_szFilePath, szTempFileName, false))
	{
		return false;
	}
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	DWORD dwOffset=m_objTempFile.m_dwAEPMapped;

	
	if(dwOffset+0x22+0x01>m_objTempFile.m_dwFileSize)
	{
		return false;
	}

	BYTE *byFullfilebuff=NULL;

	if(!(byFullfilebuff=(BYTE *)MaxMalloc(m_objTempFile.m_dwFileSize)))
	{
		return false;
	}

	memset(byFullfilebuff,0,m_objTempFile.m_dwFileSize);
	if(!m_objTempFile.ReadBuffer(byFullfilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}


	DWORD dwEBPValue=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x06-(*(DWORD*)&byFullfilebuff[dwOffset+0x09]-m_dwImageBase);
	if(dwOffset+0x0F+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}

	DWORD dwtemp1=dwEBPValue+*(DWORD*)&byFullfilebuff[dwOffset+0x0F]-m_dwImageBase-0x04;
	if(!(~(m_pMaxPEFile->Rva2FileOffset(dwtemp1,&dwtemp1))))
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}

	if(dwtemp1 + sizeof(DecryptBlock) > m_objTempFile.m_dwFileSize)
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}

	DecryptBlock *pStructDecryptBlockInfo=(DecryptBlock*)&byFullfilebuff[dwtemp1];
	pStructDecryptBlockInfo->AEP-=m_dwImageBase;
	pStructDecryptBlockInfo->dwStartSection-=m_dwImageBase;

	if(pStructDecryptBlockInfo->dwStartSection+0x28>m_objTempFile.m_dwFileSize)
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}

	if(dwOffset+0x22+0x01 > m_objTempFile.m_dwFileSize)
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}

	/*BYTE *a=(BYTE*)&(pStructDecryptBlockInfo->dwXORKeys);
	a[2]^=byFullfilebuff[dwOffset+0x22];*/
	(((BYTE*)&(pStructDecryptBlockInfo->dwXORKeys))[2])^=byFullfilebuff[dwOffset+0x22];

    //*(BYTE*)(&(pStructDecryptBlockInfo->dwXORKeys))[2]^=byFullfilebuff[dwOffset+0x22];

	DWORD dwNoofSections=pStructDecryptBlockInfo->dwNoOfSections;
	if(!(~(m_pMaxPEFile->Rva2FileOffset(pStructDecryptBlockInfo->dwStartSection,&pStructDecryptBlockInfo->dwStartSection))))
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}
	while(pStructDecryptBlockInfo->dwNoOfSections!=0x00)
	{
		//Pointer to Line Numbers Check
		if(*(DWORD*)&byFullfilebuff[pStructDecryptBlockInfo->dwStartSection+0x1C]==0xAB)
		{
			DWORD dwSrcRVA=*(DWORD*)&byFullfilebuff[pStructDecryptBlockInfo->dwStartSection+0x0C];
			if(!(~(m_pMaxPEFile->Rva2FileOffset(dwSrcRVA,&dwSrcRVA))))
			{
				free(byFullfilebuff);
				byFullfilebuff=NULL;
				return false;
			}
			DWORD dwSize=m_objTempFile.m_stSectionHeader[dwNoofSections-pStructDecryptBlockInfo->dwNoOfSections].SizeOfRawData;

			if(pStructDecryptBlockInfo->dwFlagAdd200==0x02)
			{
				dwSrcRVA+=0x200;
				dwSize-=0x200;
			}

			if((dwSize%0xC8)!=0x00)
			{
				dwSize=FANotDefault(dwSize,0xC8);
			}
			if(dwSrcRVA+dwSize>m_objTempFile.m_dwFileSize)
			{
				free(byFullfilebuff);
				byFullfilebuff=NULL;
				return false;
			}

			if(dwOffset+0xD8+0x04 > m_objTempFile.m_dwFileSize)
			{
				free(byFullfilebuff);
				byFullfilebuff=NULL;
				return false;
			}

			DWORD dwKey=*(DWORD*)&byFullfilebuff[dwOffset+0xD8];
			dwtemp1=0;
			DWORD dwtemp2=0;
			for(DWORD i=0;i<*(WORD*)&byFullfilebuff[dwOffset+0x41];i++)
			{
				for(DWORD j=0;j<dwSize;j+=8)
				{
					dwtemp1=dwKey<<0x05;
					for(DWORD k=0;k<0x20;k++)
					{
						dwtemp2=*(DWORD*)&byFullfilebuff[dwSrcRVA+j];
						dwtemp2<<=4;
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j+4]-=dwtemp2;
						dwtemp2=*(DWORD*)&(((BYTE*)&(pStructDecryptBlockInfo->dwXORKeys[2]))[2]);
						dwtemp2^=*(DWORD*)&byFullfilebuff[dwSrcRVA+j];
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j+4]-=dwtemp2;
						dwtemp2=*(DWORD*)&byFullfilebuff[dwSrcRVA+j];
						dwtemp2>>=5;
						dwtemp2^=dwtemp1;
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j+4]-=dwtemp2;
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j+4]-=*(DWORD*)&(((BYTE*)&(pStructDecryptBlockInfo->dwXORKeys[3]))[2]);
						dwtemp2=*(DWORD*)&byFullfilebuff[dwSrcRVA+j+4];
						dwtemp2<<=4;
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j]-=dwtemp2;
						dwtemp2=*(DWORD*)&(((BYTE*)&(pStructDecryptBlockInfo->dwXORKeys))[2]);
						dwtemp2^=*(DWORD*)&byFullfilebuff[dwSrcRVA+j+4];
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j]-=dwtemp2;
						dwtemp2=*(DWORD*)&byFullfilebuff[dwSrcRVA+j+4];
						dwtemp2>>=5;
						dwtemp2^=dwtemp1;
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j]-=dwtemp2;
						*(DWORD*)&byFullfilebuff[dwSrcRVA+j]-=*(DWORD*)&(((BYTE*)&(pStructDecryptBlockInfo->dwXORKeys[1]))[2]);
						dwtemp1-=dwKey;						
					}
				}
			}
		}

		if(pStructDecryptBlockInfo->dwStartSection+0x50>m_objTempFile.m_dwFileSize)
		{
			free(byFullfilebuff);
			byFullfilebuff=NULL;
			return false;
		}
		pStructDecryptBlockInfo->dwStartSection+=0x28;
		pStructDecryptBlockInfo->dwNoOfSections--;
	}

	//Writing the AEP
	*(DWORD*)&byFullfilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=pStructDecryptBlockInfo->AEP;

	if(!m_objTempFile.WriteBuffer(byFullfilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
		return false;
	}

	if(byFullfilebuff)
	{
		free(byFullfilebuff);
		byFullfilebuff=NULL;
	}

	return true;

}