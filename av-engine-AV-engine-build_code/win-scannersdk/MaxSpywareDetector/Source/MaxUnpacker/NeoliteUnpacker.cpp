#include "NeoliteUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CNeoliteUnpacker::CNeoliteUnpacker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
}

CNeoliteUnpacker::~CNeoliteUnpacker(void)
{
	m_objTempFile.CloseFile();
}

bool CNeoliteUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections >= 0x04 && 
		*(DWORD*)&m_pMaxPEFile->m_stSectionHeader[0].Name == 0x00615045 &&
		*(DWORD*)&m_pMaxPEFile->m_stSectionHeader[1].Name == 0x00625045)
	{
		const BYTE byNeolitebuff[]={0xE9,0xBE,0x00,0x00,0x00,0x55,0x8B,0xEC,0x50,0x83,0x7D,0x08,0x00,0x58,0xC9,0xC2};
		BYTE *pbyBuff = new BYTE[sizeof(byNeolitebuff)];
		if(m_pMaxPEFile->ReadBuffer(pbyBuff,m_pMaxPEFile->m_dwAEPMapped,sizeof(byNeolitebuff),sizeof(byNeolitebuff)))
		{
			if(memcmp(pbyBuff, byNeolitebuff, sizeof(byNeolitebuff)) == 0x00)
			{
				delete []pbyBuff;
				return true;
			}
		}
		delete []pbyBuff;
	}
	return false;
}

bool CNeoliteUnpacker::Unpack(LPCTSTR szTempFileName)
{
	bool bRet = false;
	if(!ReOrganizeFile(szTempFileName))
	{
		return bRet;
	}
	BYTE *byFullFilebuff = NULL;
	if(!(byFullFilebuff = (BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize)))
	{
		return bRet;
	}
	if(!m_objTempFile.ReadBuffer(byFullFilebuff, 0, m_objTempFile.m_dwFileSize, m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff = NULL;
		return bRet;
	}

	DWORD dwSrcRVA = *(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0xFC+1];
	DWORD dwDestRVA = *(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0xFC+7]+dwSrcRVA-m_dwImageBase;
	dwSrcRVA -= m_dwImageBase;
    DWORD dwDestSize = *(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0xFC+0x5E]+m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0xFC+0x5D+0x05;
	dwDestSize = *(DWORD*)&byFullFilebuff[dwDestSize+1];

	 //********Decryption Starts***********//

	//To get the Decryption Key
	BYTE byDecryptionKey[4]={0x00};
	DWORD dwImagebase=(m_dwImageBase&0xFFFFFF00)|LOBYTE(HIWORD((dwDestSize)));
	dwImagebase=(dwImagebase*0x08)+HIBYTE(HIWORD((dwDestSize)))+HIBYTE(LOWORD((dwDestSize)))+(LOBYTE(LOWORD((dwDestSize)))*0x1019);
	*(DWORD*)&byDecryptionKey=LOWORD(dwImagebase)*0x10001;
	*(DWORD*)&byDecryptionKey+=LOBYTE(LOWORD((dwDestSize)));
	*(DWORD*)&byDecryptionKey^=dwDestSize;

	//Performing the Decryption here
	dwSrcRVA+=0x14;
	dwDestSize=*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0xFC+0x5E+0x19];
	BYTE by2DecryptionKey[4]={0xA5,0x6C,0x59,0xAC};

	for(DWORD dwCounter=0;dwCounter<dwDestSize;dwCounter++)
	{
		byFullFilebuff[dwSrcRVA+dwCounter]^=(byDecryptionKey[dwCounter%0x04]^by2DecryptionKey[dwCounter%0x04]);
	}

    //********Decryption Ends***********//

	//*********Decompression Starts***********//

	//Decompression

	BYTE *byDestbuff=NULL;
	dwSrcRVA-=0x14;
	if(!(byDestbuff=(BYTE*)MaxMalloc(*(DWORD*)&byFullFilebuff[dwSrcRVA+0x04])))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return bRet;
	}
	if(!(dwDestSize=NeoliteUncompress(*(DWORD*)&byFullFilebuff[dwSrcRVA+0x08],(DWORD*)&byFullFilebuff[dwSrcRVA+0x04],0x00,0x00,NULL,NULL,&byFullFilebuff[dwSrcRVA+0x14+0xA],byDestbuff)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;

		free(byDestbuff);
		byDestbuff=NULL;
		return bRet;
	}

	//dwDestSize=*(DWORD*)&byFullFilebuff[dwSrcRVA+0x04];
	for(DWORD i=0;i<dwDestSize;i++)
	{
		byFullFilebuff[dwDestRVA+i]=byDestbuff[i];
	}

	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff=NULL;
	}

	bRet = m_objTempFile.WriteBuffer(byFullFilebuff,0x00,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize);
	
	free(byFullFilebuff);
	byFullFilebuff=NULL;    
	
	return bRet;
}