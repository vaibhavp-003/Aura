#include "SMPackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CSMPackUnpacker::CSMPackUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{
	m_dwOffset=m_pMaxPEFile->m_dwAEPMapped;	
}

CSMPackUnpacker::~CSMPackUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CSMPackUnpacker::IsPacked() 
{
	if((memcmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01].Name,".web",0x04)==0x00))
	{	
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}
		if(m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwOffset,0xB,0xB))
		{
			if(*(WORD *)&m_pbyBuff[0] == 0x8B55)
			{
				if(m_pMaxPEFile->m_wAEPSec==0x00)
				{
					if(*(DWORD*)&m_pbyBuff[3]==0xE95DEC87)
					{
						m_dwOffset=*(DWORD*)&m_pbyBuff[7]+m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint+0x0B;
						if(OUT_OF_FILE==m_pMaxPEFile->Rva2FileOffset(m_dwOffset,&m_dwOffset))
						{
							return false;
						}
						return true;
					}
				}
				else 
				{
					if(*(DWORD*)&m_pbyBuff[3]==0x5648EC83 && m_pbyBuff[7]==0x57)
					{
						return true;
					}

				}
			}
		}
	}
	return false;
}

bool CSMPackUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_dwOffset + 0x2F, 0x04, 0x04))
	{
		return false;
	}
	m_dwOffset = *(DWORD*)&m_pbyBuff[0];
	if(OUT_OF_FILE==m_pMaxPEFile->Rva2FileOffset(m_dwOffset-m_dwImageBase,&m_dwOffset))
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwOffset,0x23,0x23))
	{
		return false;	
	}

	DWORD dwImportTableRVA=*(DWORD*)&m_pbyBuff[0];
	BYTE byXORKey=m_pbyBuff[8];
	BYTE byBytestoRead=0x00;
	if(m_pbyBuff[0x22]!=0)
	{
		byBytestoRead=m_pbyBuff[0x22];
	}

	DWORD dwWrite=*(DWORD*)&m_pbyBuff[4];
	DWORD dwOffset=*(DWORD*)&m_pbyBuff[9];
	m_dwOffset+=0xA3;
	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwOffset+dwOffset,byBytestoRead,byBytestoRead))
	{
		return false;
	}

	if(dwWrite>m_objTempFile.m_dwFileSize)
	{
		return false;
	}

	if(!m_objTempFile.WriteBuffer(m_pbyBuff,dwWrite,byBytestoRead,byBytestoRead))
	{
		return false;
	}

	DWORD dwStart=0x00;
	DWORD dwSize=0x00;
	BYTE *bySrcBuff=NULL;
	while(1 && m_dwOffset<(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01].PointerToRawData+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01].SizeOfRawData))
	{
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwOffset,0x08,0x08))
		{
			return false;
		}

		//Offset to read
		dwStart=*(DWORD*)&m_pbyBuff[0];
		if(dwStart==0x00)
			break;
		dwSize=*(DWORD*)&m_pbyBuff[4];

		if(dwSize!=0x00)
		{
			if(!(bySrcBuff=(BYTE *)MaxMalloc(dwSize)))
			{
				return false;
			}
			memset(bySrcBuff,0,dwSize);

			//Reading the encrypted buffer
			if(!m_objTempFile.ReadBuffer(bySrcBuff,dwStart,dwSize,dwSize))
			{
				free(bySrcBuff);
				bySrcBuff=NULL;
				return false;
			}

			//Decryption Loop
			for(DWORD dwcounter=0;dwcounter<dwSize;dwcounter++)
			{
				DWORD temp=((dwcounter&0x7FFFFFFF)*0x51)+(dwcounter&0x80000000);
				temp^=bySrcBuff[dwcounter];
				temp+=0x6C;
				temp^=byXORKey;
				temp=~temp;
				bySrcBuff[dwcounter]=(BYTE)temp;
			}

			//Writing the decrypted buffer
			if(!m_objTempFile.WriteBuffer(bySrcBuff,dwStart,dwSize,dwSize))
			{
				free(bySrcBuff);
				bySrcBuff=NULL;
				return false;
			}

			if(bySrcBuff)
			{
				free(bySrcBuff);
				bySrcBuff=NULL;
			}
		}
		//Moving to the next Offset to read and Size of encrypted buffer
		m_dwOffset+=0x08;

	}

	//Writing the AEP
	if(!m_objTempFile.WriteAEP(dwWrite))
	{
		return false;
	}

	//Writing the Import Table
	if(!m_objTempFile.WriteBuffer(&dwImportTableRVA,m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0x68, 0x04, 0x04))
	{
		return false;
	}
	return true;
}
