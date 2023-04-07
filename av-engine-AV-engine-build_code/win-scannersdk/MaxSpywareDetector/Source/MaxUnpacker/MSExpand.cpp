#include "MSExpand.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"


#define N 4096
#define F 16

CMSExpand::CMSExpand(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
	m_pbyBuff = new BYTE[255];
	m_dwHrdOffset = 0x00;
	m_pHeader = NULL;
}

CMSExpand::~CMSExpand(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	if (m_pHeader)
	{
		delete[] m_pHeader;
		m_pHeader = NULL;
	}
	m_objTempFile.CloseFile();

}

bool CMSExpand::IsPacked() 
{
	WORD wNoOfSections = m_pMaxPEFile->m_stPEHeader.NumberOfSections;
	if(!(m_pMaxPEFile->m_dwFileSize > (m_pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].SizeOfRawData + m_pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].PointerToRawData + 0x200)))
	{
		return false;
	}

	m_pHeader=new MS_header_struct[1];
	
	m_dwHrdOffset = m_pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].PointerToRawData + m_pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].SizeOfRawData  + 0xA00;
	BYTE bTempBuff[0x100] = {0x00};
	BYTE bMSEpHrd[] = {0x53, 0x5A, 0x44, 0x44};
	if(!m_pMaxPEFile->ReadBuffer(bTempBuff, m_dwHrdOffset, 0x100, 0x100))
	{
		return false;
	}

	for(int i = 0x00; i <= 0x9C; i++)
	{
		if(memcmp(&bTempBuff[i], bMSEpHrd, sizeof(bMSEpHrd)) == 0x00)
		{
			m_dwHrdOffset+=i;
			break;
		}
		if(i == 0x9C)
		{
			return false;
		}
	}


	if(!m_pMaxPEFile->ReadBuffer(m_pHeader, m_dwHrdOffset, sizeof(MS_header_struct), sizeof(MS_header_struct)))
	{
		return false;
	}

	if(*(DWORD*)&m_pHeader->magic!=0x44445A53 || *(DWORD*)&m_pHeader->magic2!=0x3327F088 || *(WORD*)&m_pHeader->magic3!=0x41)
	{
		return false;
	}
	return true;
}

bool CMSExpand::Unpack(LPCTSTR szTempFileName)
{	
	BYTE *byFullFilebuff=NULL;
	BYTE *byDecompressedbuff=NULL;
	DWORD dwMsFileSize = m_pMaxPEFile->m_dwFileSize - m_dwHrdOffset;

	if(!(byFullFilebuff=(BYTE*)MaxMalloc(dwMsFileSize-sizeof(MS_header_struct))))
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(byFullFilebuff,sizeof(MS_header_struct) + m_dwHrdOffset,dwMsFileSize-sizeof(MS_header_struct)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(!(byDecompressedbuff=(BYTE*)MaxMalloc(*(DWORD*)&m_pHeader->filesize)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	memset(byDecompressedbuff,0,*(DWORD*)&m_pHeader->filesize);

	WORD bits,i,j,len,mask;
    BYTE *by_buffer=new BYTE[0x1000];

	if (!by_buffer)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byDecompressedbuff);
		byDecompressedbuff=NULL;
		return false;
	}

	memset(by_buffer,0,0x1000);
	DWORD dwSrcbuffpointer=0;
	DWORD dwDecompressbuffpointer=0;


	i=4080;
	while(dwSrcbuffpointer<m_pMaxPEFile->m_dwFileSize && dwDecompressbuffpointer<*(DWORD*)&m_pHeader->filesize)
	{
        bits=byFullFilebuff[dwSrcbuffpointer++];
		for(mask=0x01;(mask&0xFF) && (dwSrcbuffpointer<m_pMaxPEFile->m_dwFileSize) && (dwDecompressbuffpointer<*(DWORD*)&m_pHeader->filesize);mask<<=1)
		{
			if(!(bits&mask))
			{
				if(dwSrcbuffpointer+1>m_pMaxPEFile->m_dwFileSize)
				{
					if(by_buffer)
					{
						delete[] by_buffer;
						by_buffer=NULL;
					}
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					free(byDecompressedbuff);
					byDecompressedbuff=NULL;
					return false;

				}
				if(dwSrcbuffpointer+1>m_pMaxPEFile->m_dwFileSize)
				{
					if(by_buffer)
					{
						delete[] by_buffer;
						by_buffer=NULL;
					}
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					free(byDecompressedbuff);
					byDecompressedbuff=NULL;
					return false;

				}
				j=byFullFilebuff[dwSrcbuffpointer++];
				if(j==-1)
				{
					break;
				}
				if(dwSrcbuffpointer+1>m_pMaxPEFile->m_dwFileSize)
				{
					if(by_buffer)
					{
						delete[] by_buffer;
						by_buffer=NULL;
					}
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					free(byDecompressedbuff);
					byDecompressedbuff=NULL;
					return false;

				}
				len=byFullFilebuff[dwSrcbuffpointer++];
				j+=(len&0xF0)<<4;
				len=(len&15)+3;

				while(len--)
				{
					by_buffer[i]=by_buffer[j];
					if(dwDecompressbuffpointer+1>*(DWORD*)&m_pHeader->filesize)
					{
						if(by_buffer)
						{
							delete[] by_buffer;
							by_buffer=NULL;
						}
						free(byFullFilebuff);
						byFullFilebuff=NULL;
						free(byDecompressedbuff);
						byDecompressedbuff=NULL;
						return false;

					}
					byDecompressedbuff[dwDecompressbuffpointer++]=by_buffer[i];
					j=(j+1)&(N-1);
					i=(i+1)&(N-1);
					
				}
			}
			else
			{
				by_buffer[i]=byFullFilebuff[dwSrcbuffpointer++];
				if(dwDecompressbuffpointer+1>*(DWORD*)&m_pHeader->filesize)
				{
					if(by_buffer)
					{
						delete[] by_buffer;
						by_buffer=NULL;
					}

					free(byFullFilebuff);
					byFullFilebuff=NULL;
					free(byDecompressedbuff);
					byDecompressedbuff=NULL;
					return false;

				}
				byDecompressedbuff[dwDecompressbuffpointer++]=by_buffer[i];
				i=(i+1)&(N-1);
			}
		}
	}

	if(by_buffer)
	{
		delete[] by_buffer;
		by_buffer=NULL;
	}

	

	HANDLE hTempFile = CreateFile(szTempFileName, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
	if(hTempFile == INVALID_HANDLE_VALUE)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		if(byDecompressedbuff)
		{
			free(byDecompressedbuff);
			byDecompressedbuff=NULL;
		}
		return false;
	}
	::CloseHandle(hTempFile);

	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		if(byDecompressedbuff)
		{
			free(byDecompressedbuff);
			byDecompressedbuff=NULL;
		}
		return false;
	}

	if(!m_objTempFile.WriteBuffer(byDecompressedbuff,0,*(DWORD*)&m_pHeader->filesize,*(DWORD*)&m_pHeader->filesize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		if(byDecompressedbuff)
		{
			free(byDecompressedbuff);
			byDecompressedbuff=NULL;
		}
		return false;
	}

	if(byFullFilebuff)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
	}
	

	if(byDecompressedbuff)
	{
		free(byDecompressedbuff);
		byDecompressedbuff=NULL;
	}

	
	return true;
}