#include "MaxMACUBFile.h"
#include <string.h>

CMaxMACUBFile::CMaxMACUBFile(void)
{
	m_bIsBigEndian = false;
	m_ulDisplacement = 0x00;
    
	memset(&m_objFATHeader,0x00,sizeof(m_objFATHeader));
	m_pobjFATArray = NULL;

	//strcpy(m_szTempPath,"C:\\Zv\\2");
}

CMaxMACUBFile::~CMaxMACUBFile(void)
{
	InitializeUBStructs();
}

bool CMaxMACUBFile::InitializeUBStructs()
{
	if (m_objFATHeader.nfat_arch > 0x00)
	{
		for (DWORD i = 0x00; i < m_objFATHeader.nfat_arch; i++)
		{
			if (m_pobjFATArray[i] != NULL)
			{
				delete m_pobjFATArray[i];
			}
		}
		if (m_pobjFATArray != NULL)
		{
			delete m_pobjFATArray;
		}
	}
	
    m_pobjFATArray = NULL;
	memset(&m_objFATHeader,0x00,sizeof(m_objFATHeader));
	return true;
}

/**********************************************************************
Function Name	:	IsValidUBFile
Author			:	Tushar & Sandeep
Scope			:	Public
Input			:	CMaxPEFile Object
Output			:   true if MAC UB File, else false
**********************************************************************/
bool CMaxMACUBFile::IsValidUBFile(CMaxPEFile *pMaxPEFile)
{
	bool				bRet = false;
	unsigned char		bMAC_UB_BE[] = {0xCA, 0xFE, 0xBA, 0xBE}; //FAT_MAGIC
	unsigned char		bMAC_UB_LE[] = {0xBE, 0xBA, 0xFE, 0xCA}; //FAT_CIGAM
	unsigned char		bHeaderBuff[0x08] = {0x00};

	DWORD				bytesRead = 0;

	m_bIsBigEndian = false;
	pMaxPEFile->ReadBuffer(&bHeaderBuff[0x00], 0 , sizeof(bHeaderBuff), sizeof(bHeaderBuff), &bytesRead);
	if (memcmp(&bHeaderBuff[0x00],&bMAC_UB_BE[0x00],sizeof(bMAC_UB_BE)) == 0x00)
	{
		m_bIsBigEndian = true;
		return true;
	}
	if (memcmp(&bHeaderBuff[0x00],&bMAC_UB_LE[0x00],sizeof(bMAC_UB_LE)) == 0x00)
	{
		return true;
	}

	return bRet;
}

bool CMaxMACUBFile::GetUBHeaderStructure(CMaxPEFile *pMaxPEFile)
{
	bool		bRet = false;
    DWORD		bytesRead = 0;
	DWORD		uiFileOffSet = m_ulDisplacement;


	pMaxPEFile->ReadBuffer((unsigned char *)&m_objFATHeader, uiFileOffSet, sizeof(m_objFATHeader), sizeof(m_objFATHeader) , &bytesRead);
	if (true == m_bIsBigEndian)
	{
		//m_objFATHeader.nfat_arch = __builtin_bswap32(m_objFATHeader.nfat_arch);
		m_objFATHeader.nfat_arch = _byteswap_ulong(m_objFATHeader.nfat_arch);
		
	}

	if (m_objFATHeader.nfat_arch == 0x00 || m_objFATHeader.nfat_arch > 0x04)
	{
        m_objFATHeader.nfat_arch = 0;
		return bRet;
	}
    
    m_pobjFATArray = new LPFAT_ARCH[m_objFATHeader.nfat_arch];
	if (m_pobjFATArray == NULL)
	{
		return bRet;
	}

	for(DWORD i = 0x00; i < m_objFATHeader.nfat_arch; i++)
	{
        m_pobjFATArray[i] = new FAT_ARCH;
		uiFileOffSet = uiFileOffSet + bytesRead;
		pMaxPEFile->ReadBuffer((unsigned char *)m_pobjFATArray[i], uiFileOffSet, sizeof(FAT_ARCH), sizeof(FAT_ARCH), &bytesRead);
		ConvertBEToLB(m_pobjFATArray[i]);
	}
	
	return true;
}

bool CMaxMACUBFile::ConvertBEToLB(LPFAT_ARCH pFatArch)
{
	/*
	pFatArch->cputype = __builtin_bswap32(pFatArch->cputype);
	pFatArch->cpusubtype = __builtin_bswap32(pFatArch->cpusubtype);
	pFatArch->offset = __builtin_bswap32(pFatArch->offset);
	pFatArch->size = __builtin_bswap32(pFatArch->size);
	pFatArch->align = __builtin_bswap32(pFatArch->align);
	*/
	pFatArch->cputype = _byteswap_ulong(pFatArch->cputype);
	pFatArch->cpusubtype = _byteswap_ulong(pFatArch->cpusubtype);
	pFatArch->offset = _byteswap_ulong(pFatArch->offset);
	pFatArch->size = _byteswap_ulong(pFatArch->size);
	pFatArch->align = _byteswap_ulong(pFatArch->align);
	return true;
}

int	CMaxMACUBFile::ExtractUBFile(CMaxPEFile *pMaxPEFile,int *iFileCount, bool bIsBEndian, unsigned long ulStartOffSet)
{
	int				iRet = 0x00, iRetOffSet = 0x00;
	TCHAR			szNewFilePath[1024] = {0x00};
	unsigned char	bBuff[0x5000] = {0x00};
	int				iNoofUBFiles = 0x00;
	int				iFCount = 0x00;
	
	if (m_bIsBigEndian != true)
	{
		m_bIsBigEndian = bIsBEndian;
	}
	m_ulDisplacement = 	ulStartOffSet;

    if(!GetUBHeaderStructure(pMaxPEFile))
    {
        return iRet;
    }

	if (iFileCount != NULL)
	{
		iFCount = *iFileCount; 
	}
	
	iNoofUBFiles = m_objFATHeader.nfat_arch;
	for (DWORD i = 0x00; i < iNoofUBFiles; i++)
	{
		
		_stprintf(szNewFilePath, L"%s\\%.4d.ub", m_szTempPath,i + 1 + iFCount);

		HANDLE	hNewFile = CreateFile(szNewFilePath,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
		if (hNewFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hNewFile);
			hNewFile = INVALID_HANDLE_VALUE;
		}

        CMaxPEFile *m_pTempFile = new CMaxPEFile();
        if (!m_pTempFile->OpenFile(szNewFilePath, true))
        {
            return iRet;
        }
        
		DWORD		dwBytesRead = 0x00;
		DWORD		dwBytes2Read = 0x5000;
		DWORD		dwTotalBytesWritten = 0x00;
		DWORD		dwRet = 0x00;	
		
        DWORD		uOffset = m_pobjFATArray[i]->offset + m_ulDisplacement;
		while(1)
		{
            
			dwBytes2Read = 0x5000;
            
			if ((dwTotalBytesWritten + dwBytes2Read) > m_pobjFATArray[i]->size)
			{
				dwBytes2Read = m_pobjFATArray[i]->size - dwTotalBytesWritten;
			}

			pMaxPEFile->ReadBuffer(&bBuff[0x00],uOffset,dwBytes2Read,dwBytes2Read,&dwBytesRead);
            m_pTempFile->WriteBuffer(&bBuff[0x00],dwTotalBytesWritten,dwBytesRead,0x00,&dwRet);
			if (dwBytes2Read > dwBytesRead)
			{
				break;
			}
			dwTotalBytesWritten+=dwRet;
			if (m_pobjFATArray[i]->size <= 	dwTotalBytesWritten)
			{
				iRetOffSet += dwBytesRead;
				break;
			}
            uOffset += dwBytesRead;
			iRetOffSet += dwBytesRead;
		}
		iRet++;
		
        delete m_pTempFile;
	}
	if (iFileCount != NULL)
	{
		(*iFileCount)+=iRet;
	}

	if (iRetOffSet == 0x00)
	{
		if (ulStartOffSet > 0x00)
		{
			iRetOffSet = ulStartOffSet + m_pobjFATArray[iNoofUBFiles - 0x01]->offset + m_pobjFATArray[iNoofUBFiles - 0x01]->size;
			iRet = iRetOffSet;
		}
	}
	else
	{
		iRet = iRetOffSet;
	}
	return iRet;
}

bool	CMaxMACUBFile::SetDestDirPath(LPCTSTR pszDestPath)
{
	_stprintf(m_szTempPath,L"%s",pszDestPath); 
	return true;
}