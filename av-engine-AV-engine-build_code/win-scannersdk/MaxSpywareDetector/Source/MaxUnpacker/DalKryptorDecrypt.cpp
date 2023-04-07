#include "DalKryptorDecrypt.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CDalKryptorDecrypt::CDalKryptorDecrypt(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
}

CDalKryptorDecrypt::~CDalKryptorDecrypt(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CDalKryptorDecrypt::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Name, ".Dalkit", 7) == 0))
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x23,0x23))
		{
			return false;
		}
		if(m_pbyBuff[0] == 0x68 && *(WORD*)&m_pbyBuff[5]==0x6858 && *(DWORD*)&m_pbyBuff[0xB]==0xEBDB335F 
			&& *(DWORD*)&m_pbyBuff[0x0F]==0x03148A0D )
		{
			return true;
		}
	}
	return false;
}

bool CDalKryptorDecrypt::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	BYTE *byDalKryptorbuff=NULL;
	DWORD dwSize=*(DWORD*)&m_pbyBuff[0x1F];
	if(!(byDalKryptorbuff=(BYTE*)MaxMalloc(dwSize)))
	{
		return false;
	}
	memset(byDalKryptorbuff,0x0,dwSize);
	if(!m_objTempFile.ReadBuffer(byDalKryptorbuff,*(DWORD*)&m_pbyBuff[0x1]-m_dwImageBase,dwSize,dwSize))
	{
		free(byDalKryptorbuff);
		byDalKryptorbuff = NULL;
		return false;
	}

	for(DWORD dwCounter=0x00;dwCounter<dwSize;dwCounter++)
	{
		//Just now decrypting by a fixed value as all samples are same
		byDalKryptorbuff[dwCounter]-=0x07;
		byDalKryptorbuff[dwCounter]^=0x04;
	}

	if(!m_objTempFile.WriteBuffer(byDalKryptorbuff,*(DWORD*)&m_pbyBuff[0x1]-m_dwImageBase,dwSize,dwSize))
	{
		free(byDalKryptorbuff);
		byDalKryptorbuff = NULL;
		return false;
	}

	if(byDalKryptorbuff)
	{
		free(byDalKryptorbuff);
		byDalKryptorbuff = NULL;
	}

	if(!m_objTempFile.WriteAEP(*(DWORD*)&m_pbyBuff[0x7]-m_dwImageBase))
	{
		return false;
	}
	return true;
}

