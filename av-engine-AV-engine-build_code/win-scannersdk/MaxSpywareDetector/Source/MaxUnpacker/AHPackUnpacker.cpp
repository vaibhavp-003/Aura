#include "AHPackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CAHPackUnpacker::CAHPackUnpacker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
}

CAHPackUnpacker::~CAHPackUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CAHPackUnpacker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(m_pMaxPEFile->m_wAEPSec == m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01) &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01].Name, ".data", 5) == 0) &&
		 m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-0x01].Misc.VirtualSize==0x400 )
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x30,0x30))
		{
			return false;
		}
		if(*(WORD*)&m_pbyBuff[0]==0x6860 && m_pbyBuff[0x6]==0xB8 && *(WORD*)&m_pbyBuff[0xB]==0x10FF &&
			m_pbyBuff[0xD]==0x68 && *(WORD*)&m_pbyBuff[0x12]==0xB850 && *(WORD*)&m_pbyBuff[0x18]==0x10FF)
		{
			return true;
		}
	}
	return false;
}

bool CAHPackUnpacker::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}
	DWORD dwSrcRVA=*(DWORD*)&m_pbyBuff[0x2C]-m_dwImageBase;
	WORD wRVASection=m_objTempFile.Rva2FileOffset(dwSrcRVA,&dwSrcRVA);
	if(wRVASection==0xFF)
	{
		return false;
	}
	DWORD dwDestSize=0x00;
	CMaxPEFile *ctempFile=m_pMaxPEFile;
	m_pMaxPEFile=&m_objTempFile;
	if(!(~(dwDestSize=APLIBDecompress(m_pMaxPEFile->m_stSectionHeader[wRVASection].Misc.VirtualSize,m_pMaxPEFile->m_stSectionHeader[wRVASection].Misc.VirtualSize,dwSrcRVA,dwSrcRVA))))
	{
		m_pMaxPEFile=ctempFile;
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped+0xE0,0x04,0x04))
	{
		m_pMaxPEFile=ctempFile;
		return false;
	}

	if(m_objTempFile.WriteBuffer((DWORD*)&m_pbyBuff[0],m_objTempFile.m_stPEHeader.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+0x68,sizeof(DWORD),sizeof(DWORD)))
	{
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped+0x19C,0x04,0x04))
		{
			m_pMaxPEFile=ctempFile;
			return false;
		}
		if(m_objTempFile.WriteAEP(*(DWORD*)&m_pbyBuff[0] - m_dwImageBase))
		{
			m_pMaxPEFile=ctempFile;
			return true;
		}
	}
	m_pMaxPEFile=ctempFile;
	return false;
}