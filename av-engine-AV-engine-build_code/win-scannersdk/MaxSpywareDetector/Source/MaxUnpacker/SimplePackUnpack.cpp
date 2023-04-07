#include "SimplePackUnpack.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CSimplePackUnpack::CSimplePackUnpack(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
}

CSimplePackUnpack::~CSimplePackUnpack(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
}

bool CSimplePackUnpack::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 2 &&
		m_pMaxPEFile->m_stSectionHeader[0].Name[0]==0x00 && m_pMaxPEFile->m_stSectionHeader[1].Name[0]==0x00)
	{
		m_pbyBuff = new BYTE[255];

		BYTE bySimplePackUnpackbuff[]={0x60,0xE8,0x00,0x00,0x00,0x00,0x5B,0x8D,0x5B,0xFA,0xBD,0x8B,0x7D,0x3C};
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,sizeof(bySimplePackUnpackbuff)+0x04,sizeof(bySimplePackUnpackbuff)+0x04))
		{
			return false;
		}
		if(memcmp(m_pbyBuff,bySimplePackUnpackbuff,sizeof(bySimplePackUnpackbuff)-0x03)==0x00 &&
		   memcmp(&m_pbyBuff[sizeof(bySimplePackUnpackbuff)-0x03+0x04],&bySimplePackUnpackbuff[sizeof(bySimplePackUnpackbuff)-0x03],0x03)==0x00)
		{
			return true;
		}
	}
	return false;
}

bool CSimplePackUnpack::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	for(WORD i = 0; i < m_objTempFile.m_stPEHeader.NumberOfSections - 0x01; i++)
	{
		if(m_pMaxPEFile->m_stSectionHeader[i].NumberOfLinenumbers!=0x00 &&m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData!=0x00 && (!(~APLIBDecompress(m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData,m_pMaxPEFile->m_stSectionHeader[i].Misc.VirtualSize,
			m_pMaxPEFile->m_stSectionHeader[i].PointerToRawData,m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress))))
		{
			return false;
		}
	}
	memset(m_pbyBuff,0,0xC);
	*(DWORD*)&m_pbyBuff[0]=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x84;
	if(!m_objTempFile.ReadBuffer((DWORD*)&m_pbyBuff[0],*(DWORD*)&m_pbyBuff[0],0xC,0xC))
	{
		return false;
	}

	if(!m_objTempFile.WriteBuffer((DWORD*)&m_pbyBuff[0],m_objTempFile.m_stPEOffsets.NoOfDataDirs+(sizeof(DWORD)*0x03),sizeof(DWORD),sizeof(DWORD)))
	{
		return false;
	}

	*(DWORD*)&m_pbyBuff[0]=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x90+*(DWORD*)&m_pbyBuff[8];
	if(!m_objTempFile.ReadBuffer((DWORD*)&m_pbyBuff[0],*(DWORD*)&m_pbyBuff[0],0x2D,0x2D))
	{
		return false;
	}

	DWORD dwOffset=0x00;
	if(*(WORD*)&m_pbyBuff[0]!=0x6861)
	{
		dwOffset+=0x27;
	}
	if(!m_objTempFile.WriteAEP(*(DWORD*)&m_pbyBuff[dwOffset+0x02]-m_dwImageBase))
	{
		return false;
	}
	return true;
}

