#include "SCPackUnpacker.h"
#include "Packers.h"

CSCPackUnpacker::CSCPackUnpacker(CMaxPEFile *pMaxPEFile):
CUnpackBase(pMaxPEFile)
{
	memset(&m_objStructLdrDcdrInfo, 0x00, sizeof(LOADER_DECODER_INFO_SCPACK));
	m_objStructCode_Info = NULL; 
}

CSCPackUnpacker::~CSCPackUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_objStructCode_Info)
	{
		delete[] m_objStructCode_Info;
		m_objStructCode_Info = NULL;
	}
}

bool CSCPackUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections >= 3 &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".scpac", 6) == 0) || (m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData == 0x00))
	{
		if(_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".scpac", 6) != 0)
		{
			DWORD dwScPackSectionOffset = m_pMaxPEFile->m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_OPTIONAL_HEADER) + sizeof(IMAGE_FILE_HEADER) + 0x01;
			BYTE  bySectionNamebuff[0x07] = {0};
			if(m_pMaxPEFile->ReadBuffer(bySectionNamebuff, dwScPackSectionOffset, 0x07, 0x07))
			{
				if(_memicmp(bySectionNamebuff, "scpac", 6) != 0)
				{
					return false;
				}
			}
		}

		BYTE byScUnpackSig[]={0x55,0x8B,0xEC,0x83,0xC4,0xD8,0x53,0x56,0x57,0x8D,0x7D,0x08,0x50,0xE8,0x00,0x00,0x00,
			0x00,0x58,0x25,0x00,0xF0,0xFF,0xFF,0x05,0x28,0x10,0x00,0x00,0x89,0x45,0x0C,0x83,0xC0,0x65};

		BYTE pbyBuff[sizeof(byScUnpackSig)]={0};
		if(m_pMaxPEFile->ReadBuffer(pbyBuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(byScUnpackSig), sizeof(byScUnpackSig)))
		{
			if(memcmp(pbyBuff,byScUnpackSig,sizeof(byScUnpackSig))==0)
			{
				return true;
			}
		}	
	}
	return false;
}

bool CSCPackUnpacker::Unpack(LPCTSTR szTempFileName)
{
	DWORD dwStartOffset = 0;
	if(m_pMaxPEFile->Rva2FileOffset(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + 0x1028 + 0x65, &dwStartOffset) == OUT_OF_FILE)
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(&m_objStructLdrDcdrInfo, dwStartOffset, sizeof(LOADER_DECODER_INFO_SCPACK), sizeof(LOADER_DECODER_INFO_SCPACK)))
	{
		return false;
	}
	
	if(m_objStructLdrDcdrInfo.dwNoOfCompressedSections > 0x10)
	{
		return false;
	}

	dwStartOffset += sizeof(LOADER_DECODER_INFO_SCPACK);
	
	m_objStructCode_Info = new COMPRESSED_CODE_INFO[m_objStructLdrDcdrInfo.dwNoOfCompressedSections]; // Deleting in destructor
	if(!m_objStructCode_Info)
	{
		return false;
	}
	memset(m_objStructCode_Info, 0, m_objStructLdrDcdrInfo.dwNoOfCompressedSections * sizeof(COMPRESSED_CODE_INFO));
	if(m_pMaxPEFile->ReadBuffer(m_objStructCode_Info, dwStartOffset, m_objStructLdrDcdrInfo.dwNoOfCompressedSections * 0x08, m_objStructLdrDcdrInfo.dwNoOfCompressedSections * 0x08))
	{
		if(!ReOrganizeFile(szTempFileName))
		{
			return false;
		}

		dwStartOffset += m_objStructLdrDcdrInfo.dwNoOfCompressedSections * 0x08;
		for(DWORD i = 0; i < m_objStructLdrDcdrInfo.dwNoOfCompressedSections; i++)
		{
			DWORD dwSrcSize = m_objStructCode_Info[i].dwSize, dwDestSize = 0;
			if(i == m_objStructLdrDcdrInfo.dwNoOfCompressedSections - 1)
			{
				dwDestSize = m_pMaxPEFile->m_stSectionHeader[0].Misc.VirtualSize - (m_objStructCode_Info[i].dwUncompressedRVA - m_dwImageBase);
			}
			else if(i < m_objStructLdrDcdrInfo.dwNoOfCompressedSections - 1)
			{
				dwDestSize = m_objStructCode_Info[i + 1].dwUncompressedRVA - m_objStructCode_Info[i].dwUncompressedRVA;
			}		
			if(dwDestSize < dwSrcSize)
			{
				dwDestSize = dwSrcSize;
			}
			
			if(!(~APLIBDecompress(dwSrcSize, dwDestSize, dwStartOffset, m_objStructCode_Info[i].dwUncompressedRVA - m_dwImageBase)))
			{
				return false;
			}
			
			dwStartOffset += m_objStructCode_Info[i].dwSize;
		}
		m_objStructLdrDcdrInfo.dwDLLApiImport-=m_dwImageBase;
		if(m_objTempFile.WriteBuffer(&m_objStructLdrDcdrInfo.dwDLLApiImport,m_objTempFile.m_stPEHeader.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+0x68,sizeof(DWORD),sizeof(DWORD)))
		{
			if(m_objTempFile.WriteAEP(m_objStructLdrDcdrInfo.dwOriginalAEP - m_dwImageBase))
			{
				if(m_objTempFile.WriteSectionCharacteristic(0x00, 0x00004341, 0x4))
				{
					if(m_objTempFile.CalculateImageSize())
					{
						return true;
					}
				}
			}
		}
	}
	return false;
}
