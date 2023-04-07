#include "EmbeddedFile.h"

CEmbeddedFile::CEmbeddedFile(CMaxPEFile *pMaxPEFile, int iCurrentLevel):
CUnpackBase(pMaxPEFile, iCurrentLevel),
m_dwStartOffset(0),
m_dwSize(0),
m_bXORCrypt(false),
m_byXORKey(0)
{
}

CEmbeddedFile::~CEmbeddedFile(void)
{
}


bool CEmbeddedFile::IsPacked()
{	
	bool bCheckFurther;
	if(!m_pMaxPEFile->m_bPEFile)
	{
		bCheckFurther = CheckPKHeader();
		if(bCheckFurther==false)
		{
			return CheckXORCrypt();
		}
		return true;
	}
	if(m_iCurrentLevel > 0 || m_pMaxPEFile->m_dwAEPMapped == 0x00) //Tushar ==> 12 Oct 2018 : To handle scanner stuck
	{
		return false;
	}

	bool bRet = CheckFileInRrsSection();
	if(bRet)
	{
		return true;
	}

	return CheckFileInOverlay();
}


bool CEmbeddedFile::CheckFileInRrsSection()
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfRvaAndSizes < 3)
	{
		return false;
	}
	DWORD dwBaseResAT = m_pMaxPEFile->m_stPEHeader.DataDirectory[2].VirtualAddress;
	DWORD dwSizeofdata = m_pMaxPEFile->m_stPEHeader.DataDirectory[2].Size;	
	if(dwSizeofdata == 0 && dwBaseResAT == 0)
	{
		return false;
	}
	if(dwSizeofdata == 0 || dwBaseResAT == 0)
	{
		return false;
	}

	DWORD dwBaseResATFileOffset =0;
	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(dwBaseResAT, &dwBaseResATFileOffset))
	{
		return false;
	}

	WORD wNoofNamed = 0x00;
	DWORD dwOffset = dwBaseResATFileOffset;
	if(!m_pMaxPEFile->ReadBuffer(&wNoofNamed, dwOffset+ 0x0C, sizeof(WORD), sizeof(WORD)))
	{
		return false;
	}
	WORD wNoofID = 0x00;
	if(!m_pMaxPEFile->ReadBuffer(&wNoofID, dwOffset+ 0x0E, sizeof(WORD), sizeof(WORD)))
	{
		return false;
	}
	if(wNoofNamed == 0 && wNoofID == 0)
		return false;

	if(wNoofNamed + wNoofID > 0x256)
	{
		return false;
	}

	DWORD dwOffSetOfDir = 0, dwOffSetOfDir1 = 0, dwOffSetOfDir2 = 0;	
	for(int i = 0; i < wNoofNamed + wNoofID; i++, dwOffset += 0x8)
	{
		if(!m_pMaxPEFile->ReadBuffer(&dwOffSetOfDir, (dwOffset + 0x14), sizeof(DWORD), sizeof(DWORD)))
		{
			continue;
		}

		WORD wNoofNameEntry = 0, wNoofIDEntry = 0;
		m_pMaxPEFile->ReadBuffer(&wNoofNameEntry, (dwBaseResATFileOffset +(dwOffSetOfDir^0x80000000)+0xC), sizeof(WORD), sizeof(WORD));
		m_pMaxPEFile->ReadBuffer(&wNoofIDEntry, (dwBaseResATFileOffset +(dwOffSetOfDir^0x80000000)+0xE), sizeof(WORD), sizeof(WORD));		
		if(wNoofIDEntry == 0 && wNoofNameEntry == 0)
		{
			continue;
		}

		for(int j = 0; j < wNoofIDEntry + wNoofNameEntry && j < 0x256; j++, dwOffSetOfDir += 0x8)
		{
			if(!m_pMaxPEFile->ReadBuffer(&dwOffSetOfDir1, (dwBaseResATFileOffset +(dwOffSetOfDir^0x80000000)+0x14), sizeof(DWORD), sizeof(DWORD)))
			{
				continue;
			}
			WORD wNoofIDEntries = 0;
			if(!m_pMaxPEFile->ReadBuffer(&wNoofIDEntries, (dwBaseResATFileOffset +(dwOffSetOfDir1^0x80000000)+0xE), sizeof(WORD), sizeof(WORD)))
			{
				continue;
			}

			for(int k = 0; k < wNoofIDEntries && k < 0x256; k++, dwOffSetOfDir1 += 0x8)
			{  
				WORD wNoofIDEntrie=0;
				if(!m_pMaxPEFile->ReadBuffer(&dwOffSetOfDir2, (dwBaseResATFileOffset +(dwOffSetOfDir1^0x80000000)+0x14), sizeof(DWORD), sizeof(DWORD)))
				{
					continue;
				}
				if(dwBaseResATFileOffset + dwOffSetOfDir2 > m_pMaxPEFile->m_dwFileSize)
				{
					continue;
				}
				m_dwStartOffset = 0;	
				if(!m_pMaxPEFile->ReadBuffer(&m_dwStartOffset, dwBaseResATFileOffset + dwOffSetOfDir2, sizeof(DWORD), sizeof(DWORD)))
				{
					continue;
				}
				if(OUT_OF_FILE ==  m_pMaxPEFile->Rva2FileOffset(m_dwStartOffset, &m_dwStartOffset))
				{
					continue;
				}
				m_dwSize = 0;	
				if(!m_pMaxPEFile->ReadBuffer(&m_dwSize, dwBaseResATFileOffset + dwOffSetOfDir2 + 4, sizeof(DWORD), sizeof(DWORD)))
				{
					continue;
				}
				if(m_dwSize == 0 || m_dwSize > m_pMaxPEFile->m_dwFileSize)
				{
					continue;
				}

				IMAGE_DOS_HEADER stImageDosHeader = {0};		
				if(!m_pMaxPEFile->ReadBuffer(&stImageDosHeader, m_dwStartOffset, sizeof(IMAGE_DOS_HEADER), sizeof(IMAGE_DOS_HEADER)))
				{
					continue;
				}
				if(m_dwStartOffset == 0)
				{
					continue;
				}
				
				if (*(DWORD *)&stImageDosHeader == 0x4643534D) // Check for Cab file "MSCF" signature
				{
					return true;					
				} 
				else if(stImageDosHeader.e_magic == IMAGE_DOS_SIGNATURE)// Check for PE file
				{
					DWORD dwSignature = 0;
					m_pMaxPEFile->ReadBuffer(&dwSignature, m_dwStartOffset + stImageDosHeader.e_lfanew, sizeof(DWORD), sizeof(DWORD));
					
					if(dwSignature == IMAGE_NT_SIGNATURE)
					{
						return true;						
					}
				}					
			} 
		}		
	}
	return false;
}

bool CEmbeddedFile::CheckFileInOverlay()
{
	WORD wNoOfSections = m_pMaxPEFile->m_stPEHeader.NumberOfSections;
	DWORD dwStartOfOverlay = m_pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].PointerToRawData + m_pMaxPEFile->m_stSectionHeader[wNoOfSections - 1].SizeOfRawData;

	const int HDR_BUFF_SIZE = 0x1000;
	if(dwStartOfOverlay < HDR_BUFF_SIZE)
	{
		return false;
	}

	BYTE *byBuff = new BYTE[HDR_BUFF_SIZE];
	if(!byBuff)
	{
		return false;
	}
	
	if(m_pMaxPEFile->ReadBuffer(byBuff, dwStartOfOverlay, HDR_BUFF_SIZE, HDR_BUFF_SIZE))
	{
		for(DWORD dwOffset = 0; dwOffset < (HDR_BUFF_SIZE - sizeof(IMAGE_DOS_HEADER)); dwOffset++)
		{
			//////----------------------Smart Install Maker V 5.0 extracting CAB file------------------------///////
			bSmartInstaller = false;
			if(dwOffset == 0)//&& m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint==0x17D64)
			{
				const BYTE bySmartMakerSig[]={0x53,0x6D,0x61,0x72,0x74,0x20,0x49,0x6E,0x73,0x74,0x61,0x6C,0x6C,0x20,0x4D,0x61,0x6B,0x65,0x72,0x20,0x76,0x2E,0x20,0x35,0x2E,0x30};
				if(dwOffset+sizeof(bySmartMakerSig)<=HDR_BUFF_SIZE)
				{
					if(memcmp(&byBuff[dwOffset],bySmartMakerSig,sizeof(bySmartMakerSig))==0x00)		// Smart Installer Chk
					{

						if(m_pMaxPEFile->ReadBuffer(byBuff, m_pMaxPEFile->m_dwFileSize - 0x24, 0x24, 0x24))
						{
							DWORD dwOverlayStart = *(DWORD *)&byBuff[0];	// All this values are at the end of file
							DWORD dwCompStrSize  = *(DWORD *)&byBuff[0x8];
							DWORD dwStringOff	 = *(DWORD *)&byBuff[0x10];
							DWORD dwCABStartOff	 = *(DWORD *)&byBuff[0x18];
							if(dwOverlayStart == dwStartOfOverlay)
							{
								const BYTE byMSCABStartSig[]={0x00,0x00,0x00,0x00,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x24};	
								if(m_pMaxPEFile->ReadBuffer(byBuff, dwStringOff, 0x20, 0x20))
								{
									if(memcmp(&byBuff[0],byMSCABStartSig,sizeof(byMSCABStartSig))==0x00)	// Doller Sign Chk
									{	
										if(byBuff)
										{
											delete []byBuff;
											byBuff = NULL;
										}
										m_dwStartOffset = dwCABStartOff - 0x4;
										m_dwSize = m_pMaxPEFile->m_dwFileSize - dwCABStartOff + 0x4;
										bSmartInstaller = true;
										return true;
									}
								}
							}
						}
					}
				}
			}
			if(byBuff[dwOffset] != 0x4D)
			{
				continue;
			}
			if((*(WORD *)&byBuff[dwOffset]) == IMAGE_DOS_SIGNATURE)
			{				
				IMAGE_DOS_HEADER stImageDosHeader = *(IMAGE_DOS_HEADER *)&byBuff[dwOffset];		

				DWORD dwSignature = 0;
				if(m_pMaxPEFile->ReadBuffer(&dwSignature, dwStartOfOverlay + dwOffset + stImageDosHeader.e_lfanew, sizeof(DWORD), sizeof(DWORD)))
				{
					if(dwSignature == IMAGE_NT_SIGNATURE)
					{
						if(byBuff)
						{
							delete []byBuff;
							byBuff = NULL;
						}
						m_dwStartOffset = dwStartOfOverlay + dwOffset;
						m_dwSize = m_pMaxPEFile->m_dwFileSize - dwOffset;
						
						return true;
					}
				}					
			}
		}
	}
	if(byBuff)
	{
		delete []byBuff;
		byBuff = NULL;
	}
	return false;
}


bool CEmbeddedFile::Unpack(LPCTSTR szTempFilePath)
{	
	HANDLE hTempFile = CreateFile(szTempFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ|FILE_SHARE_DELETE, 0, CREATE_ALWAYS, 0, 0);
	if(hTempFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	
	m_pMaxPEFile->SetFilePointer(m_dwStartOffset);

	const int BUFF_SIZE	= 0x10000;
	BYTE *pReadBuffer = new BYTE[BUFF_SIZE];
	if(pReadBuffer)
	{		
		if(m_dwStartOffset == 0)
		{
			m_dwSize = m_pMaxPEFile->m_dwFileSize;
		}
		
		DWORD dwBytes2Read = 0, dwBytesWritten = 0, dwBytesRead = 0;
		for(DWORD dwTotalBytesRead = 0; dwTotalBytesRead < m_dwSize; dwTotalBytesRead += dwBytesRead)
		{
			dwBytes2Read = BUFF_SIZE;
			if ((m_dwSize - dwTotalBytesRead) < BUFF_SIZE)
			{
				dwBytes2Read = m_dwSize - dwTotalBytesRead;
			}
			m_pMaxPEFile->ReadBuffer(pReadBuffer, dwBytes2Read, &dwBytesRead);
			if(dwBytesRead == 0)
			{
				break;
			}
			if(m_bXORCrypt)
			{
				for(DWORD i=0;i<dwBytesRead;i++)
				{
					pReadBuffer[i]^=m_byXORKey;
				}
			}

			if(bSmartInstaller == true && dwTotalBytesRead == 0)	// ADD MSCF to the File Start for Qhost Family
			{
				*(DWORD*)&pReadBuffer[0]=0x4643534D;
				bSmartInstaller=false;
			}

			WriteFile(hTempFile, pReadBuffer, dwBytesRead, &dwBytesWritten, NULL);
			if(dwBytes2Read < BUFF_SIZE)
			{
				break;
			}
		}		
		delete []pReadBuffer;
		pReadBuffer = NULL;
	}

	::CloseHandle(hTempFile);
	hTempFile = INVALID_HANDLE_VALUE;
	
	return true;
}

bool CEmbeddedFile::CheckPKHeader()
{
	const int HDR_BUFF_SIZE = 0x10;
	BYTE byBuff[HDR_BUFF_SIZE] = {0};
	
	if(m_pMaxPEFile->ReadBuffer(byBuff, 0, HDR_BUFF_SIZE, HDR_BUFF_SIZE))
	{
		for(DWORD dwOffset = 1; dwOffset < HDR_BUFF_SIZE - 2; dwOffset++)
		{
			if(byBuff[dwOffset] != 0x50)
			{
				continue;
			}
			if((*(WORD *)&byBuff[dwOffset]) == 0x4B50)
			{	
				m_dwStartOffset = dwOffset;
				m_dwSize = m_pMaxPEFile->m_dwFileSize - dwOffset;
				return true;
			}
		}
	}
	return false;
}


bool CEmbeddedFile::CheckXORCrypt()
{
	const int HDR_BUFF_SIZE = 0x40;
	BYTE byBuff[HDR_BUFF_SIZE] = {0};
	
	if(m_pMaxPEFile->ReadBuffer(byBuff, 0, HDR_BUFF_SIZE, HDR_BUFF_SIZE))
	{
		m_byXORKey=byBuff[0]^0x4D;
		if(m_byXORKey == 0)
		{
			return false;
		}
		if((byBuff[1]^m_byXORKey)==0x5A)
		{
			byBuff[0x40-0x04]^=m_byXORKey;
			byBuff[0x40-0x03]^=m_byXORKey;
			byBuff[0x40-0x02]^=m_byXORKey;
			byBuff[0x40-0x01]^=m_byXORKey;

			if(m_pMaxPEFile->ReadBuffer(byBuff, *(DWORD*)&byBuff[0x40-0x04], 0x02, 0x02))
			{
				if((byBuff[0]^m_byXORKey)==0x50 && (byBuff[1]^m_byXORKey)==0x45)
				{
					m_bXORCrypt=true;
					return true;
				}
			}
		}
	}
	return false;
}

