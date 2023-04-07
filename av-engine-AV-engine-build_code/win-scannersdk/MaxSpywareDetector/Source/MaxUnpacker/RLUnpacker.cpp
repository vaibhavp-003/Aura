#include "RLUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CRLUnpacker::CRLUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{	
}

CRLUnpacker::~CRLUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CRLUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".packed", 7) == 0) && 
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[1].Name, ".RLPack", 7) == 0))
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}

		BYTE byRLbuff[0x13]={0x60,0xE8,0x00,0x00,0x00,0x00,0x8B,0x2C,0x24,0x83,0xC4,0x04,0x83,0x7C,0x24,0x28,0x01,0x75,0x0C};
		if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(byRLbuff), sizeof(byRLbuff)))
		{
			if(*(WORD*)&m_pbyBuff[0] == 0xE860)
			{
				if(memcmp(m_pbyBuff, byRLbuff, sizeof(byRLbuff)) == 0x00)
				{
					return true;
				}
			}
		}
	}
	return false;
}

bool CRLUnpacker::Unpack(LPCTSTR szTempFileName)
{
	BYTE byFindLZMAorAPLIB[0x20]={0};
	if(!m_pMaxPEFile->ReadBuffer(byFindLZMAorAPLIB, m_pMaxPEFile->m_dwAEPMapped + 0x32, 0xA, 0xA))
	{
		return false;
	}

	RLPack_Type eCompressionType;
	if(*(DWORD*)&byFindLZMAorAPLIB[0] == 0xD08)
	{
		eCompressionType = LZMA_RL;
	}
	else if(*(DWORD*)&byFindLZMAorAPLIB[0] == 0x5FE)
	{
		eCompressionType = APLIB_RL;
	}
	else
	{
		return false;
	}

	LOADER_DECODER_INFO_RLPACK *UnpackInfo = (LOADER_DECODER_INFO_RLPACK *)malloc(sizeof(LOADER_DECODER_INFO_RLPACK));
	memset(UnpackInfo, 0, sizeof(LOADER_DECODER_INFO_RLPACK));

	DWORD dwNoOfSections = 0, dwUnpackStart = m_pMaxPEFile->m_dwAEPMapped + 0x06 + *(DWORD *)&byFindLZMAorAPLIB[0];
	for(;dwNoOfSections < 0x0A; dwNoOfSections++)
	{
		if(dwNoOfSections > 0)
		{
			UnpackInfo = (LOADER_DECODER_INFO_RLPACK *)realloc(UnpackInfo,(dwNoOfSections + 1) * sizeof(LOADER_DECODER_INFO_RLPACK));
			memset(UnpackInfo + dwNoOfSections, 0, sizeof(LOADER_DECODER_INFO_RLPACK));
		}
		if(m_pMaxPEFile->ReadBuffer(UnpackInfo + dwNoOfSections, dwUnpackStart + (dwNoOfSections * 0x08), 0x08, 0x08))
		{
			if((UnpackInfo + dwNoOfSections)->CompressedRVA == 0x00)
			{
				break;
			}
		}
	}

	if(!ReOrganizeFile(szTempFileName, true, false))
	{
		free(UnpackInfo);
		UnpackInfo = NULL;
		return false;
	}

	BYTE byLZMAProp[4]={0};
	DWORD dwSrcSize, dwDesSize;
	for(DWORD dwCounter = 0; dwCounter < dwNoOfSections; dwCounter++)
	{
		if(dwCounter == dwNoOfSections - 1)
		{
			dwSrcSize = m_objTempFile.m_stPEHeader.AddressOfEntryPoint - (&UnpackInfo[dwCounter])->CompressedRVA;
			dwDesSize = m_objTempFile.m_stSectionHeader[0].Misc.VirtualSize - (&UnpackInfo[dwCounter])->UncompressedRVA;
		}
		else
		{
			dwSrcSize = (&UnpackInfo[dwCounter + 1])->CompressedRVA - (&UnpackInfo[dwCounter])->CompressedRVA;
			dwDesSize = (&UnpackInfo[dwCounter + 1])->UncompressedRVA - (&UnpackInfo[dwCounter])->UncompressedRVA;
		}
		if(m_pMaxPEFile->Rva2FileOffset((&UnpackInfo[dwCounter])->CompressedRVA, &((&UnpackInfo[dwCounter])->CompressedRVA)) > 0)
		{
			if(eCompressionType == LZMA_RL)
			{
				byLZMAProp[0] = 8;
				byLZMAProp[1] = 0;
				byLZMAProp[2] = 2;
				if(!LZMADecompress(byLZMAProp, dwSrcSize, dwDesSize, (&UnpackInfo[dwCounter])->CompressedRVA,(&UnpackInfo[dwCounter])->UncompressedRVA))
				{
					free(UnpackInfo);
					UnpackInfo = NULL;
					return false;
				}
			}
			else if(eCompressionType == APLIB_RL)
			{
				if(!(~APLIBDecompress(dwSrcSize, dwDesSize, (&UnpackInfo[dwCounter])->CompressedRVA, (&UnpackInfo[dwCounter])->UncompressedRVA)))
				{
					free(UnpackInfo);
					UnpackInfo = NULL;
					return false;
				}
			}
		}
	}
	free(UnpackInfo);
	UnpackInfo = NULL;

	//Resolve the E8/E9 calls
	dwUnpackStart = m_pMaxPEFile->m_dwAEPMapped + 0x06;
	if(eCompressionType == APLIB_RL)
	{
		dwUnpackStart += 0x5E2;
	}
	else if(eCompressionType == LZMA_RL)
	{
		dwUnpackStart += 0xCEC;
	}

	if(!m_pMaxPEFile->ReadBuffer(byFindLZMAorAPLIB, dwUnpackStart, 0x0C, 0x0C))
	{
		return false;
	}

	//Closing and opening the file again so that it reflects unpacked size
	m_objTempFile.CloseFile();

	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	//Resolving the E8/E9 calls
	if(*(DWORD *)&byFindLZMAorAPLIB[0] != 0x00 && *(DWORD *)&byFindLZMAorAPLIB[4] != 0x00)
	{
		if(!ResolveCalls(*(DWORD *)&byFindLZMAorAPLIB[0], *(DWORD *)&byFindLZMAorAPLIB[0x04], *(DWORD *)&byFindLZMAorAPLIB[0x08]))
		{
			return false;
		}
	}

	//ResolvingImportAddresses..First Another Decompression needs to run
	DWORD dwImportBufferAlloc = m_pMaxPEFile->m_dwAEPMapped;
	dwUnpackStart = m_pMaxPEFile->m_dwAEPMapped + 0x06;
	if(eCompressionType == APLIB_RL)
	{
		dwImportBufferAlloc += 0x8A;
		dwUnpackStart += 0x5FE;
	}
	else if(eCompressionType == LZMA_RL)
	{
		dwImportBufferAlloc += 0xA9;
		dwUnpackStart += 0xD08;
	}

	dwUnpackStart += (dwNoOfSections * 0x08) + 0x04;
	if(!m_pMaxPEFile->ReadBuffer(&dwImportBufferAlloc, dwImportBufferAlloc, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}

	BYTE *byImportBuff = NULL;
	if(!(byImportBuff = (BYTE *)MaxMalloc(dwImportBufferAlloc)))
	{
		return false;
	}
	memset(byImportBuff, 0x00, dwImportBufferAlloc);

	dwSrcSize = m_pMaxPEFile->m_dwFileSize - dwUnpackStart;
	dwDesSize = dwImportBufferAlloc;
	if(eCompressionType == APLIB_RL)
	{
		if(!(~APLIBDecompress(dwSrcSize, dwDesSize, dwUnpackStart, 0x00, byImportBuff)))
		{
			free(byImportBuff);
			byImportBuff = NULL;
			return false;
		}
	}
	else if(eCompressionType == LZMA_RL)
	{
		byLZMAProp[0] = 8;
		byLZMAProp[1] = 0;
		byLZMAProp[2] = 2;
		if(!LZMADecompress(byLZMAProp, dwSrcSize, dwDesSize, dwUnpackStart, 0x00, byImportBuff))
		{
			free(byImportBuff);
			byImportBuff = NULL;
			return false;
		}
	}

	if(!ResolveImportAddresses(byImportBuff, dwDesSize))
	{
		free(byImportBuff);
		byImportBuff = NULL;
		return false;
	}

	free(byImportBuff);
	byImportBuff = NULL;
	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	if(!m_objTempFile.CalculateLastSectionProperties())
	{
		return false;
	}

	DWORD dwOrigAEP = 0;
	DWORD dwAEPOffset = 0;
	if(eCompressionType == LZMA_RL)
	{
		dwOrigAEP = 0x1B0;
	}
	else if(eCompressionType == APLIB_RL)
	{
		dwOrigAEP = 0x175;
	}
	if(!m_objTempFile.ReadBuffer(&dwAEPOffset, m_objTempFile.m_dwAEPMapped + dwOrigAEP, sizeof(DWORD), sizeof(DWORD)))
	{
		return false;
	}
	dwOrigAEP += m_objTempFile.m_stPEHeader.AddressOfEntryPoint + dwAEPOffset + 0x04;

	if(!m_objTempFile.WriteAEP(dwOrigAEP))
	{
		return false;
	}
	if(!ReOrganizeFile(szTempFileName, false))
	{
		return false;
	}
	return true;
}

DWORD CRLUnpacker::CheckForAPI(BYTE *ReadAPIEncrypt, BYTE **byImportTablebuffOrig, BYTE *byImportTablebuff, DWORD *dwAPICounter, DWORD dwDLLNo, DWORD dwStartWriteDLLName, DWORD *dwImportSize, DWORD dwBuildImportSize)
{
	//Moving to the correct DLL as all the DLL's are listed together
	DWORD dwCounter = 0, dwDLLCount = dwDLLNo;
	while(dwDLLCount != 0)
	{
		dwCounter += strlen((const char*)(&ReadAPIEncrypt[dwCounter])) + 0x01;
		dwDLLCount--;
	}

	//Doing a GetModuleHandleA/LoadLibrary
	HMODULE	hDLLName = GetModuleHandleA(((char*)(&ReadAPIEncrypt[dwCounter])));
	if(GetLastError() == 0x7E)
	{
		hDLLName = LoadLibraryA(((char*)(&ReadAPIEncrypt[dwCounter])));
		//If load library also fails then terminating
		if(GetLastError() == 0x7E)
		{
			return 0;
		}
	}

	//Checking to see if the Import Table has adequate Size
	while(dwBuildImportSize + strlen((const char*)(&ReadAPIEncrypt[dwCounter])) + 0x03 > *dwImportSize)
	{
		*byImportTablebuffOrig = (BYTE*)realloc(*byImportTablebuffOrig, *dwImportSize + m_objTempFile.m_stPEHeader.SectionAlignment);
		memset(*byImportTablebuffOrig + *dwImportSize, 0, m_objTempFile.m_stPEHeader.SectionAlignment);
		*dwImportSize += m_objTempFile.m_stPEHeader.SectionAlignment;
		byImportTablebuff = &(*byImportTablebuffOrig)[dwBuildImportSize]; 
	}

	memcpy(byImportTablebuff, &ReadAPIEncrypt[dwCounter], strlen((const char *)(&ReadAPIEncrypt[dwCounter])));
	dwCounter = strlen((const char *)(&ReadAPIEncrypt[dwCounter]));
	memset(&byImportTablebuff[dwCounter], 0, 3);
	dwCounter += 3;

	bool bOrdinal = false;
	DWORD dwWriteIncrements = 0x00, dwCounterCheck = dwCounter;

	while(*(DWORD *)(&ReadAPIEncrypt[*dwAPICounter]) != 0x00)
	{
		if(ReadAPI(hDLLName, *(DWORD *)(&ReadAPIEncrypt[*dwAPICounter]), &bOrdinal) != NULL)
		{
			dwCounterCheck+=strlen((const char *)m_pbyBuff) + 0x03;
			//Checking to see if the Import Table has adequate Size to input the API Name
			while((dwBuildImportSize + dwCounterCheck) > *dwImportSize)
			{
				*byImportTablebuffOrig = (BYTE *)realloc(*byImportTablebuffOrig, *dwImportSize + m_objTempFile.m_stPEHeader.SectionAlignment);
				memset(&(*byImportTablebuffOrig)[*dwImportSize], 0, m_objTempFile.m_stPEHeader.SectionAlignment);
				*dwImportSize += m_objTempFile.m_stPEHeader.SectionAlignment;
				byImportTablebuff = &(*byImportTablebuffOrig)[dwBuildImportSize]; 
			}
			if(bOrdinal)
			{
				//Writing the Ordinal DWORD so that it resolves to the Corresponding API
				if(!m_objTempFile.WriteBuffer(m_pbyBuff, dwStartWriteDLLName + dwWriteIncrements, sizeof(DWORD), sizeof(DWORD)))
				{
					return 0;
				}
			}
			else
			{
				//Taking a Function pointer to point to the API Name
				DWORD dwFunctionPointer=*(DWORD *)(&(*byImportTablebuffOrig)[(dwDLLNo * 0x14) + 0xC]) + dwCounter - 0x02;
				//Adding the API Name to the Import Table
				memcpy(&byImportTablebuff[dwCounter], m_pbyBuff, strlen((const char *)m_pbyBuff));
				dwCounter += strlen((const char *)m_pbyBuff);
				//Leaving a gap of three after each API
				memset(&byImportTablebuff[dwCounter], 0, 3);
				dwCounter += 0x03;
				//Writing the Function pointer to memory
				if(!m_objTempFile.WriteBuffer(&dwFunctionPointer, dwStartWriteDLLName + dwWriteIncrements, sizeof(DWORD), sizeof(DWORD)))
				{
					return 0;
				}
			}
		}
		else 
		{
			return 0;
		}
		*dwAPICounter += 0x04;
		dwWriteIncrements += 0x04;
	}   
	return dwCounter;
}


BYTE *CRLUnpacker::ReadAPI(HMODULE hDLLName, DWORD dwAPIEncrypted, bool *bOrdinal)
{
	*bOrdinal = false;

	//For Ordinal handling
	if(BYTE((dwAPIEncrypted << 8) | (dwAPIEncrypted >> 24)) == 0x80)
	{
		if((dwAPIEncrypted ^ 0x80000000) <= 0x10000)
		{
			memset(m_pbyBuff, 0, 255);
			memcpy(m_pbyBuff, &dwAPIEncrypted, sizeof(DWORD));
			*bOrdinal = true;
			return m_pbyBuff;
		}
	}
	//For proper APINames Handling
	/*DWORD dwReadOffset = *(DWORD *)((DWORD)hDLLName + (*(DWORD *)((DWORD)hDLLName + 0x3C)) + 0x78);
	DWORD dwStartSearchDLL = *(DWORD *)((DWORD)hDLLName + dwReadOffset + 0x20);
	DWORD dwTotalCount = *(DWORD *)((DWORD)hDLLName + dwReadOffset + 0x18);*/

	BYTE *pBuff = (BYTE *)&hDLLName[0];

	IMAGE_FILE_HEADER *pImageFileHeader = (IMAGE_FILE_HEADER *)(&pBuff[*(DWORD *)(&pBuff[0x3C]) + 4]);
	DWORD dwReadOffset = 0;
	if(IMAGE_FILE_MACHINE_IA64 == pImageFileHeader->Machine || IMAGE_FILE_MACHINE_AMD64 == pImageFileHeader->Machine)
	{
		IMAGE_OPTIONAL_HEADER64 *pImageOptionalHeader = (IMAGE_OPTIONAL_HEADER64 *)&pBuff[*(DWORD *)(&pBuff[0x3C]) + 4 + sizeof(IMAGE_FILE_HEADER)];
		dwReadOffset = pImageOptionalHeader->DataDirectory[0].VirtualAddress;

	}
	else
	{
		IMAGE_OPTIONAL_HEADER32 *pImageOptionalHeader = (IMAGE_OPTIONAL_HEADER32 *)&pBuff[*(DWORD *)(&pBuff[0x3C]) + 4 + sizeof(IMAGE_FILE_HEADER)];	
		dwReadOffset = pImageOptionalHeader->DataDirectory[0].VirtualAddress;
	}

	//DWORD dwReadOffset = *(DWORD *)(&pBuff[*(DWORD *)(&pBuff[0x3C]) + 0x78]);
	DWORD dwStartSearchDLL = *(DWORD *)(&pBuff[dwReadOffset + 0x20]);
	DWORD dwTotalCount = *(DWORD *)(&pBuff[dwReadOffset + 0x18]);

	DWORD dwAPIValue = 0;
	for(DWORD i = 0; i < dwTotalCount; i++)
	{ 
		//dwAPIValue = (DWORD)hDLLName + (*(DWORD *)((DWORD)hDLLName + dwStartSearchDLL));
		memset(m_pbyBuff, 0, 255);
		memcpy(m_pbyBuff, (void *)&pBuff[*(DWORD *)&pBuff[dwStartSearchDLL]], strlen((const char*)&pBuff[*(DWORD *)&pBuff[dwStartSearchDLL]]));
		DWORD dwBuildEncryptedValue = 0x00;

		//Encrypting the API Name to find the match
		for(BYTE j = 0; j < strlen((const char*)&pBuff[*(DWORD *)&pBuff[dwStartSearchDLL]]); j++)
		{ 
			dwBuildEncryptedValue = (dwBuildEncryptedValue<<7)|(dwBuildEncryptedValue>>25);
			dwBuildEncryptedValue ^= m_pbyBuff[j];
		}
		//If match found then return the API as this will be used to build the Import Table
		if(dwBuildEncryptedValue == dwAPIEncrypted)
		{
			return m_pbyBuff;
		}
		dwStartSearchDLL += 0x04;
	}
	return NULL;
}

bool CRLUnpacker::ResolveImportAddresses(BYTE *bySrcbuff, DWORD dwSize)
{ 
	bool bRet = false;

	//To increment the number of sections by 1
	DWORD dwNoofSections = m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + 0x02;
	if(!m_objTempFile.ReadBuffer(&dwNoofSections, dwNoofSections, 0x02, 0x02))
	{
		return bRet;
	}
	dwNoofSections++;
	if(!m_objTempFile.WriteBuffer(&dwNoofSections, m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + 0x02, 0x02, 0x02))
	{
		return bRet;
	}	

	DWORD dwNoOfDLLs = 0, dwCounter = 0;
	while(dwCounter < dwSize)
	{
		if(bySrcbuff[dwCounter] == 0x01)
		{
			break;
		}
		dwCounter += strlen((const char*)(&bySrcbuff[dwCounter])) + 0x01;
		dwNoOfDLLs++;
	}

	dwCounter += 0x01; //To reach the place where the API Names are stored in Encrypted Form
	dwNoOfDLLs += 1; //To also include the last Import Directory Entry

	DWORD dwImportSize = 0x1000;
	BYTE *byImportTablebuff = (BYTE*)malloc(dwImportSize);	
	while(dwImportSize < (dwNoOfDLLs * 0x14))
	{
		dwImportSize += m_objTempFile.m_stPEHeader.SectionAlignment;
		byImportTablebuff = (BYTE *)realloc(byImportTablebuff, dwImportSize);
	}
	memset(byImportTablebuff, 0, dwImportSize);

	//To write the value of the Import Table RVA present in the Data Directory
	if(m_objTempFile.WriteBuffer(&m_objTempFile.m_dwFileSize, m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0x68, 0x04, 0x04))
	{
		//For the last Import Directory Entry
		memset(&byImportTablebuff[(dwNoOfDLLs - 1) * 0x14], 0x00, 0x14); 

		DWORD dwWriteIncrements = 0, dwWriteAPICount = 0, dwStartWriteDLLname = 0;
		bRet = true;

		for(DWORD dwAPICounter = dwCounter, dwDLLCount = 0; dwAPICounter < dwSize; dwDLLCount++)
		{
			dwStartWriteDLLname = *(DWORD *)(&bySrcbuff[dwAPICounter]);
			memset(&byImportTablebuff[dwDLLCount * 0x14], 0x00, 0xC); //First 12 all 0's in the Import Directory Table
			if(dwDLLCount == 0)
			{
				*(DWORD *)(&byImportTablebuff[(dwDLLCount*0x14)+0xC]) = m_objTempFile.m_dwFileSize + dwWriteAPICount + (dwNoOfDLLs * 0x14);
			}
			else
			{
				//Once a new DLL is encountered it keeps only a single space between the new DLL name and the end of the api name of the previous DLL
				dwWriteAPICount -= 2;
				*(DWORD *)(&byImportTablebuff[(dwDLLCount * 0x14) + 0xC]) = m_objTempFile.m_dwFileSize + dwWriteAPICount + (dwNoOfDLLs * 0x14);
			}
			dwAPICounter += 0x04;
			*(DWORD*)(&byImportTablebuff[(dwDLLCount * 0x14) + 0x10]) = dwStartWriteDLLname;

			dwWriteIncrements = 0x00;
			DWORD dwIncCounter = CheckForAPI(bySrcbuff, &byImportTablebuff, &byImportTablebuff[(dwNoOfDLLs * 0x14) + dwWriteAPICount], &dwAPICounter, dwDLLCount, dwStartWriteDLLname, &dwImportSize, (dwNoOfDLLs * 0x14) + dwWriteAPICount);
			if(dwIncCounter == 0)
			{
				bRet = false;
				break;
			}
			dwWriteAPICount += dwIncCounter;
			dwAPICounter += 0x04;
		}
	}

	//Writing the Import Directory Table buffer to memory		
	if(bRet)
	{
		if(!AddNewSection(dwImportSize))
		{
			return bRet;
		}
		bRet = m_objTempFile.WriteBuffer(byImportTablebuff, m_objTempFile.m_dwFileSize, dwImportSize, dwImportSize);
		
	}

	if(dwImportSize>0x14)
	{
		if(!m_objTempFile.WriteBuffer((DWORD*)&byImportTablebuff[0x10], m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0xC0, 0x04, 0x04))
		{
			return false;
		}
		if(!m_objTempFile.WriteBuffer(&dwImportSize, m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 0xC4, 0x04, 0x04))
		{
			return false;
		}
	}
	if(byImportTablebuff)
	{
		free(byImportTablebuff);
		byImportTablebuff = NULL;
	}	
	return bRet;
}

bool CRLUnpacker::ResolveCalls(DWORD dwStart, DWORD dwSize, DWORD dwFlag)
{
	bool bRet = false;

	BYTE *bySrcbuff = NULL;
	if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSize)))
	{
		return bRet;
	}
	memset(bySrcbuff, 0x00, dwSize);

	if(m_objTempFile.ReadBuffer(bySrcbuff, dwStart, dwSize, dwSize))
	{	
		//Start Resolving
		for(DWORD dwCounter = 0, dwTemp = 0; dwCounter < dwSize - 5; dwCounter++)
		{
			if(bySrcbuff[dwCounter] == 0xE8 || bySrcbuff[dwCounter] == 0xE9)
			{
				dwTemp = *(DWORD *)(&bySrcbuff[dwCounter + 1]);
				if(dwFlag == 0x00)
				{
					dwTemp = (dwTemp<<0x18) | (dwTemp>>0x18) | ((dwTemp<<8)&0x00FF0000) | ((dwTemp>>8)&0x0000FF00);
					dwTemp -= dwCounter;
					*(DWORD *)(&bySrcbuff[dwCounter + 1]) = dwTemp;
				}
				else
				{
					if((dwTemp & 0xFF) == dwFlag)
					{
						dwTemp &= 0xFFFFFF00;
						dwTemp = (dwTemp<<0x18) | (dwTemp>>0x18) | ((dwTemp<<8)&0x00FF0000) | ((dwTemp>>8)&0x0000FF00);
						dwTemp -= (0x05 + dwCounter);
						*(DWORD *)(&bySrcbuff[dwCounter + 0x01]) = dwTemp;
					}
				}
				dwCounter+=4;
			}
		}

		if(m_objTempFile.WriteBuffer(bySrcbuff, dwStart, dwSize, dwSize))
		{
			bRet = true;
		}
	}

	if(bySrcbuff)
	{
		free(bySrcbuff);
		bySrcbuff = NULL;
	}

	return bRet;
}

