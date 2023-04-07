#include "MPressUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"
#include "lzmat.h"

CMPressUnpack::CMPressUnpack(CMaxPEFile *pMaxPEFile):CUnpackBase(pMaxPEFile)
{
}

CMPressUnpack::~CMPressUnpack(void)
{
	m_objTempFile.CloseFile();
}

bool CMPressUnpack::IsPacked() 
{
	/*if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".MPRESS", 7) == 0) ||
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[1].Name, ".MPRESS", 7) == 0) ||
		((_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".", 7) == 0) &&
		(_memicmp(m_pMaxPEFile->m_stSectionHeader[1].Name, ".", 7) == 0))
		)
		*/
	BYTE bmPressName[0x08] = {0x2E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(
		((_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, &bmPressName[0x00], 7) == 0) || (_memicmp(m_pMaxPEFile->m_stSectionHeader[1].Name,&bmPressName[0x00], 7) == 0)) ||
		((_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".MPRESS", 7) == 0) || (_memicmp(m_pMaxPEFile->m_stSectionHeader[1].Name,".MPRESS", 7) == 0))
		)
		)
	{
		BYTE byMPressUnpackSig[]={0x60,0xE8,0x00,0x00,0x00,0x00,0x58,0x05,0x8B,0x30,0x03,0xF0,0x2B,0xC0,0x8B,0xFE,0x66,0xAD};

		BYTE pbyBuff[sizeof(byMPressUnpackSig) + sizeof(DWORD)] = {0};
		if(m_pMaxPEFile->ReadBuffer(pbyBuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(byMPressUnpackSig) + sizeof(DWORD), sizeof(byMPressUnpackSig) + sizeof(DWORD)))
		{
			if(*(WORD*)&pbyBuff[0] == 0xE860)
			{
				if(memcmp(&pbyBuff[2], &byMPressUnpackSig[2], 0x06) == 0 && memcmp(&pbyBuff[0x0C], &byMPressUnpackSig[8], 0xA) == 0x00)
				{
					return true;
				}
			}
		}	
	}
	return false;
}

bool CMPressUnpack::ResolveCalls(DWORD dwSize, bool bSubtract)
{
	BYTE *bySrcbuff = NULL;
	if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSize)))
	{
		return false;
	}
	memset(bySrcbuff, 0x00, dwSize);
	
	//Starts from 1000 by default
	DWORD dwStart = 0x1000;
	if(m_objTempFile.ReadBuffer(bySrcbuff, dwStart, dwSize, dwSize))
	{
		if(dwSize < 0x1000)
		{
			return false;
		}
		if(bSubtract)
		{
			dwSize -= 0x1000;
		}
		DWORD dwtemp;
		//Start Resolving
		for(DWORD dwCounter = 0; dwCounter < (dwSize - 5); dwCounter++)
		{
			if(bySrcbuff[dwCounter] == 0xE8 || bySrcbuff[dwCounter] == 0xE9)
			{
				if((*(DWORD *)(&bySrcbuff[dwCounter + 1]) & 0x80000000) == 0x80000000)
				{
					dwtemp = *(DWORD*)(&bySrcbuff[dwCounter + 1]) + (dwCounter + 1);
					if((dwtemp & 0x80000000) != 0x80000000)
					 {
						 *(DWORD *)(&bySrcbuff[dwCounter + 1]) += (dwCounter+1);
						 *(DWORD *)(&bySrcbuff[dwCounter + 1]) += dwSize;
						 *(DWORD *)(&bySrcbuff[dwCounter + 1]) -= (dwCounter+1);
					 }
				}
				else if(*(DWORD *)(&bySrcbuff[dwCounter + 1]) < dwSize)
				{
					*(DWORD *)(&bySrcbuff[dwCounter + 1]) -= (dwCounter+1);
				}
				dwCounter+=4;
			}
		}

		if(!m_objTempFile.WriteBuffer(bySrcbuff, 0x1000, dwSize + (int(bSubtract)*0x1000), dwSize + (int(bSubtract)*0x1000)))
		{
			free(bySrcbuff);
			bySrcbuff=NULL;
			return false;
		}
	}

	free(bySrcbuff);
	bySrcbuff=NULL;
	return true;
}

bool CMPressUnpack::ResolveImportAddresses(DWORD *dwOrigAEP)
{
	//To read the source buffer which contains the DLL and API Names so that we can resolve them
	DWORD dwStartReadDLLName=*dwOrigAEP;
	
	BYTE byNamesbuff[0x04];
	dwStartReadDLLName += 0x05;
   	
	if(!m_objTempFile.ReadBuffer(byNamesbuff,dwStartReadDLLName,0x03,0x03))
	{
		return false;
	}	
	if(byNamesbuff[0]==0x74)
	{
		dwStartReadDLLName+=byNamesbuff[1]+0x07;
	}
	else if(byNamesbuff[1]==0x74)
	{
		dwStartReadDLLName+=byNamesbuff[2]+0x08;
	}
	else 
	{
		return false;
	}
	
	
	if(!m_objTempFile.ReadBuffer(byNamesbuff,dwStartReadDLLName+0x02,0x04,0x04))
	{
		return false;
	}
	
	dwStartReadDLLName+=*(DWORD*)&byNamesbuff[0];
	*dwOrigAEP=dwStartReadDLLName-0x04;

	if(!m_objTempFile.ReadBuffer(byNamesbuff,dwStartReadDLLName,0x04,0x04))
	{
		return false;
	}
	dwStartReadDLLName+=*(DWORD*)&byNamesbuff[0];

	DWORD dwIncrements = 0, dwNoOfDLLs = 0, dwInitialSize = 0x1000;
	BYTE bflagafter = 0, bflagNoOfDLL = 0, bflagbefore = 0;
	BYTE *bySrcbuff = (BYTE *)malloc(dwInitialSize);

	//First read the full buffer
	for(;;)
	{
		if(dwIncrements>(dwInitialSize-0x04))
		{
			dwInitialSize += 0x1000;
			bySrcbuff = (BYTE*)realloc(bySrcbuff,dwInitialSize);
		}

		if(!m_objTempFile.ReadBuffer(&bySrcbuff[dwIncrements],dwStartReadDLLName+dwIncrements,0x04,0x04))
		{
			free(bySrcbuff);
			bySrcbuff=NULL;
			return false;
		}

		if(bflagafter==0x00)
		{
			//If at the multiple of 4 break directly
			if(*(DWORD *)(&bySrcbuff[dwIncrements]) == 0xFFFFFFFF)  
			{
				break;
			}
			//If not a multiple of 4 then check data after/before
			if( ((*(DWORD *)(&bySrcbuff[dwIncrements]) == 0xFFFFFF00) && (bflagbefore = 0x04)) || 
				((*(DWORD *)(&bySrcbuff[dwIncrements]) == 0xFFFF0000) && (bflagbefore = 0x03)) ||
				(((*(DWORD *)(&bySrcbuff[dwIncrements]) & 0xFF000000) == 0xFF000000) && (bflagbefore = 0x02)) )
			{
				bflagafter=0x01;
			}
		}
		else if(bflagafter==0x01)
		{
			if( ((*(DWORD *)(&bySrcbuff[dwIncrements]) & 0x000000FF) == 0x000000FF && (bflagbefore == 0x04)) ||
				((*(DWORD *)(&bySrcbuff[dwIncrements]) & 0x0000FFFF) == 0x0000FFFF && (bflagbefore == 0x03))||
				((*(DWORD *)(&bySrcbuff[dwIncrements]) & 0x00FFFFFF) == 0x00FFFFFF && (bflagbefore == 0x02)) ) 
			{
				if(bflagbefore)
				{
					dwIncrements-=bflagbefore;
				}
				break;
			}
			bflagafter = 0;
			bflagbefore = 0;
		}
		dwIncrements += 0x04;
	}
	
	DWORD dwStartWriteDLLname = 0, dwWriteIncrements = 0;

	//Just running this full loop once only to get the count of the DLL's present
	for(DWORD dwCounter = 0; dwCounter < dwIncrements;)
	{
		dwStartWriteDLLname = dwStartWriteDLLname + (*(DWORD *)&bySrcbuff[dwCounter]) + dwWriteIncrements;
		dwWriteIncrements = 0;
		dwCounter += 4;

		while(bySrcbuff[dwCounter] != 0)
		{
			dwCounter++;
		}
		dwCounter++;
		while(dwCounter < dwIncrements)
		{
			if(bySrcbuff[dwCounter] == 0)
			{
				/*if(*(DWORD*)&(bySrcbuff[dwCounter+0x01])==0x00)
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					return false;
				}*/
				dwCounter += 0x01;
				dwNoOfDLLs++;
				if(dwCounter == dwIncrements && bflagbefore == 0)
				{
					dwNoOfDLLs--;
				}
				break;
			}

			if(bySrcbuff[dwCounter] <= 0x20)
			{
				dwCounter += 0x03;
				continue;
			}
			while(bySrcbuff[dwCounter] != 0)
			{
				dwCounter++;
			}
			dwCounter++;
			if(dwCounter == dwIncrements)
			{
				break;
			}
		}
	}

	dwNoOfDLLs += 2; //To also include the last Import Directory Entry
	DWORD dwImportSize = 0x1000;
	BYTE *byImportTablebuff = (BYTE*)malloc(dwImportSize);
	
	while(dwImportSize < ((dwNoOfDLLs)*0x14))
	{
		dwImportSize += m_objTempFile.m_stPEHeader.SectionAlignment;
		byImportTablebuff = (BYTE*)realloc(byImportTablebuff, dwImportSize);
	}
	memset(byImportTablebuff, 0, dwImportSize);

	//To write the value of the Import Table RVA present in the Data Directory
	if(!m_objTempFile.WriteBuffer(&m_objTempFile.m_dwFileSize, m_objTempFile.m_stPEHeader.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+0x68,0x04,0x04))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		free(byImportTablebuff);
		byImportTablebuff=NULL;
		return false;
	}

	//To increment the number of sections by 1
	DWORD dwNoofSections = m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + 2;
	if(!m_objTempFile.ReadBuffer(&dwNoofSections, dwNoofSections, 2, 2))
	{
		
		free(bySrcbuff);
		bySrcbuff=NULL;
		free(byImportTablebuff);
		byImportTablebuff=NULL;
		return false;
	}
	dwNoofSections++;
	if(!m_objTempFile.WriteBuffer(&dwNoofSections, m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + 2, 2, 2))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		free(byImportTablebuff);
		byImportTablebuff=NULL;
		return false;
	}

	//For the last Import Directory Entry
	memset(&byImportTablebuff[((dwNoOfDLLs-1) * 0x14)], 0, 0x14); 

	dwWriteIncrements=0;
	DWORD dwWriteAPICount=0;
	dwStartWriteDLLname=dwStartReadDLLName;

	for(DWORD dwCounter = 0, dwDLLCount = 0; dwCounter < dwIncrements; dwDLLCount++)
	{
		dwStartWriteDLLname += *(DWORD *)(&bySrcbuff[dwCounter]) + dwWriteIncrements;
		memset(&byImportTablebuff[dwDLLCount * 0x14], 0, 0xC); //First 12 all 0's in the Import Directory Table
		if(dwDLLCount == 0)
		{
			*(DWORD *)(&byImportTablebuff[(dwDLLCount*0x14)+0xC]) = m_objTempFile.m_dwFileSize + dwWriteAPICount + (dwNoOfDLLs * 0x14);
		}
		else
		{
			//Once a new DLL is encountered it keeps only a single space between the new DLL name and the end of the api name of the previous DLL
			dwWriteAPICount-=2;
			*(DWORD *)(&byImportTablebuff[(dwDLLCount*0x14)+0xC]) = m_objTempFile.m_dwFileSize + dwWriteAPICount + (dwNoOfDLLs * 0x14);
		}
		dwCounter += 0x04;
		*(DWORD*)(&byImportTablebuff[(dwDLLCount*0x14)+0x10]) = dwStartWriteDLLname;
		dwWriteAPICount += strlen((const char*)(&bySrcbuff[dwCounter])) + 3;
		dwWriteIncrements = 0;
		dwCounter += strlen((const char*)(&bySrcbuff[dwCounter])) + 1;

		while(dwCounter < dwIncrements)
		{
			if(bySrcbuff[dwCounter] == 0x00)
			{
				dwCounter++;
				break;
			}
			//For Ordinal handling
			if(bySrcbuff[dwCounter] <= 0x20)
			{
				dwCounter += 0x03;
				dwWriteIncrements += 0x04;
				continue;
			}
			//For API Name handling
			dwWriteAPICount += strlen((const char*)(&bySrcbuff[dwCounter])) + 3;
			dwWriteIncrements += 0x04;

			dwCounter += strlen((const char*)(&bySrcbuff[dwCounter])) + 1;
			if(dwCounter == dwIncrements)
			{
				break;
			}
		}
	}
	
	while(dwImportSize < dwWriteAPICount + (dwNoOfDLLs * 0x14))
	{
		byImportTablebuff = (BYTE *)realloc(byImportTablebuff, dwImportSize + m_objTempFile.m_stPEHeader.SectionAlignment);
		memset(byImportTablebuff + dwImportSize, 0, m_objTempFile.m_stPEHeader.SectionAlignment);
		dwImportSize += m_objTempFile.m_stPEHeader.SectionAlignment;
	}

	DWORD dwWriteFunctionPointerName = 0, dwWriteZero = 0, dwWriteAPIName = 0, dwAPIOffset;

	for(DWORD dwCounter = 0, dwDLLCount = 0; dwCounter < dwIncrements; dwDLLCount++)
	{
		dwWriteIncrements=0x00;
		dwAPIOffset=0x00;
		
		dwWriteAPIName = *(DWORD *)(&byImportTablebuff[(dwDLLCount * 0x14)+0xC]);
		dwWriteFunctionPointerName = *(DWORD *)(&byImportTablebuff[(dwDLLCount * 0x14) + 0x10]);
		dwCounter += 0x04;

		memcpy((&byImportTablebuff[dwWriteAPIName - m_objTempFile.m_dwFileSize]), (char *)(&bySrcbuff[dwCounter]), strlen((char *)(&bySrcbuff[dwCounter])));
		dwAPIOffset += strlen((char*)(&bySrcbuff[dwCounter]));
		memcpy(&byImportTablebuff[dwWriteAPIName - m_objTempFile.m_dwFileSize + dwAPIOffset], &dwWriteZero, 0x03);
		dwAPIOffset += 0x03; 
		dwCounter += strlen((char*)(&bySrcbuff[dwCounter]))+1;
		
		while(dwCounter < dwIncrements)
		{
			if(bySrcbuff[dwCounter] == 0x00)
			{
				dwCounter++;
				break;
			}
			if(bySrcbuff[dwCounter] <= 0x20)
			{				
				DWORD dwFunctionOrdinalValue = 0x80000000;
				dwFunctionOrdinalValue |= *(WORD *)(&bySrcbuff[dwCounter + 1]);
				dwCounter += 0x03;
				if(dwWriteFunctionPointerName>m_objTempFile.m_dwFileSize)
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					free(byImportTablebuff);
					byImportTablebuff=NULL;
					return false;
				}
				if(!m_objTempFile.WriteBuffer(&dwFunctionOrdinalValue,dwWriteFunctionPointerName+dwWriteIncrements,0x04,0x04))
				{
					
					free(bySrcbuff);
					bySrcbuff=NULL;
					free(byImportTablebuff);
					byImportTablebuff=NULL;
					return false;
				}
				dwWriteIncrements+=0x04;
				continue;
			}

			memcpy((&byImportTablebuff[dwWriteAPIName-m_objTempFile.m_dwFileSize+dwAPIOffset]),(char*)(&bySrcbuff[dwCounter]),strlen((char*)(&bySrcbuff[dwCounter])));
			DWORD temp = dwWriteAPIName + dwAPIOffset - 0x02;
			if(dwWriteFunctionPointerName>m_objTempFile.m_dwFileSize)
			{
				free(bySrcbuff);
				bySrcbuff=NULL;
				free(byImportTablebuff);
				byImportTablebuff=NULL;
				return false;
			}
			if(!m_objTempFile.WriteBuffer(&temp, dwWriteFunctionPointerName + dwWriteIncrements, 0x04, 0x04))
			{
				free(bySrcbuff);
				bySrcbuff=NULL;
				free(byImportTablebuff);
				byImportTablebuff=NULL;
				return false;
			}
			dwWriteIncrements += 0x04;

			dwAPIOffset+=strlen((char*)(&bySrcbuff[dwCounter]));
			memcpy(&byImportTablebuff[dwWriteAPIName - m_objTempFile.m_dwFileSize + dwAPIOffset], &dwWriteZero, 0x03);
			dwAPIOffset += 0x03;
			dwCounter += strlen((char*)(&bySrcbuff[dwCounter]))+1;

			if(dwCounter == dwIncrements)
			{
				break;
			}
		}
	}
	
	if(!AddNewSection(dwImportSize))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		free(byImportTablebuff);
		byImportTablebuff=NULL;
		return false;
	}

	//Writing the basic Import Directory Table buffer to memory
	if(!m_objTempFile.WriteBuffer(byImportTablebuff, m_objTempFile.m_dwFileSize, dwImportSize, dwImportSize))
	{
		free(bySrcbuff);
		bySrcbuff=NULL;
		free(byImportTablebuff);
		byImportTablebuff=NULL;
		return false;
	}	
	free(bySrcbuff);
	bySrcbuff=NULL;
	free(byImportTablebuff);
	byImportTablebuff=NULL;
	return true;
}

bool CMPressUnpack::Unpack(LPCTSTR szTempFileName)
{
	DWORD dwStartOffset = 0, dwRVAStartOffset = 0, dwOrigAEP = 0, dwFirstOffset = 0;
	BYTE byMpressBuff[0x20];

	if(m_pMaxPEFile->ReadBuffer(byMpressBuff, m_pMaxPEFile->m_dwAEPMapped + 0x08, 0x04, 0x04))
	{
		dwFirstOffset = *(DWORD *)&byMpressBuff[0];
		dwRVAStartOffset = m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + *(DWORD *)&byMpressBuff[0] + 0x02;

		if(m_pMaxPEFile->Rva2FileOffset(dwRVAStartOffset,&dwStartOffset) != OUT_OF_FILE)
		{
			if(m_pMaxPEFile->ReadBuffer(byMpressBuff, dwStartOffset, 0x08, 0x08))
			{
				dwOrigAEP = dwRVAStartOffset + *(DWORD *)&byMpressBuff[0] + 4;
				dwRVAStartOffset += *(DWORD *)&byMpressBuff[4] + 4;

				if(m_pMaxPEFile->Rva2FileOffset(dwRVAStartOffset,&dwStartOffset) != OUT_OF_FILE)
				{
					DWORD dwReadSize = 0x08;
					//Case for LZMAT..Here there are no LZMA properties which are used only in LZMA
					if(dwFirstOffset == 0x29F  || dwFirstOffset == 0x2B6 || dwFirstOffset==0x29E)
					{ 
						dwReadSize -= 0x02;						
					}
					if(m_pMaxPEFile->ReadBuffer(byMpressBuff, dwStartOffset, dwReadSize, dwReadSize))
					{
						BYTE byLZMAProp[4] = {0};
						if(dwFirstOffset != 0x29F && dwFirstOffset!=0x29E)
						{ 
							//Case for the LZMA properties.This occurs only with LZMA
							byLZMAProp[0] = byMpressBuff[7];                        
							byLZMAProp[1] = byMpressBuff[6] & 0x0F;
							byLZMAProp[2] = byMpressBuff[6] >> 4;
						}

						//Source Compressed Size and Destination Uncompressed Size
						DWORD dwSrcSize = *(DWORD *)&byMpressBuff[2];
						DWORD dwDestSize = DWORD(*(WORD *)&byMpressBuff[0] << 0x0C);
					
						if(!ReOrganizeFile(szTempFileName, true, false))
						{
							return false;
						}

						if(dwSrcSize > 10 * 1024 * 1024 || dwDestSize > 10 * 1024 * 1024 )
						{
							return false;
						}

						__try
						{							
							if(dwFirstOffset == 0x29F || dwFirstOffset == 0x2B6 || dwFirstOffset==0x29E) //Case for LZMAT
							{
								if(!(dwDestSize = LZMATUncompress(dwSrcSize, dwDestSize)))
								{
									return false;
								}
							}							
							else	//Case for LZMA
							{
								DWORD dwReadOffset = m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData + 0x08;
								DWORD dwWriteOffset = m_objTempFile.m_stSectionHeader[0].VirtualAddress;
								if(!(dwDestSize = LZMADecompress(byLZMAProp, dwSrcSize, dwDestSize, dwReadOffset, dwWriteOffset, NULL)))
								{
									return false;
								}
							}

							//Closing and opening the file again so that it reflects unpacked size
							m_objTempFile.CloseFile();

							if(!m_objTempFile.OpenFile(szTempFileName, true))
							{
								return false;
							}
							//Resolving the E8/E9 calls
	                        bool bSubtract=true;
							if(dwFirstOffset==0x29E)
							{
								bSubtract=false;
							}
							if(ResolveCalls(dwDestSize,bSubtract))
							{
								//Writing the API Addresses at the specified offset
								if(ResolveImportAddresses(&dwOrigAEP))
								{
									m_objTempFile.CloseFile();

									if(!m_objTempFile.OpenFile(szTempFileName, true))
									{
										return false;
									}

									if(!m_objTempFile.CalculateLastSectionProperties())
									{
										return false;
									}
									//Just reading statically from an offset..Worked for 2 files so keeping it the same
									if(!m_objTempFile.ReadBuffer(byMpressBuff,dwOrigAEP,0x04,0x04))
									{
										return false;
									}
									//Setting the AEP..Here we can also rename the section to ease scanning
									if(m_objTempFile.WriteAEP(dwOrigAEP+*(DWORD*)&byMpressBuff[0]+0x04))
									{
										if(!ReOrganizeFile(szTempFileName, false))
										{
											return false;
										}
										return true;
									}
								}
							}
						}
						__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception caught in Mpress Unpacking"), m_pMaxPEFile->m_szFilePath, false))
						{
						}
					}
				}
			}
		}
	}
	return false;
}

DWORD CMPressUnpack::LZMATUncompress(DWORD dwSrcSize,DWORD dwDestSize)
{
	DWORD dwRet = 0;

	BYTE *bySrcbuff = NULL;
	BYTE *byDestbuff = NULL;

	//Allocating a buffer to read the SourceSize
	if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSrcSize)))
	{
		return dwRet;
	}
	memset(bySrcbuff, 0x00, dwSrcSize);

	//Reading from PRD of First Section+0x06
	if(!m_objTempFile.ReadBuffer(bySrcbuff, (m_objTempFile.m_stSectionHeader[0].PointerToRawData + 0x06), dwSrcSize, dwSrcSize))
	{
		free(bySrcbuff);
		bySrcbuff = NULL;
		return dwRet;
	}

	if(!(byDestbuff = (BYTE *)MaxMalloc(dwDestSize)))
	{
		free(bySrcbuff);
		bySrcbuff = NULL;
		return dwRet;
	}	
	memset(byDestbuff, 0x00, dwDestSize);

	DWORD dwtempDestSize = dwDestSize;

	//LZMAT Decompression
	int err = lzmat_decode(byDestbuff, &dwDestSize, bySrcbuff, dwSrcSize);

	//Only when err returns 0 does the uncompression succeed
	if(err == 0 && dwDestSize == dwtempDestSize)
	{		
		if(m_objTempFile.WriteBuffer(byDestbuff,m_objTempFile.m_stSectionHeader[0].VirtualAddress, dwDestSize, dwDestSize))
		{
			dwRet = dwDestSize;
		}
	}
	free(bySrcbuff);
	bySrcbuff=NULL;
	
	free(byDestbuff);
	byDestbuff=NULL;
	
	return dwRet;
}
