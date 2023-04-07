#include "pch.h"
#include "MaxYara.h"

CMaxYara::CMaxYara(CMaxPEFile *pMaxPEFile)
{
	_tcscpy(m_szIMPHash,L"");
	m_pMaxPEFile = pMaxPEFile;
}

CMaxYara::~CMaxYara(void)
{
	if(m_pMaxPEFile != NULL)
	{
		m_pMaxPEFile->SetFilePointer(0,NULL,FILE_BEGIN,0);
	}
}

bool CMaxYara::GetAPIfromOrdList(char *pszDllName,int iOrdinal,char *pszAPIName)
{
	bool	bFound = false;

	if (pszDllName == NULL || pszAPIName == NULL || iOrdinal == 0x00)
	{
		return bFound;
	}

	//iOrdinal++;
	if (strstr(pszDllName,"oleaut32") != NULL)
	{
		if (iOrdinal < 444)
		{
			strcpy(pszAPIName,m_Oleaut32[iOrdinal]);
			bFound = true;
		}
	}
	else if (strstr(pszDllName,"ws2_32") != NULL)
	{
		if (iOrdinal < 117)
		{
			strcpy(pszAPIName,m_ws32[iOrdinal]);
			bFound = true;
		}
	}

	return bFound;
}

bool CMaxYara::GetIMPHashforYARA()
{
	bool					bReturn = false;
	char					*szIMPHashBuff = NULL;
	DWORD					dwBufferLenth = 15 * 1024;	
	bool					bMemAllocFailed = false;
	

	typedef struct _MAX_IMP_TABLE_STRUCT
	{
		DWORD	dwNameTableRVA;
		DWORD	dwTimeStamp;
		DWORD	dwFwrdChain;
		DWORD	dwNameRVA;
		DWORD	dwAddTableRVA;
	}MAX_IMP_TABLE_STRUCT,*LPMAX_IMP_TABLE_STRUCT;
	
	MAX_IMP_TABLE_STRUCT	*pImpTable = NULL;

	try
	{
	
		
		typedef struct _MAX_NAME_TABLE_STRUCT
		{
			WORD	wHint;
			char	szData[MAX_PATH];
		}MAX_NAME_TABLE_STRUCT;

		_tcscpy(m_szIMPHash,L"");

		if (m_pMaxPEFile == NULL)
		{
			return bReturn;	
		}

		if (m_pMaxPEFile->m_bPEFile == false)
		{
			return bReturn;
		}

		DWORD	dwIMPTableRVA = 0x00, dwIMPTableOffset = 0x00, dwIMPTableSize = 0x00;
		DWORD	dwEntryCnt = 0x00;

		dwIMPTableRVA = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].VirtualAddress; 
		dwIMPTableSize = m_pMaxPEFile->m_stPEHeader.DataDirectory[0x01].Size;

		
		if ((dwIMPTableSize % 20) != 0x00 && m_pMaxPEFile->m_b64bit == false)
		{
			return bReturn;
		}
		

		dwEntryCnt = dwIMPTableSize / 20;

		if (dwEntryCnt == 0x00)
		{
			return bReturn;
		}

		dwIMPTableSize = dwEntryCnt * sizeof(MAX_IMP_TABLE_STRUCT);

		//MAX_IMP_TABLE_STRUCT	objImpTable[dwEntryCnt] = {0x00};
		
		LPVOID	pLPDummy = calloc(dwEntryCnt,sizeof(MAX_IMP_TABLE_STRUCT));

		pImpTable = (MAX_IMP_TABLE_STRUCT *)pLPDummy;
		//pImpTable = (MAX_IMP_TABLE_STRUCT **) new MAX_IMP_TABLE_STRUCT[dwEntryCnt];
		

		m_pMaxPEFile->Rva2FileOffset(dwIMPTableRVA,&dwIMPTableOffset);

		if (dwIMPTableOffset == 0x00 || dwIMPTableOffset >= m_pMaxPEFile->m_dwFileSize)
		{
			if (pImpTable)
			{
				delete pImpTable;
				pImpTable = NULL;
			}
			return bReturn;
		}

		if (!m_pMaxPEFile->ReadBuffer((LPVOID)&pImpTable[0x00],dwIMPTableOffset,dwIMPTableSize,dwIMPTableSize))
		{
			if (pImpTable)
			{
				delete pImpTable;
				pImpTable = NULL;
			}
			return bReturn;
		}

		//char	szIMPHashBuff[15360] = {0x00};
		

		//szIMPHashBuff = new char[dwBufferLenth];
		szIMPHashBuff = (char *)calloc(dwBufferLenth,sizeof(char));

		memset(szIMPHashBuff,0x00,(dwBufferLenth));

		if (szIMPHashBuff == NULL)
		{
			if (pImpTable)
			{
				delete pImpTable;
				pImpTable = NULL;
			}
			return bReturn;
		}

		
		for (int i = 0x00; i < dwEntryCnt; i++)
		{
			DWORD	dwFileOffset = 0x00;
			char	szDllName[MAX_PATH] = {0x00};

			if (pImpTable[i].dwNameTableRVA == 0x00 && pImpTable[i].dwNameRVA == 0x00 && pImpTable[i].dwAddTableRVA == 0x00)
			{
				break;
			}
			
			m_pMaxPEFile->Rva2FileOffset(pImpTable[i].dwNameRVA ,&dwFileOffset);
			
			if (pImpTable[i].dwNameRVA != 0x00 && dwFileOffset < m_pMaxPEFile->m_dwFileSize)
			{
				strcpy(szDllName,"");

				m_pMaxPEFile->ReadBuffer(&szDllName[0x00],dwFileOffset,MAX_PATH,5);
				strlwr(szDllName);

				char	*pTemp = NULL;
				pTemp = strstr(szDllName,".dll");
				if (pTemp)
				{
					*pTemp = '\0';
					pTemp = NULL;
				}

				if (strlen(szDllName) > 0x00)
				{
					dwFileOffset = 0x00;
					DWORD	dwReqAddress = pImpTable[i].dwNameTableRVA;

					if (dwReqAddress == 0x00 && pImpTable[i].dwAddTableRVA != 0x00)
					{
						dwReqAddress = pImpTable[i].dwAddTableRVA;
					}
					m_pMaxPEFile->Rva2FileOffset(dwReqAddress ,&dwFileOffset);
					if (dwReqAddress != 0x00 && dwFileOffset < m_pMaxPEFile->m_dwFileSize)
					{
						while(1)
						{
							DWORD					dwAPIRVA = 0x00,dwAPIOffset = 0x00,dwCurBuffLen = 0x00;
							MAX_NAME_TABLE_STRUCT	objNMTable = {0x00};
							ULONG64					ulAPIRVA = 0x00;

							dwCurBuffLen = strlen(szIMPHashBuff);
							if (dwCurBuffLen < dwBufferLenth)
							{
								if ((dwBufferLenth - dwCurBuffLen) < 1000)
								{
									dwBufferLenth += 0x1000;
									szIMPHashBuff = (char *)realloc((LPVOID)&szIMPHashBuff[0x00],dwBufferLenth);
									if (szIMPHashBuff == NULL)
									{
										bMemAllocFailed = true;
										break;
									}
								}
							}

							if (m_pMaxPEFile->m_b64bit)
							{
								if (!m_pMaxPEFile->ReadBuffer(&ulAPIRVA,dwFileOffset,sizeof(ULONG64),sizeof(ULONG64)))
								{
									break;
								}
								dwAPIRVA = ulAPIRVA;
							}
							else
							{
								if (!m_pMaxPEFile->ReadBuffer(&dwAPIRVA,dwFileOffset,sizeof(DWORD),sizeof(DWORD)))
								{
									break;
								}
							}	
							if (dwAPIRVA > 0x80000000 || ulAPIRVA > 0x8000000000000000)
							{
								if (dwAPIRVA > 0x80000000)
								{
									dwAPIOffset = dwAPIRVA - 0x80000000;
								}
								else
								{
									dwAPIOffset = dwAPIRVA;
								}

								char szName2Append[512] = {0x00},szAPIName[512] = {0x00};
								
								if (GetAPIfromOrdList(szDllName,dwAPIOffset,&szAPIName[0x00]))
								{
									strlwr(szAPIName);
									sprintf(szName2Append,"%s.%s",szDllName,szAPIName);
								}
								else
								{
									sprintf(szName2Append,"%s.ord%d",szDllName,dwAPIOffset);
								}
								if (dwCurBuffLen > 0x00)
								{
									strcat(szIMPHashBuff,",");
								}
								strcat(szIMPHashBuff,szName2Append);

								dwFileOffset += sizeof(DWORD);
								if (m_pMaxPEFile->m_b64bit)
								{
									dwFileOffset += sizeof(DWORD);
								}
								continue;
							}
							m_pMaxPEFile->Rva2FileOffset(dwAPIRVA ,&dwAPIOffset);

							if (dwAPIRVA == 0x00 || dwAPIOffset == 0x00)
							{
								break;
							}

							dwFileOffset += sizeof(DWORD);
							if (m_pMaxPEFile->m_b64bit)
							{
								dwFileOffset += sizeof(DWORD);
							}
							if (dwAPIOffset < m_pMaxPEFile->m_dwFileSize)
							{
								m_pMaxPEFile->ReadBuffer(&objNMTable,dwAPIOffset,sizeof(MAX_NAME_TABLE_STRUCT),5);
								strlwr(objNMTable.szData);
								if (strlen(objNMTable.szData) > 0x00)
								{
									char szName2Append[512] = {0x00};
									sprintf(szName2Append,"%s.%s",szDllName,objNMTable.szData);
									if (dwCurBuffLen > 0x00)
									{
										strcat(szIMPHashBuff,",");
									}
									strcat(szIMPHashBuff,szName2Append);
								}
							}
							else
							{
								break;
							}
						}//while
						if (bMemAllocFailed == true)
						{
							break;
						}
					}
				}
			}

		}

		if (bMemAllocFailed == false)
		{
			DWORD	dwBuffLen = 0x00;
			dwBuffLen = strlen(szIMPHashBuff);
			if (dwBuffLen > 0x00)
			{
				CMaxMD5	objMD5;
				//strcpy(szImpHash,objMD5.digestString((BYTE *)&szIMPHashBuff[0x00],dwBuffLen * sizeof(char)));
				_stprintf(m_szIMPHash,L"%S",objMD5.digestString((BYTE *)&szIMPHashBuff[0x00],dwBuffLen * sizeof(char))); 
				_tcsupr(m_szIMPHash);
				bReturn = true;
			}
		}
		if (pImpTable)
		{
			delete pLPDummy;
			pImpTable = NULL;
			pLPDummy = NULL;
		}
		if (szIMPHashBuff)
		{
			delete szIMPHashBuff;
			szIMPHashBuff = NULL;
		}
	}
	catch(...)
	{
		if (pImpTable)
		{
			delete pImpTable;
			pImpTable = NULL;
		}
		if (szIMPHashBuff)
		{
			delete szIMPHashBuff;
			szIMPHashBuff = NULL;
		}
	}

	return bReturn;
}

bool CMaxYara::ValidatePERules(LPTSTR pszPERules)
{
	bool	bRulesMatched = false;

	if (m_pMaxPEFile == NULL || pszPERules == NULL)
	{
		return bRulesMatched; 
	}

	CString		csRule,csToken;

	csRule.Format(L"%s",pszPERules);
	csRule.MakeUpper();

	csRule.Replace(L"[",L"");
	csRule.Replace(L"]",L"");

	bool	bTokenMatched = false;
	int		iContext =0;

	csToken = csRule.Tokenize(_T("}"), iContext);
	while(_T("") != csToken)
	{
		if (csToken.Find(L"IMPHASH{") != -1) //IMPORT TABLE HASH
		{
			if (_tcslen(m_szIMPHash) == 0x00)
			{
				bTokenMatched = false;
				break;
			}

			csToken.Replace(L"IMPHASH{",L"");
			if (csToken.Find(m_szIMPHash) == -1)
			{
				bTokenMatched = false;
				break;
			}
			else
			{
				bTokenMatched = true;
			}
		}
		if (csToken.Find(L"AEP{") != -1)//ADRESS OF ENTRY POINT
		{
			csToken.Replace(L"AEP{",L"");
			csToken.Replace(L"0X",L"");
			csToken.Replace(L",",L"");
			if (csToken.GetLength() > 0x00)
			{
				DWORD	dwAEP = _tcstol(csToken,NULL,0x10);
				if (dwAEP != m_pMaxPEFile->m_dwAEPMapped)
				{
					bTokenMatched = false;
					break;
				}
				else
				{
					bTokenMatched = true;
				}
			}
			else
			{
				bTokenMatched = false;
				break;
			}
			
		}
		if (csToken.Find(L"FZ{") != -1)//FILE SIZE
		{
			csToken.Replace(L"FZ{",L"");
			if (CheckFileSizeRule(csToken))
			{
				bTokenMatched = true;
			}
			else
			{
				bTokenMatched = false;
				break;
			}
		}
		if (csToken.Find(L"NSEC{") != -1)//NO OF SECTIONS
		{
			csToken.Replace(L"NSEC{",L"");

			csToken.Replace(L"0X",L"");
			csToken.Replace(L",",L"");
			if (csToken.GetLength() > 0x00)
			{
				DWORD	dwNoOfSecs = _tcstol(csToken,NULL,0x10);
				if (dwNoOfSecs != m_pMaxPEFile->m_stPEHeader.NumberOfSections)
				{
					bTokenMatched = false;
					break;
				}
				else
				{
					bTokenMatched = true;
				}
			}
			else
			{
				bTokenMatched = false;
				break;
			}
			
		}
		if (csToken.Find(L"OVSZ{") != -1)//OVELAY SIZE
		{
			csToken.Replace(L"OVSZ{",L"");

			csToken.Replace(L"0X",L"");
			csToken.Replace(L",",L"");
			if (csToken.GetLength() > 0x00)
			{
				DWORD	dwOverLaySz = _tcstol(csToken,NULL,0x10);
				DWORD	dwFileOverlaySize = m_pMaxPEFile->m_dwFileSize -(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].PointerToRawData + m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections-1].SizeOfRawData);
				if (dwFileOverlaySize > 0x00 && dwFileOverlaySize < m_pMaxPEFile->m_dwFileSize)
				{
					if (dwFileOverlaySize != dwOverLaySz)
					{
						bTokenMatched = false;
						break;
					}
					else
					{
						bTokenMatched = true;
					}
				}
				else
				{
					bTokenMatched = false;
					break;
				}
			}
			else
			{
				bTokenMatched = false;
				break;
			}
			
		}
		if (csToken.Find(L"SRVA{") != -1)//SECTION RVA e.g SRVA{0=0x10000,1=0x20000}
		{
			csToken.Replace(L"SRVA{",L"");
			if (CheckSecSizeRule(csToken,1))
			{
				bTokenMatched = true;
			}
			else
			{
				bTokenMatched = false;
				break;
			}
			
		}
		if (csToken.Find(L"SVSZ{") != -1)//SECTION'S VIRTUAL SIZE
		{
			csToken.Replace(L"SVSZ{",L"");
			if (CheckSecSizeRule(csToken,2))
			{
				bTokenMatched = true;
			}
			else
			{
				bTokenMatched = false;
				break;
			}
			
		}
		if (csToken.Find(L"SPRD{") != -1)//SECTION'S POINTER TO RAW DATA
		{
			csToken.Replace(L"SPRD{",L"");
			if (CheckSecSizeRule(csToken,3))
			{
				bTokenMatched = true;
			}
			else
			{
				bTokenMatched = false;
				break;
			}
			
		}
		if (csToken.Find(L"SSRD{") != -1)//SECTION'S SIZE OF RAW DATA
		{
			csToken.Replace(L"SSRD{",L"");
			if (CheckSecSizeRule(csToken,4))
			{
				bTokenMatched = true;
			}
			else
			{
				bTokenMatched = false;
				break;
			}
		}
		if (csToken.Find(L"SNAME{") != -1)//SECTION'S NAME e.g. SNAME{0=".SFFDFDFD"}
		{
			csToken.Replace(L"SNAME{",L"");
			if (CheckSecSizeRule(csToken,5))
			{
				bTokenMatched = true;
			}
			else
			{
				bTokenMatched = false;
				break;
			}
		}
		
		csToken = csRule.Tokenize(_T("}"), iContext);
	}

	if (bTokenMatched == true)
	{
		bRulesMatched = true;
	}
	return bRulesMatched;
}

//1 : RVA, 2 : Virtual Size, 3 : Pointer to Raw, 4 : SRD, 5 : Section Name
bool CMaxYara::CheckSecSizeRule(CString csPERules,int iSecProperty)
{
	bool		bMatched = false;
	CString		csData,csToken;
	
	csData.Format(L"%s",csPERules);
	csData.Trim();

	int		iContext = 0x00;
	int		iNoofToken = 0, iTokenMatched = 0;
	csToken = csData.Tokenize(_T(","), iContext);
	while(_T("") != csToken)
	{	

		csToken.Trim();
		iNoofToken++;
		CString csPart1,csPart2;
		int		iPos = 0;
		iPos = csToken.Find(L"=");

		if (iPos != -1)
		{
			csPart1 = csToken.Left(iPos).Trim();
			csPart2 = csToken.Mid(iPos+1).Trim();

			csPart1.Replace(L"0X",L"");
			csPart2.Replace(L"0X",L"");

			
			DWORD	dwSecNo = _tcstol(csPart1,NULL,0x10);
			DWORD	dwValue = 0x00;
			if (iSecProperty != 5)
			{
				dwValue = _tcstol(csPart2,NULL,0x10);
			}

			if (dwSecNo <= m_pMaxPEFile->m_stPEHeader.NumberOfSections)
			{
				switch(iSecProperty)
				{
				case 1:
					{
						if (m_pMaxPEFile->m_stSectionHeader[dwSecNo].VirtualAddress == dwValue)
						{
							iTokenMatched++;
						}
					}
					break;
				case 2 :
					{
						if (m_pMaxPEFile->m_stSectionHeader[dwSecNo].Misc.VirtualSize == dwValue)
						{
							iTokenMatched++;
						}
					}
					break;
				case 3 : 
					{
						if (m_pMaxPEFile->m_stSectionHeader[dwSecNo].PointerToRawData == dwValue)
						{
							iTokenMatched++;
						}
					}
					break;
				case 4 : 
					{
						if (m_pMaxPEFile->m_stSectionHeader[dwSecNo].SizeOfRawData == dwValue)
						{
							iTokenMatched++;
						}
					}
					break;
				case 5 : 
					{
						TCHAR	szSecName[MAX_PATH] = {0x00};

						_stprintf( szSecName,L"%S",(char *)m_pMaxPEFile->m_stSectionHeader[dwSecNo].Name);
						szSecName[0x08] = '\0';
						_tcsupr(szSecName);

						csPart2.Replace(L"\"",L"");
						if (csPart2.Find(szSecName) != -1)
						{
							iTokenMatched++;
						}
					}
					break;
				default:
					break;
				}
			}
		}
		csToken = csData.Tokenize(_T(","), iContext);
	}
	if (iNoofToken > 0x00 && iNoofToken == iTokenMatched)
	{
		bMatched = true;
	}

	return bMatched;
}

bool CMaxYara::CheckFileSizeRule(CString csPERules)
{
	bool		bMatched = false;
	CString		csData;

	csData.Format(L"%s",csPERules);
	csData.Trim();

	csData.Replace(L",",L"");

	if (csData.Find(L"<>") != -1)
	{
		CString csPart1,csPart2;
		int		iPos = 0x00;
		
		iPos = csData.Find(L"<>");
		csPart1 = csData.Left(iPos);
		csPart2 = csData.Mid(iPos+2);
		
		csPart1.Replace(L"0X",L"");
		csPart2.Replace(L"0X",L"");
		csPart1.Trim();
		csPart2.Trim();

		DWORD	dwSmall = _tcstol(csPart1,NULL,0x10);
		DWORD	dwLarge = _tcstol(csPart2,NULL,0x10);

		dwSmall = dwSmall * 1024;
		dwLarge = dwLarge * 1024;

		if (m_pMaxPEFile->m_dwFileSize >= dwSmall && m_pMaxPEFile->m_dwFileSize <= dwLarge)
		{
			return true;
		}
	
	}
	else if (csData.Find(L">") != -1)
	{
		csData.Replace(L">",L"");
		csData.Replace(L"0X",L"");
		csData.Trim();
		DWORD	dwSmall = _tcstol(csData,NULL,0x10);
		
		dwSmall = dwSmall * 1024;
		if (m_pMaxPEFile->m_dwFileSize > dwSmall)
		{
			return true;
		}
	}
	else if (csData.Find(L"<") != -1)
	{
		csData.Replace(L"<",L"");
		csData.Replace(L"0X",L"");
		csData.Trim();
		DWORD	dwLarge = _tcstol(csData,NULL,0x10);

		dwLarge = dwLarge * 1024;
		if (m_pMaxPEFile->m_dwFileSize < dwLarge)
		{
			return true;
		}
	}
	else
	{
		csData.Replace(L"0X",L"");
		csData.Trim();
		DWORD	dwLarge = _tcstol(csData,NULL,0x10);

		//dwLarge = dwLarge * 1024;
		if (dwLarge == m_pMaxPEFile->m_dwFileSize)
		{
			return true;
		}
	}

	return bMatched;
}

bool CMaxYara::CheckStaticYaraRules(CTreeManager *pYaraTree)
{
	bool	bVirusFound = false;
	int		iCnt = 0x00;

	for (iCnt = 0x00; iCnt < pYaraTree->m_dwYaraPEListCnt; iCnt++)
	{
		if (pYaraTree->m_pYaraPEList[iCnt]->bOnlyRule == true)
		{
			bVirusFound = ValidatePERules(pYaraTree->m_pYaraPEList[iCnt]->szRules);
			if (bVirusFound)
			{
				break;
			}
		}
	}


	return bVirusFound;
}

/*
bool CMaxYara::ScanFile(CTreeManager *pYaraTree)
{
	bool	bVirusFound = false;
	
	if(pYaraTree == NULL)
	{
		return bVirusFound;
	}

	if(pYaraTree->m_dwNodeCount <= 0x00)
	{
		return bVirusFound;
	}

	TCHAR	m_szFile2Open[1024] = {0x00};
	TCHAR	szExt2Skip[]={L".acm.ax.cpl.drv.efi.fon.mui.ocx.scr.tsp"};

	GetIMPHashforYARA();
	bVirusFound = CheckStaticYaraRules(pYaraTree);
	if (bVirusFound)
	{
		return bVirusFound;
	}

	_stprintf(m_szFile2Open,L"%s",m_pMaxPEFile->m_szFilePath); 
	TCHAR	*pTemp = NULL;

	pTemp = _tcsrchr(m_szFile2Open,L'.');
	if(pTemp)
	{
		if (_tcslen(pTemp) > 0x00 && _tcslen(pTemp) < MAX_PATH)
		{
			TCHAR	szExt[MAX_PATH] = {0x00};
			_tcscpy(szExt,pTemp);
			_tcslwr(szExt);
			if (_tcsstr(szExt2Skip,szExt) != NULL)
			{
				return bVirusFound;
			}
		}
	}
	
	if (m_pMaxPEFile->m_hFileHandle == NULL)
	{
		return bVirusFound;	
	}


	HANDLE hFileMap = CreateFileMapping(m_pMaxPEFile->m_hFileHandle, NULL, PAGE_READONLY, 0x00, m_pMaxPEFile->m_dwFileSize, NULL);
	if (NULL != hFileMap)
	{
		LPVOID pFileView = NULL;

		pFileView = MapViewOfFile(hFileMap, FILE_MAP_READ, 0x00, 0x00, m_pMaxPEFile->m_dwFileSize);
		if (pFileView != NULL)
		{
			TCHAR	szPERule[2048] = {0x00};
			char	szVirusName[MAX_PATH] = {0x00};
			pYaraTree->ScanBuffer4YARA((unsigned char *)pFileView,m_pMaxPEFile->m_dwFileSize,szVirusName,&szPERule[0x00]);
			if (strlen(szVirusName) != 0x00)
			{
				//_tcscpy(&szPERule[0x00],L"[IMPHASH{f9a5c5a17830b5293a53c6ff9bd9b6b0},SNAME{1=\".text\",2=\".data\"},SRVA{0=1230,1=43210},NSEC{05},FZ{441<}]");
				if (_tcslen(szPERule) > 0x00)
				{
					if (ValidatePERules(szPERule))
					{
						//return true;	
						bVirusFound = true;
					}
				}
				else
				{
					bVirusFound = true;
				}
			}
			UnmapViewOfFile(pFileView);
			pFileView = NULL;
		}
		CloseHandle(hFileMap);
		hFileMap = NULL;
	}
	return bVirusFound;
}
*/

bool CMaxYara::ScanFile(CTreeManager *pYaraTree)
{
	bool	bVirusFound = false;
	
	if(pYaraTree == NULL)
	{
		return bVirusFound;
	}

	if(pYaraTree->m_dwNodeCount <= 0x00)
	{
		return bVirusFound;
	}

	TCHAR	m_szFile2Open[1024] = {0x00};
	TCHAR	szExt2Skip[]={L".acm.ax.cpl.drv.efi.fon.mui.ocx.scr.tsp"};

	_stprintf(m_szFile2Open,L"%s",m_pMaxPEFile->m_szFilePath); 
	TCHAR	*pTemp = NULL;
	bool	bIsDllFile = false;
	pTemp = _tcsrchr(m_szFile2Open,L'.');
	if(pTemp)
	{
		if (_tcslen(pTemp) > 0x00 && _tcslen(pTemp) < MAX_PATH)
		{
			TCHAR	szExt[MAX_PATH] = {0x00};
			_tcscpy(szExt,pTemp);
			_tcslwr(szExt);
			if (_tcsstr(szExt2Skip,szExt) != NULL)
			{
				return bVirusFound;
			}
			if (_tcsstr(L".dll",szExt) != NULL)
			{
				bIsDllFile = true;
			}
		}
	}
	
	if (m_pMaxPEFile->m_hFileHandle == NULL)
	{
		return bVirusFound;
	}

	GetIMPHashforYARA();
	bVirusFound = CheckStaticYaraRules(pYaraTree);
	if (bVirusFound)
	{
		return bVirusFound;
	}

	TCHAR	szPERule[2048] = {0x00};
	char	szVirusName[MAX_PATH] = {0x00};

	if (bIsDllFile && (m_pMaxPEFile->m_dwFileSize > (6 * 1024 * 1024)))
	{
		return bVirusFound;
	}
	
	pYaraTree->ScanBuffer4YARA(m_pMaxPEFile->m_hFileHandle,m_pMaxPEFile->m_dwFileSize,szVirusName,&szPERule[0x00]);
	if (strlen(szVirusName) != 0x00)
	{
		//_tcscpy(&szPERule[0x00],L"[IMPHASH{f9a5c5a17830b5293a53c6ff9bd9b6b0},SNAME{1=\".text\",2=\".data\"},SRVA{0=1230,1=43210},NSEC{05},FZ{441<}]");
		if (_tcslen(szPERule) > 0x00)
		{
			if (ValidatePERules(szPERule))
			{
				//return true;	
				bVirusFound = true;
			}
		}
		else
		{
			bVirusFound = true;
		}
	}

	return bVirusFound;
}