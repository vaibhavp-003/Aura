#include "ASPackUnpack.h"
#include "MaxExceptionFilter.h"

CASPackUnpack::CASPackUnpack(CMaxPEFile *pMaxPEFile):
CUnpackBase(pMaxPEFile)
{
	m_dwOriAEP = m_dwSecStrtAdd = m_wUnPackSecNo = 0;	
	byDecryptFlag=0;
}

CASPackUnpack::~CASPackUnpack(void)
{
	if(m_pbyBuff)
	{
		VirtualFree((void*)m_pbyBuff, 0, MEM_RELEASE);
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CASPackUnpack::IsPacked()
{
	bool bRetStatus = false;	
	//OutputDebugString(L"MAX Inside CASPackUnpack::IsPacked()1.1");
	//AddLogEntry(L"TEST : IsPacked (ASPack) : Inside");
//#ifndef WIN64	
	if (m_pMaxPEFile->m_b64bit == false)
	{
		//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 1");
		if(LOBYTE(LOWORD(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint)) != 0x01)
		{
			//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 1R");
			return bRetStatus;
		}

		//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 2");
		if(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint % 0x10 != 0x01)
		{
			//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 2R");
			return bRetStatus;
		}

		//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 3");
		BYTE byFirstDWORD[8]={0};
		if(!m_pMaxPEFile->ReadBuffer(byFirstDWORD, m_pMaxPEFile->m_dwAEPMapped - 1, 8, 8))
		{
			//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 3R");
			return bRetStatus;
		}

		//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 4");
		if(*(WORD*)&byFirstDWORD[0] != 0x6090 && *(DWORD*)&byFirstDWORD[0] != 0xE8609090 && *(WORD*)&byFirstDWORD != 0x6091)
		{
			//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 4R");
			return bRetStatus;
		}

		//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 5");
		if((byFirstDWORD[2]==0xE9 && *(DWORD*)&byFirstDWORD[3]>0x10) || (byFirstDWORD[7]==0xEB && *(DWORD*)&byFirstDWORD[3]<0x05))
		{
			//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 5R");
			byDecryptFlag=1;
		}
		//OutputDebugString(L"MAX Inside CASPackUnpack::IsPacked() TRUE");
		//AddLogEntry(L"TEST : IsPacked (ASPack) : Level 6");
		return true;
	}
//#endif
	//AddLogEntry(L"TEST : IsPacked (ASPack) : Bye Bye");
	return bRetStatus;
}

bool CASPackUnpack::Emulate()
{		
	bool bRetStatus = false;
	m_dwImportTableRVA = 0x0;
	DWORD dwEIPofImportTbl = 0x0;
	DWORD dwRegEBP		   = 0x0;	
	const int IMPORTTBL_BUFF_SIZE = 0x400;	// import table buffer size

	CEmulate objEmulate(m_pMaxPEFile);
	if(0 == objEmulate.IntializeProcess())
	{
		return bRetStatus;
	}
	char szBreakPoint[1024] = {0};
	
	sprintf_s(szBreakPoint, 1024, "__isinstruction('jnz ')");// && __isinstructionlength() == 0x06)");	
	objEmulate.SetBreakPoint(szBreakPoint);
	DWORD dwEIPtoSet=0;
	char szInstruction[1024] = {0x00};

	if(byDecryptFlag==0x01)
	{
		BYTE *bybuff=new BYTE[0x30+0x30];
		if(!m_pMaxPEFile->ReadBuffer(bybuff,m_pMaxPEFile->m_dwAEPMapped,0x30,0x30))
		{
			return false;
		}
		DWORD dwLength = 0, dwInstructionCountFound = 0, dwOffset=0, dwChk = 0x0;		
		while(dwOffset < 0x30 && dwInstructionCountFound<0x30)
		{
			dwLength = objEmulate.DissassemBuffer((char*)&bybuff[dwOffset],szInstruction);
			if(strstr(szInstruction,"JMP") && dwLength==0x05 && *(DWORD*)&bybuff[1]>0x40)
			{
				dwEIPtoSet = dwOffset + 0x05 + m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint + m_dwImageBase;
				dwEIPofImportTbl = dwEIPtoSet;
				break;
			}
			dwOffset+=dwLength;
			dwInstructionCountFound++;
		}
	}
	
	objEmulate.SetNoOfIteration(30+byDecryptFlag*0x5000);
	dwCount=0;
	bybuffDecrypt=NULL;
	while(1)
	{
        dwCount++;
		if(7 != objEmulate.EmulateFile())
		{
			return bRetStatus;
		}
		DWORD	dwLen = objEmulate.GetInstructionLength();
		if(dwLen == 6 && (byDecryptFlag==0x00 || bybuffDecrypt))
		{
			dwEIPtoSet = objEmulate.GetEip();
			dwRegEBP   = objEmulate.GetSpecifyRegValue(0x5); // For Import Table RVA
			break;
		}
		if(byDecryptFlag==0x01 && objEmulate.CheckZeroFlag())
		{
			objEmulate.SetEip(dwEIPtoSet);
			bybuffDecrypt=new BYTE[dwCount];
			if(!objEmulate.ReadEmulateBuffer(bybuffDecrypt,dwCount,dwEIPtoSet))
			{
				return false;
			}
			if(!m_objTempFile.WriteBuffer(bybuffDecrypt,dwEIPtoSet-m_dwImageBase,dwCount,dwCount))
			{
				return false;
			}
		}
	}

	objEmulate.PauseBreakPoint(0); 
   //do normal emulation for import table -PRASHANT-
	DWORD dwBuffOffset = 0x0,
		  dwLength	   = 0x0,
	      dwBuffSize   = IMPORTTBL_BUFF_SIZE;
	bool bMovEsiFound  = false;
	//------------ImportTable RVA calculation---------------------------
	if(byDecryptFlag == 0x00)
	{
		bybuffDecrypt = new BYTE[IMPORTTBL_BUFF_SIZE];
		if(!m_pMaxPEFile->ReadBuffer(&bybuffDecrypt[0], m_pMaxPEFile->m_dwAEPMapped, IMPORTTBL_BUFF_SIZE, IMPORTTBL_BUFF_SIZE))
			return bRetStatus;
	}
	const BYTE bMovEsiChk[] = {0xAD, 0x0B, 0xC0, 0x74, 0x0A, 0x03, 0xC2, 0x8B, 0xF8, 0x66, 0xAD, 0x66, 0xAB, 0xEB, 0xF1};
	while(dwBuffOffset < IMPORTTBL_BUFF_SIZE)
	{
		if(dwCount <= dwBuffOffset && byDecryptFlag == 0x1)
			break;

		if(memcmp(&bybuffDecrypt[dwBuffOffset], bMovEsiChk, sizeof(bMovEsiChk))== 0 && bMovEsiFound  == false)
		{
			bMovEsiFound = true;
			dwBuffOffset += sizeof(bMovEsiChk);
			continue;
		}
		else if(bMovEsiFound == true)
		{
			dwLength = objEmulate.DissassemBuffer((char*)&bybuffDecrypt[dwBuffOffset],szInstruction);
			if(strstr(szInstruction,"MOV ESI ,"))
			{	
				if(dwLength==0x05)
				{
					m_dwImportTableRVA = *(DWORD*)&bybuffDecrypt[dwBuffOffset + 1];
					break;
				}
				else if(dwLength==0x06 && strstr(szInstruction,"MOV ESI ,DWORD PTR [EBP"))
				{
					m_dwImportTableRVA = *(DWORD*)&bybuffDecrypt[dwBuffOffset + 2] + dwRegEBP - m_dwImageBase;
					
					if(byDecryptFlag == 0x0)				// Normal File
					{	
						if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_dwImportTableRVA, &m_dwImportTableRVA))
							return bRetStatus;
						
						if(!m_pMaxPEFile->ReadBuffer(&m_dwImportTableRVA, m_dwImportTableRVA, sizeof(DWORD), sizeof(DWORD)))
							return bRetStatus;
					}
					else									// File With Decryption
					{
						if(OUT_OF_FILE == m_objTempFile.Rva2FileOffset(m_dwImportTableRVA, &m_dwImportTableRVA))
							return bRetStatus;

						if(!m_objTempFile.ReadBuffer(&m_dwImportTableRVA, m_dwImportTableRVA, sizeof(DWORD), sizeof(DWORD)))
							return bRetStatus;
					}
					break;
				}
			}	
		}
		dwBuffOffset++;
	}

	//------------End of ImportTable RVA calculation---------------------------
	//objEmulate.PauseBreakPoint(0); 
	objEmulate.ModifiedZeroFlag(false);
	
	DWORD dwEip = objEmulate.GetEip() + 6;
	objEmulate.SetNoOfIteration(2);
	if(0 != objEmulate.EmulateFile())
	{
		return bRetStatus;
	}
	m_dwOriAEP =  objEmulate.GetSpecifyRegValue(0);

	objEmulate.SetEip(dwEip);
	objEmulate.SetNoOfIteration(300);
	
	sprintf_s(szBreakPoint, 1024, "__isinstruction('lea esi ,dword ptr [ebp + ')");// && __isinstructionlength() == 0x06)");
	objEmulate.SetBreakPoint(szBreakPoint);
	
	while(1)
	{
		if(7 != objEmulate.EmulateFile())
		{
			return bRetStatus;
		}
		DWORD	dwLen = objEmulate.GetInstructionLength();
		if(dwLen == 6)
		{
			break;
		}
	}
	
	m_dwSecStrtAdd = objEmulate.GetMemoryOprand();
	m_dwSecStrtAdd -= (m_pMaxPEFile->m_stPEHeader.ImageBase + m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint);
	m_dwResolveCallAdd = objEmulate.GetEip();
	m_dwResolveCallAdd -= (m_pMaxPEFile->m_stPEHeader.ImageBase + m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint);

	if(m_dwSecStrtAdd > 4000)
	{
		return bRetStatus;
	}

	if(OUT_OF_FILE != m_pMaxPEFile->Rva2FileOffset(m_dwOriAEP, NULL))
	{
		return true;
	}
	return bRetStatus;
}

bool CASPackUnpack::Unpack(LPCTSTR szTempFileName)
{

	WaitForSingleObject(CUnpackBase::m_hEvent, INFINITE);
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	bool bRetStatus = Emulate();
	SetEvent(CUnpackBase::m_hEvent);

	if(!bRetStatus)
	{
		return false;
	}
	
	/*if(byDecryptFlag==0x01)
	{
		bybuff[0]=0xE8;
		*(DWORD*)&bybuff[1]=0x00;
		if(!m_objTempFile.WriteBuffer(bybuff,m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x01,dwCountDecrypt,dwCountDecrypt))
		{
			return false;
		}
		return true;
	}*/
	CMaxPEFile *ctempFile=m_pMaxPEFile;

	bRetStatus = false;
	if(byDecryptFlag==0x01)
	{
		m_pMaxPEFile=&m_objTempFile;
	}

	if(!m_pMaxPEFile->ReadBuffer(m_byAspackCode, m_pMaxPEFile->m_dwAEPMapped, 4096, 2000))
	{
		m_pMaxPEFile=ctempFile;
		return bRetStatus;
	}

	m_pMaxPEFile=ctempFile;

	bool bNewVersion = false;
	
	m_pstructNewSecRcrd = (SECTION_RECORD_NEW*)&m_byAspackCode[m_dwSecStrtAdd];
	if(m_pstructNewSecRcrd == NULL)
	{
		return bRetStatus;
	}

	if(OUT_OF_FILE == m_pMaxPEFile->Rva2FileOffset(m_pstructNewSecRcrd[0].dwAttributes, NULL))
	{
		bNewVersion = true;
	}
	else
	{
		m_pstructSecRcrd = (SECTION_RECORD*)&m_byAspackCode[m_dwSecStrtAdd];
		if(m_pstructSecRcrd == NULL )
		{
			return bRetStatus;
		}
	}

	unsigned int address	= 0;
	unsigned int size		= 0;
	unsigned int worksize	= 0;
	bool bflag = true;

	for(int i = 0;i < MAX_SECTIONS; i++)
	{
		if(bNewVersion == true)
		{
			address		= m_pstructNewSecRcrd[i].dwRVA;
			size		= m_pstructNewSecRcrd[i].dwSize;
			worksize	= size + 0x10E;
		}
		else
		{
			address	= m_pstructSecRcrd[i].dwRVA;
			size		= m_pstructSecRcrd[i].dwSize;
			worksize	= size + 0x10E;
		}

		if(address == 0)
		{
			bRetStatus = true;
			break;
		}

		if(worksize == 0)
		{
			continue;
		}

		DWORD  dwInputSize = 0;

		unsigned char *input  = PeLoadSection(address, &dwInputSize);
		unsigned char *output = (unsigned char*)VirtualAlloc(NULL, worksize + 4, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if(output == NULL)
		{
			break;
		}
		if(input == NULL)
		{
			VirtualFree((void*)output, 0, MEM_RELEASE);
			output = NULL;
			continue;
		}

		memset(output, 0, worksize+4);

		if(DecompressData(input, output, dwInputSize, size) != 0xFFFFFFFF)
		{
		
			if(size <= SA(m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].Misc.VirtualSize))
			{
				if(bflag)
				{
					if(!ResolveE8E9Calls(output,size))
					{
						VirtualFree((void*)output, 0, MEM_RELEASE);
						output = NULL;
						return bRetStatus;
					}
					bflag = false;
				}
				if(size > dwInputSize)
				{
					return false;
				}
				memcpy(input, output, size);
			}
			m_objTempFile.WriteBuffer(m_pbyBuff, m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].VirtualAddress, SA(m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].Misc.VirtualSize));
		}

		VirtualFree((void*)output, 0, MEM_RELEASE);
		output = NULL;
	}

	if(m_dwImportTableRVA != 0 && m_dwImportTableRVA < (m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1].VirtualAddress + m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1].Misc.VirtualSize))// Resolve calls to do.....
	{
		//if(!m_objTempFile.WriteBuffer((DWORD*)&m_byAspackCode[m_dwResolveCallAdd+0x12B], m_objTempFile.m_stPEHeader.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+0x68,0x04,0x04))
		if(!m_objTempFile.WriteBuffer(&m_dwImportTableRVA, m_objTempFile.m_stPEHeader.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+0x68,0x04,0x04))
		{
			return bRetStatus;
		}
	}

	m_objTempFile.WriteAEP(m_dwOriAEP);

	return bRetStatus;
}

int CASPackUnpack::DecompressData(void *input, void *output, unsigned int inputsize, unsigned int outputsize)
{
	// return negative value on error, unpacked size on success
	int iRetVal = -1;
	unsigned char *temp = new unsigned char [0x1800];
	if(!temp)
	{
		return iRetVal;
	}	
	__try
	{
		if (input == NULL || output == NULL || inputsize == 0x00 || outputsize == 0x00)
		{
			return iRetVal;
		}
		iRetVal = Decompress(input, output, outputsize, temp, inputsize);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(), _T("Exception caught in ASPack Unpacking"), m_pMaxPEFile->m_szFilePath, false))
	{		
	}
	delete [] temp;
	return iRetVal;	
}

BYTE* CASPackUnpack::PeLoadSection(DWORD dwRVA, DWORD *size/* = 0*/)
{
	if(m_pbyBuff && SA(dwRVA >= m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].VirtualAddress) &&
		dwRVA < (SA(m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].VirtualAddress +
		m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].Misc.VirtualSize)))
	{
		// already loaded
	}
	else
	{
		if(m_pbyBuff)
		{
			VirtualFree((void*)m_pbyBuff, 0, MEM_RELEASE);
			m_pbyBuff = NULL;
		}

		WORD wSecNo = m_pMaxPEFile->Rva2FileOffset(dwRVA, NULL);
		if(0xFFFF != wSecNo)
		{
			unsigned int virtsize = SA(m_pMaxPEFile->m_stSectionHeader[wSecNo].Misc.VirtualSize);
			unsigned int physsize = FA(m_pMaxPEFile->m_stSectionHeader[wSecNo].SizeOfRawData);
			unsigned int offset = m_pMaxPEFile->m_stSectionHeader[wSecNo].PointerToRawData;
			if(m_pMaxPEFile->m_stSectionHeader[wSecNo].PointerToRawData%m_pMaxPEFile->m_stPEHeader.FileAlignment !=0x00)
			{
				offset-=(m_pMaxPEFile->m_stSectionHeader[wSecNo].PointerToRawData%m_pMaxPEFile->m_stPEHeader.FileAlignment);
			}
			
			m_dwSize = virtsize;
			if(virtsize < physsize)
			{
				m_dwSize = physsize;
			}
			m_pbyBuff = (BYTE*)VirtualAlloc(NULL, m_dwSize + 16, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(m_pbyBuff == NULL)
			{
				return 0;
			}
			memset(m_pbyBuff, 0, m_dwSize+16);
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff, offset, physsize))
			{
				VirtualFree((void*)m_pbyBuff, 0, MEM_RELEASE);
				m_pbyBuff = 0;
			}
			m_wUnPackSecNo = wSecNo;
		}
	}

	if(size)
	{
		if(m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].Misc.VirtualSize!=0x00)
		{
		*size = m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].Misc.VirtualSize - 
			(dwRVA - m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].VirtualAddress);
		}
		else
		{
			WORD wSecNo=0xFF;
			DWORD dwtempFileOffset=0;
			if(!(~(wSecNo=m_pMaxPEFile->Rva2FileOffset(dwRVA,&dwtempFileOffset))))
			{
				return 0;
			}
			*size = m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].SizeOfRawData - 
				(dwtempFileOffset - m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].PointerToRawData);
		}

	}

	return m_pbyBuff + dwRVA - m_pMaxPEFile->m_stSectionHeader[m_wUnPackSecNo].VirtualAddress;
}


//Separate Function
bool CASPackUnpack::ResolveE8E9Calls(BYTE *byBuff, DWORD dwSize)
{
	bool bflag=false;
	if(m_dwResolveCallAdd+0xC0 < 2000)
	{
        m_dwResolveCallAdd+=0x0F; 
        if(*(WORD*)&m_byAspackCode[m_dwResolveCallAdd]==0xB58D)
		{
			m_dwResolveCallAdd+=0x06;
		}
		m_dwResolveCallAdd+=0x0E;
		if(*(WORD*)&m_byAspackCode[m_dwResolveCallAdd]==0x95FF)
		{
			bflag=true;
            m_dwResolveCallAdd+=0x03;
		}
        m_dwResolveCallAdd+=0x11;
		if(*(WORD*)&m_byAspackCode[m_dwResolveCallAdd]==0x840F)
		{
			m_dwResolveCallAdd+=0x06;
		}
		m_dwResolveCallAdd+=0x0A;
		if(bflag)
		{
			m_dwResolveCallAdd+=0x03;
		}
		m_dwResolveCallAdd+=0x22;
        if(*(WORD*)&m_byAspackCode[m_dwResolveCallAdd]==0xBD80)
		{
			m_dwResolveCallAdd+=0x02;
		}
		m_dwResolveCallAdd+=0x0D;
        if(*(WORD*)&m_byAspackCode[m_dwResolveCallAdd]==0x3E8B)
		{
			m_dwResolveCallAdd+=0x11;
		}
		m_dwResolveCallAdd+=0x29;
		
		bool bDirectSub=false;
		if(m_byAspackCode[m_dwResolveCallAdd]!=0x00)
		{ 
			bDirectSub=true;
		}
		m_dwResolveCallAdd+=0x03;

		BYTE bytemp=m_byAspackCode[m_dwResolveCallAdd];
		if(bflag)
		{
			m_dwResolveCallAdd+=0x06;
		}
		
		for(DWORD dwCounter = 0; dwSize > 6 && dwCounter < (dwSize - 6); dwCounter++)
		{
			if(byBuff[dwCounter] == 0xE8 || byBuff[dwCounter] == 0xE9)
			{
				if(byBuff[dwCounter+1]==bytemp && !bDirectSub)
				{ 
					*(DWORD*)&byBuff[dwCounter+0x01]=((*(DWORD*)&byBuff[dwCounter+0x01]&0xFFFFFF00)<<24)|((*(DWORD*)&byBuff[dwCounter+0x01]&0xFFFFFF00)>>8)-dwCounter;
					dwCounter+=0x04;
				}
				else if(bDirectSub)
				{
					*(DWORD*)&byBuff[dwCounter+0x01]-=dwCounter;
					dwCounter+=0x04;
				}
			}
		}
	}	
	return true;
}

