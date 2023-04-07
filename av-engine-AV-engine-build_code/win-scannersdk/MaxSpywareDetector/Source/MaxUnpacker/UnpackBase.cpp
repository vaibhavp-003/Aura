#include "UnpackBase.h"
#include "Packers.h"
#include "Alloc.h"
#include "7zFile.h"
#include "7zVersion.h"
#include "LzmaDec.h"
#include "MaxExceptionFilter.h"
#include "depacks.h"

#define IN_BUF_SIZE (1 << 16)
#define OUT_BUF_SIZE (1 << 16)

static void *SzAlloc(void *p, size_t size) { p = p; return MyAlloc(size); }
static void SzFree(void *p, void *address) { p = p; MyFree(address); }
static ISzAlloc g_Alloc = { SzAlloc, SzFree };

PEBUNDLE_DLL CUnpackBase::m_PEBundle[NO_OF_DLL] = {NULL};
PEC2_DECODER_EXTRA CUnpackBase::m_DecoderExtra = {0};
int CUnpackBase::m_iDataCnt = 0;
HANDLE CUnpackBase::m_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);

CUnpackBase::CUnpackBase(CMaxPEFile *pMaxPEFile, int iCurrentLevel):
m_pMaxPEFile(pMaxPEFile),
m_iCurrentLevel(iCurrentLevel),
m_pbyBuff(NULL)
{
	m_dwImageBase = m_pMaxPEFile->m_stPEHeader.ImageBase;
}

CUnpackBase::~CUnpackBase(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CUnpackBase::ReOrganizeFile(LPCTSTR szTempFileName,bool bOnlyfile /*= true*/, bool bOnlyOverlay /*= true*/,int iType)
{
	static DWORD dwPRDLargestSection=0x00,dwSRDLargestSection=0x00;
	if(bOnlyfile)
	{
		if(!CopyFile(m_pMaxPEFile->m_szFilePath, szTempFileName, false))
		{
			return false;
		}

		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			return false;
		}
		dwPRDLargestSection=0x00;
		dwSRDLargestSection=0x00;
		
		
		DWORD dwImageSectionHeaderCavityOffset=m_objTempFile.m_stPEOffsets.Magic+m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader+m_pMaxPEFile->m_stPEHeader.NumberOfSections*0x28;
		DWORD dwImageSectionHeaderCavitySize=m_pMaxPEFile->m_stPEHeader.SizeOfHeaders+((bOnlyfile && !bOnlyOverlay)*0x28)-dwImageSectionHeaderCavityOffset;
		if(dwImageSectionHeaderCavitySize!=0x00 && dwImageSectionHeaderCavitySize<(m_pMaxPEFile->m_stSectionHeader[0].VirtualAddress-dwImageSectionHeaderCavityOffset)&&
			bOnlyfile==true && bOnlyOverlay==false)
		{
			CUnpackBase::m_iDataCnt++;
			BYTE *byCavitybuff=NULL;

			byCavitybuff = (BYTE*)VirtualAlloc(NULL, dwImageSectionHeaderCavitySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(byCavitybuff == NULL)
			{
				return false;
			}
			memset(byCavitybuff, 0, dwImageSectionHeaderCavitySize);
			m_pMaxPEFile->ReadBuffer(byCavitybuff, dwImageSectionHeaderCavityOffset, dwImageSectionHeaderCavitySize);
			m_objTempFile.WriteBuffer(byCavitybuff, dwImageSectionHeaderCavityOffset+0x28, dwImageSectionHeaderCavitySize);
			VirtualFree((void*)byCavitybuff, 0, MEM_RELEASE);
			byCavitybuff = NULL;	
		}
		
		/*bool bChangeSectionAlignment=false;
		if(dwImageSectionHeaderCavityOffset+0x28+dwImageSectionHeaderCavitySize>m_objTempFile.m_stPEHeader.SectionAlignment)
		{
			bChangeSectionAlignment=true;
		}*/


		BYTE	*byBuffer = NULL;
		DWORD	dwReadOffset = 0, dwAllocationSize = 0, dwReadSize = 0, dwWriteOffset = 0, dwCharacteristics = 0;

		for(WORD i = 0; i < m_pMaxPEFile->m_stPEHeader.NumberOfSections; i++)
		{
			dwReadOffset = m_pMaxPEFile->m_stSectionHeader[i].PointerToRawData;			
			
			if((dwReadOffset%0x200)!=0x00)
			{
			dwReadOffset=FANotDefault(dwReadOffset,0x200)-0x200;
			}

			dwReadSize = m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData;
			if(i==0x00 && iType==0x01)
			{
				dwReadOffset=0x00;
				dwReadSize=0x400;
			}
			if(dwReadOffset > dwPRDLargestSection )
			{
				dwPRDLargestSection=dwReadOffset;
				dwSRDLargestSection=m_pMaxPEFile->m_stSectionHeader[i].SizeOfRawData;
			}
			
			dwAllocationSize	= SA(m_pMaxPEFile->m_stSectionHeader[i].Misc.VirtualSize);
			dwWriteOffset		= m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress;
			dwCharacteristics	= m_pMaxPEFile->m_stSectionHeader[i].Characteristics;

			if(dwAllocationSize < dwReadSize && 
				(i < m_pMaxPEFile->m_stPEHeader.NumberOfSections - 1) && 
				SA(dwReadSize) + m_pMaxPEFile->m_stSectionHeader[i].VirtualAddress <= m_pMaxPEFile->m_stSectionHeader[i+1].VirtualAddress)
			{
				dwAllocationSize = SA(dwReadSize);
			}
			if(dwAllocationSize != 0)
			{
				byBuffer = (BYTE*)VirtualAlloc(NULL, dwAllocationSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if(byBuffer == NULL)
				{
					return false;
				}
				memset(byBuffer, 0, dwAllocationSize);
				m_pMaxPEFile->ReadBuffer(byBuffer, dwReadOffset, dwReadSize);
				//m_objTempFile.WriteBuffer(byBuffer, dwWriteOffset+(bChangeSectionAlignment*m_pMaxPEFile->m_stPEHeader.SectionAlignment), dwAllocationSize);
				m_objTempFile.WriteBuffer(byBuffer, dwWriteOffset, dwAllocationSize);
				VirtualFree((void*)byBuffer, 0, MEM_RELEASE);
				byBuffer = NULL;			
			}
			m_objTempFile.WriteSectionCharacteristic(i, dwAllocationSize, 8);
			m_objTempFile.WriteSectionCharacteristic(i, dwAllocationSize, 16);
			m_objTempFile.WriteSectionCharacteristic(i, dwWriteOffset, 20);		
			m_objTempFile.WriteSectionCharacteristic(i, dwCharacteristics | 0x80000000,36);

			if(i==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1)
			{
				if(!m_objTempFile.ForceTruncate(dwWriteOffset+dwAllocationSize))
				{
					return false;
				}
			}
		}

	}

	if(bOnlyfile && bOnlyOverlay)
	{
		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			return false;
		}
	}

	if(bOnlyOverlay)
	{
		//To handle the overlay
		DWORD dwOverlaySize=m_pMaxPEFile->m_dwFileSize-(dwPRDLargestSection + dwSRDLargestSection);
		if(m_pMaxPEFile->m_dwFileSize > dwPRDLargestSection + dwSRDLargestSection)
		{
			BYTE	*byBuffer = (BYTE*)VirtualAlloc(NULL, dwOverlaySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if(byBuffer == NULL)
			{
				return false;
			}
			memset(byBuffer, 0, dwOverlaySize);
			m_pMaxPEFile->ReadBuffer(byBuffer, dwPRDLargestSection + dwSRDLargestSection, dwOverlaySize);
			m_objTempFile.WriteBuffer(byBuffer,m_objTempFile.m_dwFileSize ,dwOverlaySize);
			VirtualFree((void*)byBuffer, 0, MEM_RELEASE);
			byBuffer = NULL;	
		}
	}

	m_objTempFile.CloseFile();
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}
	return true;
}

bool CUnpackBase::AddNewSection(DWORD dwImportSize /* = 0*/,WORD wDecrementSections /* = 0*/)
{
	DWORD dwSectionStart = m_objTempFile.m_stPEHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 
		m_objTempFile.m_stPEHeader.SizeOfOptionalHeader + ((m_objTempFile.m_stPEHeader.NumberOfSections-wDecrementSections) * 0x28);

	BYTE bySection[0x28] = {0};
	memcpy(bySection, (void *)".idata2", 0x08); //Section Name

	//Initially keeping the sizes of VS and SRD = 1	
	*(DWORD *)&bySection[0x08] = 0x01;							// VS
	*(DWORD *)&bySection[0x10] = 0x01;							// SRD
	*(DWORD *)&bySection[0x0C] = (m_objTempFile.m_dwFileSize);	//RVA
	*(DWORD *)&bySection[0x14] = (m_objTempFile.m_dwFileSize);	//PRD
	*(DWORD *)&bySection[0x18] = 0;								//Pointer to reloc
	*(DWORD *)&bySection[0x1C] = 0;								//Pointer to line number
	*(DWORD *)&bySection[0x20] = 0;								//No. of Reloc and No. of Line numbers
	*(DWORD *)&bySection[0x24] = 0xC0000040;					//Pointer to line number

	if(dwImportSize)
	{
		*(DWORD *)&bySection[0x08] = dwImportSize;							// VS
		*(DWORD *)&bySection[0x10] = dwImportSize;
	}

	if(m_objTempFile.WriteBuffer(bySection, dwSectionStart, 0x28, 0x28))
	{
		return true;
	}
	return false;
}

DWORD CUnpackBase::LZMADecompress(BYTE byLZMAProp[], DWORD dwSrcSize, DWORD dwDestSize, DWORD dwRead, DWORD dwWrite, BYTE * byBuff /*= NULL*/,BYTE *byReadSrcbuff/*= NULL*/,BYTE byPackerSpecial,bool bCheckDestSize)
{
	DWORD dwRet = 0;
	if(dwSrcSize > 10 * 1024 * 1024 || dwDestSize > 10 * 1024 * 1024 )
	{
		return dwRet;
	}

	if (sizeof(UInt32) != 4 || sizeof(UInt64) != 8)
	{
		return dwRet;
	}

	/* header: 5 bytes of LZMA properties and 8 bytes of uncompressed size */
	unsigned char header[4 + LZMA_PROPS_SIZE + 8] = {0};
	byLZMAProp[0] = (byLZMAProp[2] * 5 + byLZMAProp[1]) * 9 + byLZMAProp[0];	
	memcpy(header, &dwSrcSize, 0x04);
	memcpy(header + 4, &byLZMAProp[0], 0x01);
	memcpy(header + 5, &dwDestSize, 0x04);
	//This is actually 8 bytes wrt 64 bit but for now read only 4 bytes and remaining are 0
	memcpy(header+9,&dwDestSize,0x04);

	//Reads the unpack size which is 64bit
	UInt64 unpackSize = 0;
	for (int i = 0; i < 8; i++)
	{
		unpackSize += (UInt64)header[4 + LZMA_PROPS_SIZE + i] << (i * 8);
	}

	CLzmaDec state;
	LzmaDec_Construct(&state);
	if(LzmaDec_Allocate(&state, header + 0x04, LZMA_PROPS_SIZE, &g_Alloc) != SZ_OK)
	{
		return dwRet;
	}
	LzmaDec_Init(&state);

	int thereIsSize = (unpackSize != (UInt64)(Int64)-1);

	BYTE *bySrcbuff = NULL, *byDestbuff = NULL;
	size_t inPos = 0, inSize = 0, outPos = 0;
	int Loop_Length = (*(DWORD *)&header[0] / IN_BUF_SIZE) + 1, NoRepeat = 1, Counter = 0;
	SizeT inProcessed, outProcessed;
	SRes res = 0;
	DWORD dwOffsetToWrite = 0;

	while(1)
	{
		if(Counter == Loop_Length && outProcessed != 0x10000)
		{
			break;
		}
		if (inPos == inSize)
		{
			inSize = IN_BUF_SIZE;
			if(Counter == Loop_Length)
			{
				break;
			}
			else if(Counter == Loop_Length - 1)
			{
				inSize = *(DWORD *)&header[0] % IN_BUF_SIZE;
				if(dwRead!=0x00)
				{
					if(bySrcbuff)
					{
						free(bySrcbuff);
					}
				}
				bySrcbuff = NULL;
				if(dwRead!=0x00)
				{
					if(!(bySrcbuff = (BYTE *)MaxMalloc(inSize)))
					{
						break;
					}
					memset(bySrcbuff, 0x00, inSize);
				}
			}
			else if(Counter == 0)
			{
				if(dwRead!=0x00)
				{
					if(!(bySrcbuff = (BYTE *)MaxMalloc(inSize)))
					{
						break;
					}
					memset(bySrcbuff, 0x00, inSize);
				}
			}
			if(dwRead!=0x00)
			{
				if(!m_pMaxPEFile->ReadBuffer(bySrcbuff, dwRead + (IN_BUF_SIZE * Counter), inSize, inSize))
				{				
					break;
				}
			}
			else
			{
				bySrcbuff=&byReadSrcbuff[(IN_BUF_SIZE * Counter)];
			}
			Counter++;
			inPos = 0;
		}

		inProcessed = inSize - inPos;
		outProcessed = OUT_BUF_SIZE - outPos;
		ELzmaFinishMode finishMode = LZMA_FINISH_ANY;
		ELzmaStatus status;
		if(thereIsSize && outProcessed > unpackSize)
		{
			if(byDestbuff)
			{
				free(byDestbuff);
				byDestbuff = NULL;
			}			
			if(!(byDestbuff = (BYTE *)MaxMalloc(unpackSize % OUT_BUF_SIZE)))
			{
				break;
			}	
			memset(byDestbuff, 0x00, unpackSize % OUT_BUF_SIZE);
			outProcessed = (SizeT)unpackSize;
			finishMode = LZMA_FINISH_END;
		}
		else if(thereIsSize && Counter == 0x01 && NoRepeat)
		{
			NoRepeat = 0;
			if(!(byDestbuff = (BYTE *)MaxMalloc(outProcessed)))
			{
				break;
			}	
			memset(byDestbuff, 0x00, OUT_BUF_SIZE);
		}
		res = LzmaDec_DecodeToBuf(&state, byDestbuff + outPos, &outProcessed, bySrcbuff + inPos, &inProcessed, finishMode, &status,byPackerSpecial);

		inPos += inProcessed;
		outPos += outProcessed;
		unpackSize -= outProcessed;

		if((dwOffsetToWrite + outPos) > dwDestSize && bCheckDestSize)
		{
			break;
		}
		if(byBuff)
		{
			memcpy(&byBuff[dwOffsetToWrite], byDestbuff, outPos);
		}
		else
		{
			if(!m_objTempFile.WriteBuffer(byDestbuff, dwWrite + dwOffsetToWrite, outPos, outPos))
			{
				break;
			}
		}
		dwOffsetToWrite += outPos;
		outPos = 0;
		dwRet = dwOffsetToWrite;

		if(bCheckDestSize==false)
		{
			if(!(state.dic=(BYTE*)realloc(state.dic,state.dicBufSize+(1<<16))))
			{
				dwRet=0;
				break;
			}
			state.dicBufSize+=(1<<16);
			state.checkDicSize=state.dicBufSize;
			state.prop.dicSize=state.dicBufSize;
		 unpackSize=(1<<16)*2;
		}

		if (res != SZ_OK || thereIsSize && unpackSize == 0)
		{
			break;
		}

		if (inProcessed == 0 && outProcessed == 0)
		{
			break;
		}
	}

	if(dwRead!=0x00)
	{
		if(bySrcbuff)
		{

			free(bySrcbuff);
		}
	}
	
	bySrcbuff = NULL;
	
	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff = NULL;
	}
	LzmaDec_Free(&state, &g_Alloc);	
	return dwRet;
}

bool CUnpackBase::LoadDLLs(int i)
{
	if(!m_DecoderExtra.dwGetProcAddress)
	{
		HMODULE	hKernel32 = GetModuleHandle(L"kernel32.dll");
		m_DecoderExtra.dwGetProcAddress = (DWORD) GetProcAddress(hKernel32, "GetProcAddress");
		m_DecoderExtra.dwLoadLibraryA   = (DWORD) GetProcAddress(hKernel32, "LoadLibraryA");
		m_DecoderExtra.dwVitualAlloc    = (DWORD) GetProcAddress(hKernel32, "VirtualAlloc");
		m_DecoderExtra.dwVirtualFree    = (DWORD) GetProcAddress(hKernel32, "VirtualFree");
	}

	if(m_PEBundle[i].hUnpacker && m_PEBundle[i].lpfnDecodeSmall)
	{
		return true;
	}
	TCHAR szDLLNames[][40]={
		_T("pec2codec_lzma2.dll"),
		_T("PEC2CODEC_JCALG1.dll")
	};

	m_PEBundle[i].hUnpacker = LoadLibrary(szDLLNames[i]);
	if(m_PEBundle[i].hUnpacker)
	{
		PFNCodecGetProcAddress lpfnCodecGetProcAddress = (PFNCodecGetProcAddress) GetProcAddress(m_PEBundle[i].hUnpacker, "CodecGetProcAddress");
		if(lpfnCodecGetProcAddress  != NULL)
		{
			m_PEBundle[i].lpfnDecodeSmall = (PFNDecodeSmall)lpfnCodecGetProcAddress(0, "DecodeSmall");
			if(m_PEBundle[i].lpfnDecodeSmall)
			{
				return true;
			}
		}
	}
	return false;
}

DWORD CUnpackBase::APLIBDecompress(DWORD dwSrcSize, DWORD dwDestSize, DWORD dwRead, DWORD dwWrite, BYTE *byDestbuff /*= NULL*/, int iCType /*= 0x00*/, BYTE *bybuff /*= NULL*/, DWORD *dwActualSrcSize /*= NULL*/)
{
	DWORD dwOut = 0;
	BYTE *bySrcbuff = NULL;
	if(dwRead!=0x00)
	{
		if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSrcSize)))
		{
			return dwOut;
		}
		memset(bySrcbuff, 0x00, dwSrcSize);
		if(!m_pMaxPEFile->ReadBuffer(bySrcbuff, dwRead, dwSrcSize, dwSrcSize))
		{
			if(bySrcbuff)
			{
				free(bySrcbuff);
				bySrcbuff = NULL;
			}
			return 0;
		}
	}
	else
	{
		bySrcbuff=bybuff;
	}

	bool bWriteToFile = false;
	if(byDestbuff == NULL)
	{
		bWriteToFile = true;
		if(!(byDestbuff = (BYTE *)MaxMalloc(dwDestSize)))
		{
			free(bySrcbuff);
			bySrcbuff = NULL;
			return dwOut;
		}
		memset(byDestbuff, 0x00, dwDestSize);
	}
	__try
	{
		dwOut = aP_depack_safe(bySrcbuff, dwSrcSize, byDestbuff, dwDestSize, iCType, (unsigned int *)dwActualSrcSize);
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception caught in RLPack_APLIB Unpacking"), m_pMaxPEFile->m_szFilePath, false))
	{
	}

	if(dwOut!=0xFFFFFFFF)
	{
		if(dwOut > dwDestSize)
		{
			dwOut = dwDestSize;
		}
		if(dwOut != 0x00 && bWriteToFile) 
		{	
			if(!m_objTempFile.WriteBuffer(byDestbuff, dwWrite, dwOut, dwOut))
			{
				dwOut = 0;
			}
		}
	}
	if(dwRead!=0x00)
	{
		free(bySrcbuff);
		bySrcbuff = NULL;
	}
	if(bWriteToFile && byDestbuff)
	{
		free(byDestbuff);
		byDestbuff = NULL;	
	}

	return dwOut;
}


DWORD CUnpackBase::NeoliteUncompress(DWORD dwSrcSize,DWORD *dwDestSize,DWORD dwRead,DWORD dwWrite,CMaxPEFile *pMaxPeFile,DWORD *dwIncrement,BYTE *bySrcbuff /*==NULL*/,BYTE *byBuff /*==NULL*/)
{
	bool bGreater=0;
	DWORD dwSrcCounter=0x00;
	DWORD dwStackLocal2=0;
	DWORD dwStackLocal1=8;
	DWORD dwStackLocal3=0;
	DWORD dwStackLocal6=0;
	DWORD dwEDX=IMAGE_ORDINAL_FLAG32;
	DWORD dwEBX=0;
	DWORD dwECX=0;
	DWORD dwEBP=0;
	DWORD dwEAX=0;
	DWORD dwDestCounter=0;

	for(;dwDestCounter<*dwDestSize;)
	{
		if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
		{
			dwECX=dwStackLocal2;
			dwEAX=0;
			while(dwECX!=0x00)
			{
				if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
				{
					dwEAX+=dwEAX+1;
				}
				else
				{
					if(bGreater)
					{
						return dwDestCounter;
					}
					dwEAX+=dwEAX;
				}
				dwECX--;
			}
			dwEAX=(dwEAX&0xFFFFFF00)|(BYTE(dwEAX)+BYTE(dwStackLocal3));
			if(dwDestCounter+1>*dwDestSize)
			{
				return dwDestCounter;
			}
			byBuff[dwDestCounter]=BYTE(dwEAX);
			dwDestCounter++;
		}
		else
		{
			if(bGreater)
			{
				return dwDestCounter;
			}

			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				dwECX=0x01;
				while(1)
				{
					if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
					{
						dwECX+=dwECX+1;
					}
					else
					{
						if(bGreater)
						{
							return dwDestCounter;
						}
						dwECX+=dwECX;
					}

					if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
					{
						if(bGreater)
						{
							return dwDestCounter;
						}
						dwECX-=0x02;
						if(dwECX==0x00)
						{
							dwEAX=dwEBX;
							dwECX=0x01;
							while(1)
							{
								if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
								{
									dwECX+=dwECX+1;
								}
								else
								{
									if(bGreater)
									{
										return dwDestCounter;
									}
									dwECX+=dwECX;
								}
								if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
								{
									if(bGreater)
									{
										return dwDestCounter;
									}
									break;
								}

							}
							if(dwDestCounter< dwEAX  || dwDestCounter+dwECX>*dwDestSize) //False Cases
							{
								return dwDestCounter;
							}
							for(DWORD i=0;i<dwECX;i++)
							{
								byBuff[dwDestCounter+i]=byBuff[dwDestCounter-dwEAX+i];
							}
							dwDestCounter+=dwECX;
							break;

						}
						else
						{
							dwECX-=0x01;
							dwEAX=dwECX;
							dwECX=dwStackLocal1;
							dwEBP=dwEAX;
							dwEAX=0x00;
							dwEBP<<=BYTE(dwECX);
							while(dwECX!=0x00)
							{
								if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
								{
									dwEAX+=dwEAX+1;
								}
								else
								{
									if(bGreater)
									{
										return dwDestCounter;
									}
									dwEAX+=dwEAX;
								}
								dwECX--;
							}
							dwEAX|=dwEBP;
							dwEBX=dwEAX;
							dwECX=0x01;

							while(1)
							{
								if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
								{
									dwECX+=dwECX+1;
								}
								else
								{
									if(bGreater)
									{
										return dwDestCounter;
									}
									dwECX+=dwECX;
								}
								if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
								{
									if(bGreater)
									{
										return dwDestCounter;
									}
									break;

								}
							}

							if(dwEAX>=0x27F)
							{
								dwECX+=0x01;
							}
							if(dwEAX>=0x37FF)
							{
								dwECX+=0x01;
							}
							if(dwEAX>=0x10000)
							{
								dwECX+=0x01;
							}
							if(dwEAX<=0x7F && dwEAX>=0x00)
							{
								dwECX+=4;
							}

							if(dwDestCounter< dwEAX  || dwDestCounter+dwECX>*dwDestSize) //False Cases
							{
								return dwDestCounter;
							}
							for(DWORD i=0;i<dwECX;i++)
							{
								byBuff[dwDestCounter+i]=byBuff[dwDestCounter-dwEAX+i];
							}
							dwDestCounter+=dwECX;
							break;
						}

					}
				}//Terminating while
			}
			else
			{
				if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
				{
					dwECX=0x04;
					dwEAX=0x00;
					while(dwECX!=0x00)
					{
						if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
						{
							dwEAX+=dwEAX+1;
						}
						else
						{
							if(bGreater)
							{
								return dwDestCounter;
							}
							dwEAX+=dwEAX;
						}
						dwECX--;
					}



					dwEAX-=0x01;
					if(dwEAX==0x00)
					{
						if(dwDestCounter+1>*dwDestSize)
						{
							return dwDestCounter;
						}
						byBuff[dwDestCounter]=BYTE(dwEAX);
						dwDestCounter++;

					}
					else if((dwEAX&IMAGE_ORDINAL_FLAG32)!=IMAGE_ORDINAL_FLAG32)
					{
						dwECX+=0x01;
						if(dwDestCounter< dwEAX  || dwDestCounter+dwECX>*dwDestSize) //False Cases
						{
							return dwDestCounter;
						}
						for(DWORD i=0;i<dwECX;i++)
						{
							byBuff[dwDestCounter+i]=byBuff[dwDestCounter-dwEAX+i];
						}
						dwDestCounter+=dwECX;
					}
					else
					{
						if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
						{
							while(1)
							{
								dwEBP=0x100;
								while(dwEBP!=0x00)
								{
									dwECX=0x08;
									dwEAX=0x00;
									while(dwECX!=0x00)
									{
										if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
										{
											dwEAX+=dwEAX+1;
										}
										else
										{
											if(bGreater)
											{
												return dwDestCounter;
											}
											dwEAX+=dwEAX;
										}
										dwECX--;
									}
									if(dwDestCounter+1>*dwDestSize)
									{
										return dwDestCounter;
									}
									byBuff[dwDestCounter]=BYTE(dwEAX);
									dwDestCounter++;
									dwEBP--;
								}
								if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
								{
									if(bGreater)
									{
										return dwDestCounter;
									}
									break;
								}
							}	

						}
						else
						{
							dwECX=1;
							dwEAX=0;
							if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
							{
								dwEAX+=dwEAX+1;
							}
							else
							{
								if(bGreater)
								{
									return dwDestCounter;
								}
								dwEAX+=dwEAX;
							}
							dwEAX+=0x07;
						}
						dwStackLocal2=dwEAX;
						dwStackLocal3=0;
						if(dwEAX!=0x08)
						{
							dwECX=0x08;
							dwEAX=0x00;
							while(dwECX!=0x00)
							{
								if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
								{
									dwEAX+=dwEAX+1;
								}
								else
								{
									if(bGreater)
									{
										return dwDestCounter;
									}
									dwEAX+=dwEAX;
								}
								dwECX--;
							}
							dwStackLocal3=BYTE(dwEAX);


						}




					}
				}
				else
				{
					if(bGreater)
					{
						return dwDestCounter;
					}
					dwECX=0x07;
					dwEAX=0x00;
					while(dwECX!=0x00)
					{
						if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
						{
							dwEAX+=dwEAX+1;
						}
						else
						{
							if(bGreater)
							{
								return dwDestCounter;
							}
							dwEAX+=dwEAX;
						}
						dwECX--;
					}
					dwEBP=dwEAX;
					dwECX=0x02;
					dwEAX=0x00;

					while(dwECX!=0x00)
					{
						if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
						{
							dwEAX+=dwEAX+1;
						}
						else
						{
							
							if(bGreater)
							{
								return dwDestCounter;
							}
							dwEAX+=dwEAX;
						}
						dwECX--;
					}
					dwECX=dwEAX;
					dwEAX=dwEBP;
					dwECX+=0x02;
					if(dwEAX!=0x00)
					{
						dwEBX=dwEAX;
						if(dwDestCounter< dwEAX  || dwDestCounter+dwECX>*dwDestSize) //False Cases
						{
							return dwDestCounter;
						}
						for(DWORD i=0;i<dwECX;i++)
						{
							byBuff[dwDestCounter+i]=byBuff[dwDestCounter-dwEAX+i];
						}
						dwDestCounter+=dwECX;
					}
					else if(dwECX==0x02) //Actual true case
					{
						return dwDestCounter;
					}
					else
					{
						dwECX+=1;
						dwEAX=0;
						while(dwECX!=0x00)
						{
							if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
							{
								dwEAX+=dwEAX+1;
							}
							else
							{
								
								if(bGreater)
								{
									return dwDestCounter;
								}
								dwEAX+=dwEAX;
							}
							dwECX--;
						}
						dwStackLocal1=dwEAX;

					}

				}
			}
		}
	}
	
	return dwDestCounter;
}


bool CUnpackBase::LZSSUncompress(DWORD dwSrcSize,DWORD *dwDestSize,DWORD dwRead,DWORD dwWrite,CMaxPEFile *pMaxPeFile,DWORD *dwIncrement,BYTE *bySrcbuff /*==NULL*/,BYTE *byBuff /*==NULL*/,bool bFFCEMd)
{
	bool bGreater=false;
	DWORD dwSrcCounter=0x00;
	DWORD dwECX=0x03;
	DWORD dwEDX=0x00;
	DWORD dwEBX;
	DWORD dwEBP=0;
	DWORD dwEDI;
	DWORD dwEAX;
	DWORD dwOldEBP;
	DWORD dwDestCounter=0;
	if(dwDestCounter+1>*dwDestSize || dwSrcCounter+1>dwSrcSize)
	{
		return false;
	}
	byBuff[dwDestCounter]=bySrcbuff[dwSrcCounter];
	dwDestCounter++;dwSrcCounter++;
	for(;dwDestCounter<*dwDestSize;)
	{
		while(1)
		{
			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				break;
			}
			if(bGreater)
			{
				return false;
			}
			dwECX=0x03;
			if(dwDestCounter+1>*dwDestSize || dwSrcCounter+1>dwSrcSize)
			{
				return false;
			}

			byBuff[dwDestCounter]=bySrcbuff[dwSrcCounter];
			dwDestCounter++;dwSrcCounter++;
		}
		if(bGreater)
		{
			return false;
		}
		if(dwDestCounter>=*dwDestSize)
		{
			break;
		}
		dwEBX=1;
		dwOldEBP=dwEBP;
		dwEBP=0;
		dwEAX=1;
		while(1)
		{
			dwEDI=dwEBX+dwEBP;
			dwEBP=dwEBX;
			dwEBX=dwEDI;
			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				dwEBX=dwEDI+dwEBP;
				dwEAX+=dwEDI;
				dwEBP=dwEDI;
				if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
				{
					break;
				}

			}
			if(bGreater)
			{
				return false;
			}
		}
		if(bGreater)
		{
			return false;
		}

		if(dwEAX<dwECX)
		{
			dwEAX=dwOldEBP;
			dwEBP=dwOldEBP;
			dwECX=1;
			while(1)
			{
				if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
				{
					dwECX+=dwECX+1;
				}
				else
				{
					if(bGreater)
					{
						return false;
					}
					dwECX+=dwECX;
				}
				if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
				{
					if(bGreater)
					{
						return false;
					}
					break;
				}
			}
		}
		else
		{
			dwEAX-=dwECX;
			if(bFFCEMd)
			{
				dwEAX<<=0x08;
				if(dwSrcCounter+1 > dwSrcSize)
				{
					return false;
				}
				if(dwSrcCounter + 1 > dwSrcSize)
				{
					return false;
				}

				dwEAX|=bySrcbuff[dwSrcCounter];
				dwSrcCounter++;
			}
			else
			{
				for(DWORD i=0;i<0x06;i++)
				{
					if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
					{
						dwEAX+=dwEAX+1;
					}
					else
					{
						if(bGreater)
						{
							return false;
						}
						dwEAX*=2;
					}
				}
			}
			dwEAX+=1;
			dwECX=1;
			while(1)
			{
				if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
				{
					dwECX+=dwECX+1;
				}
				else
				{
					if(bGreater)
					{
						return false;
					}
					dwECX+=dwECX;
				}
				if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
				{
					if(bGreater)
					{
						return false;
					}
					break;
				}
			}
			dwEBP=dwEAX;
			if((dwEAX>=0x8001 && !bFFCEMd) || (dwEAX>=0x4001 && bFFCEMd))
			{
				dwECX+=1;
			}
			if(dwEAX>=0x781)
			{
				dwECX+=1;
			}
		}
		if(dwDestCounter< dwEAX  || dwDestCounter+dwECX>*dwDestSize) //False Cases
		{
			return false;
		}
		for(DWORD i=0;i<dwECX;i++)
		{
			byBuff[dwDestCounter+i]=byBuff[dwDestCounter-dwEAX+i];
		}
		dwDestCounter+=dwECX;
		if(dwDestCounter>=0x430)
		{
			dwECX=dwECX;
		}
		dwECX=2;
	}
	return true;
}


unsigned int align(unsigned int x, unsigned int alignment)
{
	return (x + alignment - 1) & ~(alignment - 1);
}

bool CUnpackBase::PetiteUncompress(DWORD dwSrcSize,DWORD *dwDestSize,DWORD dwRead,DWORD dwWrite,BYTE *bySrcbuff /*==NULL*/,BYTE *byDestbuff /*==NULL*/,int iType,DWORD dwCompare1,DWORD dwCompare2)
{
	bool bGreater=false;
	DWORD dwPush1=0;
	DWORD dwPush2=0;
	WORD  wDX=0;
	DWORD dwEDX=0x00;
	DWORD dwPreviousOffset=0;
	DWORD dwEAX;
	DWORD dwSrcCounter=0x00;
	DWORD dwDestCounter=0;
	DWORD dwEBP;
	if(*dwDestSize<dwCompare1)
	{
		dwPush1=-0x3FA0;
		dwPush2=-0x3A0;
		//wDX=(WORD(0x08)<<8);
		if(iType==0x0)
		dwEDX=0x80000000;
		else
		dwEDX=0x00000500;
	}
	else if(*dwDestSize<dwCompare2)
	{
		dwPush1=0xFFFF8180;
		dwPush2=-0x680;
		//wDX=(WORD(0x08)<<8);
		if(iType==0x0)
		dwEDX=0x80000000;
		else
		dwEDX=0x00000700;
	}
	else
	{
		dwPush1=0xFFFF8300;
		dwPush2=-0x500;

		//wDX=(WORD(0x08)<<8);
		if(iType==0x0)
		dwEDX=0x80000000;
		else
		dwEDX=0x00000800;

	}

	if(dwDestCounter+1>*dwDestSize || dwSrcCounter+1>dwSrcSize)
	{
		return false;
	}
	byDestbuff[dwDestCounter]=bySrcbuff[dwSrcCounter];
	if(iType==0x0)
	{
	 byDestbuff[dwDestCounter]^=BYTE(*dwDestSize-dwDestCounter);
	}
	dwDestCounter++;dwSrcCounter++;
	for(;dwDestCounter<*dwDestSize;)
	{
		DWORD dwLookBackOffset=0;
		
		//if(CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
		if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
		{
			dwEBP=0;
			dwLookBackOffset+=1;
			while(1)
			{
				dwLookBackOffset+=dwLookBackOffset;
				//if(CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
				if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
				{
					dwLookBackOffset+=1;
				}
				//if(!CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
				if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
				{
					break;
				}
			}
			if(dwLookBackOffset<0x03)
			{
				dwLookBackOffset-=0x03;
				dwEAX=dwPreviousOffset;
				dwLookBackOffset+=1;

			}
			else
			{
				dwLookBackOffset-=0x03;
				dwEAX=dwLookBackOffset;

				if(dwPush1==0xFFFF8300)
					dwLookBackOffset=0x08;
				else if(dwPush1==0xFFFF8180)
					dwLookBackOffset=0x07;
				else
					dwLookBackOffset=0x05;

				while(dwLookBackOffset!=0x00)
				{
					dwEAX+=dwEAX;
					//if(CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
					if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
					{
						dwEAX+=1;
					}
					dwLookBackOffset--;
				}
				dwEAX^=0xFFFFFFFF;
				dwEBP+=1;
				if(dwEAX<dwPush2)
				{
					dwEBP+=1;
				}
				if(dwEAX<dwPush1)
				{
					dwEBP+=1;
				}
				dwPreviousOffset=dwEAX;
			}

			dwLookBackOffset+=dwLookBackOffset;
			//if(CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
			{
				dwLookBackOffset+=1;
			}
			dwLookBackOffset+=dwLookBackOffset;
			//if(CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
			{
				dwLookBackOffset+=1;
			}
			if(dwLookBackOffset==0x00)
			{
				dwLookBackOffset+=1;
				while(1)
				{
					dwLookBackOffset+=dwLookBackOffset;
					//if(CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
					if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
					{
						dwLookBackOffset+=1;
					}
					//if(!CheckByteBit1(bySrcbuff,&dwSrcCounter,(BYTE*)&wDX,dwSrcSize,&bGreater))
						if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater,iType))
					{
						break;
					}
				}
				dwLookBackOffset+=2;
			}
			dwLookBackOffset+=dwEBP;
			if(dwDestCounter+dwEAX+dwLookBackOffset>*dwDestSize)
			{
				return false;
			}
			for(DWORD i=0;i<dwLookBackOffset;i++)
			{
				byDestbuff[dwDestCounter+i]=byDestbuff[dwDestCounter+dwEAX+i];
			}
			dwDestCounter+=dwLookBackOffset;
		}
		else
		{
			if(dwDestCounter+1>*dwDestSize || dwSrcCounter+1>dwSrcSize)
			{
				return false;
			}
			byDestbuff[dwDestCounter]=bySrcbuff[dwSrcCounter];
			byDestbuff[dwDestCounter]^=BYTE(*dwDestSize-dwDestCounter);
			dwDestCounter++;dwSrcCounter++;
		}
	}
	return true;
}


bool CUnpackBase::CheckBit1(BYTE *bySrc,DWORD *dwSrcCounter,DWORD *dwEDX,DWORD dwSrcSize,bool &bGreater,int iType)
{
	bool bRetStatus=false;
	if(iType==0x00)
	{
		if(*dwEDX*2==0x00)
		{
			if(*dwSrcCounter+0x04>dwSrcSize)
			{
				bGreater = true;
				return false;
			}
			*dwEDX = *(DWORD*)&bySrc[*dwSrcCounter];
			if((*dwEDX*2)<*dwEDX)
			{
				bRetStatus=true;
			}
			*dwEDX*=2;
			*dwEDX+=1;	
			*dwSrcCounter+=0x04;
		}
		else
		{
			if((*dwEDX*2)<*dwEDX)
			{
				bRetStatus=true;
			}
			*dwEDX*=2;
		}
	}
	else if(iType==0x01)
	{
		if(BYTE(BYTE(*dwEDX)*2)==0x00)
		{
			if(*dwSrcCounter+0x01>dwSrcSize)
			{
				bGreater = true;
				return false;			
			}
			*dwEDX=bySrc[*dwSrcCounter];
			//*byDL = bySrc[*dwSrcCounter];
			if(BYTE((BYTE(*dwEDX)*2))<BYTE(*dwEDX))
			{
				bRetStatus=true;
			}
			*dwEDX=BYTE(*dwEDX)+BYTE(*dwEDX);
			*dwEDX=BYTE(*dwEDX)+1;
			*dwSrcCounter+=0x01;
		}
		else
		{
			if(BYTE((BYTE(*dwEDX)*2))<BYTE(*dwEDX))
			{
				bRetStatus=true;
			}
			*dwEDX=BYTE(*dwEDX)+BYTE(*dwEDX);
		}
	}
	return bRetStatus;
}

//Function Definition
bool CUnpackBase::LZSSModUncompress(DWORD dwSrcSize,DWORD *dwDestSize,DWORD dwRead,DWORD dwWrite,CMaxPEFile *pMaxPeFile,DWORD *dwIncrement,BYTE *bySrcbuff /*==NULL*/,BYTE *byBuff /*==NULL*/)
{
	bool bGreater=false;
	DWORD dwSrcCounter=0x00;
	DWORD dwECX=0x00;
	DWORD dwEDX=0x00;
	DWORD dwEAX;
	DWORD dwDestCounter=0;
	if(dwDestCounter+1>*dwDestSize || dwSrcCounter+1>dwSrcSize)
	{
		return false;
	}
	byBuff[dwDestCounter]=bySrcbuff[dwSrcCounter];
	dwDestCounter++;dwSrcCounter++;
	for(;dwDestCounter<*dwDestSize || dwSrcCounter<dwSrcSize;)
	{
		
		while(1)
		{
			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				break;
			}
			if(bGreater)
			{
				return false;
			}
			if(dwDestCounter+1>*dwDestSize || dwSrcCounter+1>dwSrcSize)
			{
				return false;
			}
			if(dwDestCounter>=0xB08)
			{
				dwDestCounter=dwDestCounter;
			}
			byBuff[dwDestCounter]=bySrcbuff[dwSrcCounter];
			dwDestCounter++;dwSrcCounter++;
			if(dwDestCounter>=*dwDestSize)
			{
				break;
			}
		}
		if(bGreater)
		{
			return false;
		}
		if(dwDestCounter>=*dwDestSize)
		{
			break;
		}

		dwECX=1;
		while(1)
		{
			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				dwECX+=dwECX+1;
			}
			else
			{
				if(bGreater)
				{
					return false;
				}
				dwECX+=dwECX;
			}
			if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				if(bGreater)
				{
					return false;
				}
				break;
			}
		}

		dwEAX=1;
		while(1)
		{
			if(CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				dwEAX+=dwEAX+1;
			}
			else
			{
				if(bGreater)
				{
					return false;
				}
				dwEAX+=dwEAX;
			}
			if(!CheckBit1(bySrcbuff,&dwSrcCounter,&dwEDX,dwSrcSize,bGreater))
			{
				if(bGreater)
				{
					return false;
				}
				break;
			}
		}

		dwECX+=2;
		dwEAX<<=8;
		*(BYTE*)&dwEAX=bySrcbuff[dwSrcCounter];
		dwSrcCounter++;
		dwEAX-=0x1FF;		
	
		if(dwDestCounter< dwEAX  || dwDestCounter+dwECX>*dwDestSize) //False Cases
		{
			return false;
		}
		for(DWORD i=0;i<dwECX;i++)
		{
			byBuff[dwDestCounter+i]=byBuff[dwDestCounter-dwEAX+i];
		}
		dwDestCounter+=dwECX;
	}
	return true;
}

CStealthackUnpacker::CStealthackUnpacker(CMaxPEFile *pMaxPEFile):CUnpackBase(pMaxPEFile)
{	
}

CStealthackUnpacker::~CStealthackUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
}

bool CStealthackUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 && (m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint % 0x1000) == 0x00)
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x13,0x13))
		{
			return false;
		}
		if((m_pbyBuff[0x07]&0xB8)==0xB8 && (m_pbyBuff[0x0E]&0xB8)==0xB8 &&
			*(DWORD*)&(m_pbyBuff[0x08])==*(DWORD*)&(m_pbyBuff[0x0F]))
		{
			return true;
		}
	}
	return false;
}

bool CStealthackUnpacker::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}
	DWORD dwAEPUnMapped=*(DWORD*)&(m_pbyBuff[0x08])-m_dwImageBase;
	DWORD dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint+0x14;
	if(!m_objTempFile.ReadBuffer(m_pbyBuff,dwOffset,0x0E,0x0E))
	{
		return false;
	}
    
	*(DWORD*)&m_pbyBuff[0x3]=*(DWORD*)&m_pbyBuff[0xA];
	if(!m_objTempFile.WriteBuffer(m_pbyBuff,dwAEPUnMapped,0x07,0x07))
	{
		return false;
	}
	
	if(m_objTempFile.WriteAEP(dwAEPUnMapped))
	{
		return true;
	}
	return false;
}

CUPXPatch::CUPXPatch(CMaxPEFile *pMaxPEFile):CUnpackBase(pMaxPEFile)
{	
}

CUPXPatch::~CUPXPatch(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
}

bool CUPXPatch::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 && (m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-2))
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x13,0x13))
		{
			return false;
		}
		if(*(DWORD*)&m_pbyBuff[0]==0x53C08B66)
		{
			return true;
		}
	}
	return false;
}

bool CUPXPatch::Unpack(LPCTSTR szTempFileName)
{	
	if(!CopyFile(m_pMaxPEFile->m_szFilePath, szTempFileName, false))
	{
		return false;
	}
	if(!m_objTempFile.OpenFile(szTempFileName, true))
	{
		return false;
	}

	if(!m_objTempFile.ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped+0x3C,0x04,0x04))
	{
		return false;
	}

	if(m_objTempFile.WriteAEP(*(DWORD*)&m_pbyBuff[0]+0x0B))
	{
		return true;
	}
	return false;
}