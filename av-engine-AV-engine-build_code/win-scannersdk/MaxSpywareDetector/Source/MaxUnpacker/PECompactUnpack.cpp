#pragma once
#include "PECompactUnpack.h"
#include "MaxExceptionFilter.h"
#include "wincrypt.h"
#include "Packers.h"

CPECompactUnpack::CPECompactUnpack(CMaxPEFile *pMaxPEFile):
CUnpackBase(pMaxPEFile)
{
	memset(&m_objStructLdrDcdrInfo, 0x00, sizeof(LOADER_DECODER_INFO));
	m_pStructPecBlockInfo=NULL;
	m_dwBypassSEH=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
	m_dwImageBase = m_pMaxPEFile->m_stPEHeader.ImageBase;
	m_pbyBuff = new BYTE[255];
	m_eDLLCompress=INVALID;
}

CPECompactUnpack::~CPECompactUnpack(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_pStructPecBlockInfo=NULL;
	m_pStructPecHostInfo=NULL;
	m_objTempFile.CloseFile();
}

bool CPECompactUnpack::IsPacked() 
{
	//AddLogEntry(L"TEST : IsPacked (CPECompactUnpack) : Inside");
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections < 1 || ((m_pMaxPEFile->m_stSectionHeader[1].Characteristics & 0xC0000000) != 0xC0000000))
	{
		//AddLogEntry(L"TEST : IsPacked (CPECompactUnpack) : Ret 1");
		return false;
	}
	if ((m_pMaxPEFile->m_stSectionHeader[0].PointerToRelocations & 0x00434550) == 0x00434550 || 
		m_pMaxPEFile->m_stPEHeader.NumberOfSections == 2 || 	
		m_iCurrentLevel > 1 || 
		(m_pMaxPEFile->m_stPEHeader.SizeOfOptionalHeader==0x148 && m_pMaxPEFile->m_stPEHeader.e_lfanew<0x3C && m_pMaxPEFile->m_stPEHeader.NumberOfSymbols==0x7CEB3476))
	{
		//AddLogEntry(L"TEST : IsPacked (CPECompactUnpack) : Ret 2");
		return true;
	}
	//AddLogEntry(L"TEST : IsPacked (CPECompactUnpack) : Ret 3");
	return false;
}

bool CPECompactUnpack::Emulate() 
{
	bool bRetStatus = false;	
	m_dwDetectType = 0;	
	CEmulate objEmulate(m_pMaxPEFile);
	if(!objEmulate.IntializeProcess(true))
	{
		return bRetStatus;
	}
	objEmulate.SetNoOfIteration(15);
	objEmulate.SetBreakPoint("__isinstruction('mov eax ,')");
	const BYTE byLoaderDirectSig[] = {0x53,0x57,0x56,0x55,0xE8,0x0,0x0,0x0,0x0,0x5D,0x81,0xED,0x8D,0xB5};

	BYTE byLoaderSigComparebuff[sizeof(byLoaderDirectSig) + 0x8] = {0};


	if(7 == objEmulate.EmulateFile())
	{
		objEmulate.SetNoOfIteration(2);
		objEmulate.ModifiedBreakPoint("__isinstruction('push eax')", 0);
		if(7 == objEmulate.EmulateFile())
		{
			objEmulate.SetNoOfIteration(2);
			objEmulate.ModifiedBreakPoint("__isinstruction('push dword ptr fs:[0h]')", 0);
			if(7 == objEmulate.EmulateFile())
			{	
				m_dwBypassSEH=objEmulate.GetSpecifyRegValue(0)-m_dwImageBase;
				return true;
			}
		}
		else if(0 == objEmulate.EmulateFile())
		{
			const BYTE byNoSEHSig[]= {0xB8, 0x8D, 0x88, 0x89, 0x41, 0x01, 0x8B, 0x54, 0x24, 0x04};	
			const BYTE byBypassSEH[]= {0xB8, 0x55, 0x53, 0x51, 0x57, 0x56, 0x52};



			if(!m_pMaxPEFile->ReadBuffer(byLoaderSigComparebuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(byLoaderDirectSig) + 0x8, sizeof(byLoaderDirectSig) + 0x8))
			{
				return bRetStatus;
			}			
			else if((memcmp(byLoaderSigComparebuff, byLoaderDirectSig, 0xC) == 0) && (memcmp(byLoaderSigComparebuff + 0x10, byLoaderDirectSig + 0xC, 0x2) == 0))
			{
				m_dwDetectType = 0x1;
				return true;
			}
			else if( (memcmp(byLoaderSigComparebuff, byNoSEHSig, 0x01) == 0) && (memcmp(byLoaderSigComparebuff+0x05, byNoSEHSig+0x01, 0x02)==0) && (memcmp(byLoaderSigComparebuff+0x0B, byNoSEHSig+0x03, sizeof(byNoSEHSig)-0x03) == 0) )
			{ 
				return true;
			}
			else if( byLoaderSigComparebuff[0]==0xB8 && memcmp(&byLoaderSigComparebuff[5],&byBypassSEH[1],sizeof(byBypassSEH)-1)==0)
			{
				m_dwDetectType=0x02;
				m_dwBypassSEH=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
				return true;
			}

			else if(byLoaderSigComparebuff[0]==0xB8 && *(WORD*)&byLoaderSigComparebuff[0x05]==0xE0FF)
			{
				m_dwBypassSEH=*(DWORD*)&byLoaderSigComparebuff[0x01]-m_dwImageBase;
				m_dwDetectType = 0x2;
				return true;

			}
			
		}
	}
	else
	{
			const BYTE byMessagesEBPNotSet[]={0x8B,0x2C,0x08,0x2C,0x08,0x8B,0x45};
		    
		    if(!m_pMaxPEFile->ReadBuffer(byLoaderSigComparebuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(byLoaderDirectSig) + 0x8, sizeof(byLoaderDirectSig) + 0x8))
			{
				return bRetStatus;
			}
			else if( byLoaderSigComparebuff[0]==0x8B && memcmp(&byLoaderSigComparebuff[1],&byMessagesEBPNotSet[1],sizeof(byMessagesEBPNotSet)-1)==0)		
			{
				m_dwDetectType=0x03;
				m_dwBypassSEH=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
				if(!m_pMaxPEFile->ReadBuffer(byLoaderSigComparebuff, m_pMaxPEFile->m_dwAEPMapped+0x1A, sizeof(byLoaderDirectSig) + 0x8, sizeof(byLoaderDirectSig) + 0x8))
				{
					return bRetStatus;
				}
				m_dwBypassSEH+=*(DWORD*)&byLoaderSigComparebuff[0]+0x04+0x1A;
				return true;
			}

	}
	return bRetStatus;	
}


bool CPECompactUnpack::Unpack(LPCTSTR szTempFileName)
{
	__try
	{
		WaitForSingleObject(CUnpackBase::m_hEvent, INFINITE);
		bool bRet = Emulate();
		
		SetEvent(CUnpackBase::m_hEvent);
		
		if(!bRet)
		{
			return false;
		}

		if(!ReOrganizeFile(szTempFileName))
		{
			return false;
		}
		if(m_dwDetectType==0x03)
		{
			if(!m_objTempFile.WriteAEP(m_dwBypassSEH))
			{
				return false;
			}
			return true;
		}
		
		//Making the m_pMAXPefile=m_obFile to avoid having to convert to RVA
		CMaxPEFile *ctempFile=m_pMaxPEFile;
		m_pMaxPEFile=&m_objTempFile;
		BYTE *byLoaderbuff=NULL;
		DWORD dwDestSize;
		DWORD dwDecompressionAlgoOffset;
		DWORD dwPecHostInfo=0x00;
		bool bAddMoreBytestoSource=false;


		if(m_dwDetectType == 0x1)  //Case for Direct Loader
		{
			if(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint<0x04)
			{
				m_pMaxPEFile=ctempFile;
				return false;
			}
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint-0x04,0x04,0x04))
			{
				m_pMaxPEFile=ctempFile;
				return false;
			}
			m_dwBypassSEH=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint-*(DWORD*)&m_pbyBuff[0]-0x04;
			dwPecHostInfo=*(DWORD*)&m_pbyBuff[0]+0x04;
			if(!(m_pStructPecHostInfo=(PEC_HOST_INFO *)MaxMalloc(sizeof(PEC_HOST_INFO))))
			{
				m_pMaxPEFile=ctempFile;
				return false;
			}
			if(!m_pMaxPEFile->ReadBuffer(m_pStructPecHostInfo,m_dwBypassSEH,sizeof(PEC_HOST_INFO),sizeof(PEC_HOST_INFO)))
			{
				m_pMaxPEFile=ctempFile;
				free(m_pStructPecHostInfo);
				m_pStructPecHostInfo=NULL;
				return false;
			}
			m_dwBypassSEH-=m_pStructPecHostInfo->dwOffsetInLoader;
			if(m_pStructPecHostInfo->dwOffsetInLoader2!=0x00)
			{
				m_dwBypassSEH=m_dwBypassSEH+m_pStructPecHostInfo->dwOffsetInLoader-m_pStructPecHostInfo->dwOffsetInLoader2;			
			}
			m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint-m_dwBypassSEH;



			if(m_dwBypassSEH>m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint)
			{
				m_pMaxPEFile=ctempFile;
				free(m_pStructPecHostInfo);
				m_pStructPecHostInfo=NULL;
				return false;
			}

			if(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize<m_dwBypassSEH)
			{
				m_pMaxPEFile=ctempFile;
				free(m_pStructPecHostInfo);
				m_pStructPecHostInfo=NULL;
				return false;
			}

			if(!(byLoaderbuff=(BYTE*)MaxMalloc(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize-m_dwBypassSEH)))
			{
				m_pMaxPEFile=ctempFile;
				free(m_pStructPecHostInfo);
				m_pStructPecHostInfo=NULL;
				return false;
			}
			if(!m_pMaxPEFile->ReadBuffer(byLoaderbuff,m_dwBypassSEH,m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize-m_dwBypassSEH,m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize-m_dwBypassSEH))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(m_pStructPecHostInfo);
				m_pStructPecHostInfo=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			m_objStructLdrDcdrInfo.dwUncompressedLoaderSize=m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress+m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize-m_dwBypassSEH;

			free(m_pStructPecHostInfo);
			m_pStructPecHostInfo=NULL;
			m_pStructPecHostInfo=(PEC_HOST_INFO *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo];
		}



		else  //Default Case
		{
			//Bypassing the SEH to read the LoaderStructure If there is a Loader
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_dwBypassSEH+0x01,0x11,0x11))
			{
				m_pMaxPEFile=ctempFile;
				return false;
			}

			if(m_dwDetectType==0x02)
			{
				*(DWORD*)&m_pbyBuff[0x06]=*(DWORD*)&m_pbyBuff[0x0C]+0x47;				
			}
			
			m_dwBypassSEH=*(DWORD*)&m_pbyBuff[0]+*(DWORD*)&m_pbyBuff[0x06]-0x47-m_dwImageBase;


			if(!m_pMaxPEFile->ReadBuffer(&m_objStructLdrDcdrInfo,m_dwBypassSEH,sizeof(m_objStructLdrDcdrInfo),sizeof(m_objStructLdrDcdrInfo)))
			{
				m_pMaxPEFile=ctempFile;
				return false;
			}

			if(!(byLoaderbuff=(BYTE*)MaxMalloc(m_objStructLdrDcdrInfo.dwUncompressedLoaderSize)))
			{
				m_pMaxPEFile=ctempFile;
				return false;
			}

			if(m_objStructLdrDcdrInfo.dwUncompressedLoaderSize<0x15)
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}

			dwDecompressionAlgoOffset=m_objStructLdrDcdrInfo.dwRvaDecoder;
			if(!m_pMaxPEFile->ReadBuffer(byLoaderbuff,dwDecompressionAlgoOffset,0x15,0x15))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}



			//To check and Implement Decompression for the Loader
			if(!CheckAlgorithm(0x00,0x00,byLoaderbuff,&dwDestSize,byLoaderbuff,false))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}

			dwPecHostInfo=0x00;
			if(m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry>0x04)
			{
				dwPecHostInfo=*(DWORD*)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-0x04]+0x04;
			}
			else
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			if(dwPecHostInfo>m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry && (m_objStructLdrDcdrInfo.dwUncompressedLoaderSize-1)<(m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+sizeof(PEC_HOST_INFO)))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}

			m_pStructPecHostInfo=(PEC_HOST_INFO *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo];

		}


		//AEP Patching if it needs to be done
		if(m_pStructPecHostInfo->dwNewEntryinLastSection!=0x01 && m_pStructPecHostInfo->dwRVAOrigBytes)
		{
			DWORD dwAEPPatchOffset=m_pMaxPEFile->m_dwAEPMapped;
			DWORD dwOffsettoCheckAEPPatch=0x3C;
			if(m_dwDetectType==0x02)
			{
				dwOffsettoCheckAEPPatch+=0x31;
			}
			DWORD dwAEPPatchCount=-1;
			if(m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry+dwOffsettoCheckAEPPatch+0x40>m_objStructLdrDcdrInfo.dwUncompressedLoaderSize)
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			for(DWORD i=0;i<=0xA7-0x11;i++)
			{
				if(*(DWORD*)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry+dwOffsettoCheckAEPPatch+i]==0x0E74F685 &&
					byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry+dwOffsettoCheckAEPPatch+i+4]==0xB9 &&
					*(WORD*)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry+dwOffsettoCheckAEPPatch+i+9]==0xF203 )
				{
					dwAEPPatchCount=*(DWORD*)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry+dwOffsettoCheckAEPPatch+i+5];
					break;
				}
			}
			if(dwAEPPatchCount==0xFFFFFFFF || dwAEPPatchCount>255)
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}


			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pStructPecHostInfo->dwRVAOrigBytes,dwAEPPatchCount,dwAEPPatchCount))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			if(!m_objTempFile.WriteBuffer(m_pbyBuff,m_pStructPecHostInfo->dwStubRVA,dwAEPPatchCount,dwAEPPatchCount))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}   


			m_pMaxPEFile=NULL;
			m_objTempFile.CloseFile();

			if(!m_objTempFile.OpenFile(szTempFileName, true))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			m_pMaxPEFile=&m_objTempFile;

		}

		BYTE *byDestbuff=NULL;
		if(!(byDestbuff=(BYTE*)MaxMalloc(m_pStructPecHostInfo->dwWorkingMemoryRequired)))
		{
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			m_pMaxPEFile=ctempFile;
			return false;
		}


		if(m_pStructPecHostInfo->wTotalDecoders>0x00)
		{

			if(m_objStructLdrDcdrInfo.dwUncompressedLoaderSize-1<m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock+sizeof(PEC_BLOCK))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			//m_pStructPecBlockInfo=(PEC_BLOCK *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock];
			m_pStructPecBlockInfo=(PEC_BLOCK *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock];





			//To be coded Not Getting a Sample to understand this

			/*WORD wtempTotalDecoders=m_pStructPecHostInfo->wTotalDecoders;
			m_pStructPecBlockInfo=(PEC_BLOCK *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock];
			for(WORD i=0;i<m_pStructPecHostInfo->wNoOfPecBlocks;i++,m_pStructPecBlockInfo++)
			{
			if((m_pStructPecBlockInfo->wFlag_Encoded&0x20)==0x20)
			{

			}
			}*/




			if(m_pStructPecHostInfo->dwOffsetInLoader2!=0x00)
			{
				bAddMoreBytestoSource=true;
			}

			DWORD dwAddMoreBytesOffset=0x00;
			if(m_pStructPecHostInfo->dwOffsetInLoader!=m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo)
			{
				dwAddMoreBytesOffset=m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo-m_pStructPecHostInfo->dwOffsetInLoader;
			}

			DWORD dwAddMoreBytesCount=0x00;
			WORD wtempTotalDecoders;
			bool bUseEarlierDecompression=false;

			for(WORD i=0;i<m_pStructPecHostInfo->wNoOfPecBlocks;i++,m_pStructPecBlockInfo++)
			{
				//For the case of flag==0x10 Decompress bytes and fill the rest with zero till Section Alignment
				if((m_pStructPecBlockInfo->wFlag_Encoded&0x10)==0x10)
				{
					wtempTotalDecoders=m_pStructPecHostInfo->wTotalDecoders;

					/*if(bAddMoreBytestoSource)
					{
					dwAddMoreBytesOffset=m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo-m_pStructPecHostInfo->dwOffsetInLoader;
					}*/

					//Check for Decompression Algorithm to be used
					bool bUseVirtualSizeforSource=false;
					WORD wWorkingDecoders=0x00;
					if(wtempTotalDecoders>0x01)
					{
						bUseVirtualSizeforSource=true;
					}
					while(wtempTotalDecoders--)
					{
						bUseEarlierDecompression = false;
						wWorkingDecoders++;
						if((DWORD)(dwAddMoreBytesOffset+wtempTotalDecoders*0x04+0x04)>m_objStructLdrDcdrInfo.dwUncompressedLoaderSize-1)
						{
							free(byLoaderbuff);
							byLoaderbuff=NULL;
							free(byDestbuff);
							byDestbuff=NULL;
							m_pMaxPEFile=ctempFile;
							return false;
						}

						dwDecompressionAlgoOffset=dwAddMoreBytesOffset+*(DWORD*)&byLoaderbuff[dwAddMoreBytesOffset+wtempTotalDecoders*0x04];
						if(dwDecompressionAlgoOffset==0xFFFFFFFF && m_eDLLCompress!=INVALID)
						{
							bUseEarlierDecompression=true;
						}
						else if(dwDecompressionAlgoOffset==0xFFFFFFFF && m_eDLLCompress ==INVALID)
						{
							free(byLoaderbuff);
							byLoaderbuff=NULL;
							free(byDestbuff);
							byDestbuff=NULL;
							m_pMaxPEFile=ctempFile;
							return false;
						}

						//Case when more bytes are to be added to source buffer for decompression
						if(bAddMoreBytestoSource)
						{
							DWORD dwCounter=0x00;
							dwAddMoreBytesOffset=m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo-m_pStructPecHostInfo->dwOffsetInLoader2;
							while(1)
							{
								if(dwAddMoreBytesOffset+0x04>m_objStructLdrDcdrInfo.dwUncompressedLoaderSize)
								{
									free(byLoaderbuff);
									byLoaderbuff=NULL;
									free(byDestbuff);
									byDestbuff=NULL;
									m_pMaxPEFile=ctempFile;
									return false;
								}
								if(*(DWORD*)&byLoaderbuff[dwAddMoreBytesOffset]==0x00)
								{
									break;
								}
								dwAddMoreBytesOffset+=0x04;
								if(dwCounter==m_pStructPecBlockInfo->dwAddMoreBytes)
								{
									break;
								}
								dwCounter++;
							}
							dwAddMoreBytesCount=m_pStructPecBlockInfo->dwOverKillSize;
						}

						if(dwDecompressionAlgoOffset!=0x00)
						{
							if(bAddMoreBytestoSource && dwAddMoreBytesCount)
							{
								if(dwAddMoreBytesOffset+dwAddMoreBytesCount>m_objStructLdrDcdrInfo.dwUncompressedLoaderSize)
								{
									free(byLoaderbuff);
									byLoaderbuff=NULL;
									free(byDestbuff);
									byDestbuff=NULL;
									m_pMaxPEFile=ctempFile;
									return false;
								}
							}

							if(dwDecompressionAlgoOffset+0x1C>m_objStructLdrDcdrInfo.dwUncompressedLoaderSize)
							{
								free(byLoaderbuff);
								byLoaderbuff=NULL;
								free(byDestbuff);
								byDestbuff=NULL;
								m_pMaxPEFile=ctempFile;
								return false;
							}
							if(!CheckAlgorithm(wWorkingDecoders,dwDecompressionAlgoOffset,byLoaderbuff,&dwDestSize,byDestbuff,true,bAddMoreBytestoSource,dwAddMoreBytesOffset,dwAddMoreBytesCount,bUseEarlierDecompression,bUseVirtualSizeforSource))
							{
								free(byLoaderbuff);
								byLoaderbuff=NULL;
								free(byDestbuff);
								byDestbuff=NULL;
								m_pMaxPEFile=ctempFile;
								return false;
							}
						}
						else
						{
							free(byLoaderbuff);
							byLoaderbuff=NULL;
							free(byDestbuff);
							byDestbuff=NULL;
							m_pMaxPEFile=ctempFile;
							return false;

						}

						m_objTempFile.CloseFile();

						if(!m_objTempFile.OpenFile(szTempFileName, true))
						{
							free(byLoaderbuff);
							byLoaderbuff=NULL;
							free(byDestbuff);
							byDestbuff=NULL;
							m_pMaxPEFile=ctempFile;
							return false;
						}

					}

					//Fill the remaining part with zeroes till Section Alignment
					if(!m_pMaxPEFile->FillWithZeros(m_pStructPecBlockInfo->dwRVADest+dwDestSize,SA(m_pStructPecBlockInfo->dwRVADest+dwDestSize)-(m_pStructPecBlockInfo->dwRVADest+dwDestSize)))
					{
						free(byLoaderbuff);
						byLoaderbuff=NULL;
						free(byDestbuff);
						byDestbuff=NULL;
						m_pMaxPEFile=ctempFile;
						return false;
					}


				}
				if(m_objStructLdrDcdrInfo.dwUncompressedLoaderSize-1<m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock+sizeof(PEC_BLOCK)*(i+2))
				{
					free(byLoaderbuff);
					byLoaderbuff=NULL;
					free(byDestbuff);
					byDestbuff=NULL;
					m_pMaxPEFile=ctempFile;
					return false;
				}
			}


			m_pMaxPEFile=NULL;
			m_objTempFile.CloseFile();

			if(!m_objTempFile.OpenFile(szTempFileName, true))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			m_pMaxPEFile=&m_objTempFile;

			//For the case of flag==0x02 just copy bytes from A->B
			wtempTotalDecoders=m_pStructPecHostInfo->wTotalDecoders;
			m_pStructPecBlockInfo=(PEC_BLOCK *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock];
			for(WORD i=0;i<m_pStructPecHostInfo->wNoOfPecBlocks;i++,m_pStructPecBlockInfo++)
			{
				if((m_pStructPecBlockInfo->wFlag_Encoded&0x02)==0x02)
				{
					//Taking in a Buffer
					if(!(m_pMaxPEFile->ReadBuffer(byDestbuff,m_pStructPecBlockInfo->dwRVADest,m_pStructPecBlockInfo->dwBlockCSize,m_pStructPecBlockInfo->dwBlockCSize)))
					{
						free(byLoaderbuff);
						byLoaderbuff=NULL;
						free(byDestbuff);
						byDestbuff=NULL;
						m_pMaxPEFile=ctempFile;
						return false;
					}

					//Writing into another Buffer
					if(!m_pMaxPEFile->WriteBuffer(byDestbuff,m_pStructPecBlockInfo->dwRVASource,m_pStructPecBlockInfo->dwBlockCSize,m_pStructPecBlockInfo->dwBlockCSize))
					{
						free(byLoaderbuff);
						byLoaderbuff=NULL;
						free(byDestbuff);
						byDestbuff=NULL;
						m_pMaxPEFile=ctempFile;
						return false;
					}

					//Filling with zeroes and taking back in the original buffer
					DWORD dwFillZeroSize=m_pStructPecBlockInfo->dwBlockCSize;
					DWORD dwFillWithZeroOffset=m_pStructPecBlockInfo->dwRVADest;
					if(m_pStructPecBlockInfo->dwRVADest>m_pStructPecBlockInfo->dwRVASource && m_pStructPecBlockInfo->dwRVADest-m_pStructPecBlockInfo->dwRVASource<dwFillZeroSize)
					{
						dwFillZeroSize=m_pStructPecBlockInfo->dwRVADest-m_pStructPecBlockInfo->dwRVASource;
						dwFillWithZeroOffset=m_pStructPecBlockInfo->dwRVASource+m_pStructPecBlockInfo->dwBlockCSize;
					}
					else if(m_pStructPecBlockInfo->dwRVASource>m_pStructPecBlockInfo->dwRVADest && m_pStructPecBlockInfo->dwRVASource-m_pStructPecBlockInfo->dwRVADest<dwFillZeroSize)
					{
						dwFillZeroSize=m_pStructPecBlockInfo->dwRVASource-m_pStructPecBlockInfo->dwRVADest;
					}
					memset(byDestbuff,0x0,dwFillZeroSize);
					if(!m_pMaxPEFile->WriteBuffer(byDestbuff,dwFillWithZeroOffset,dwFillZeroSize,dwFillZeroSize))
					{
						free(byLoaderbuff);
						byLoaderbuff=NULL;
						free(byDestbuff);
						byDestbuff=NULL;
						m_pMaxPEFile=ctempFile;
						return false;
					}

				}
			}

			m_pMaxPEFile=NULL;
			m_objTempFile.CloseFile();

			if(!m_objTempFile.OpenFile(szTempFileName, true))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
			m_pMaxPEFile=&m_objTempFile;

			//For the case of flag==0x200 and 0x8
			//For the case of flag==0x04 then it just does a integrity check..So no need to code
			//0x200-> Filter value to be put at specific location
			//0x8-> Resolve E8/E9 calls as per the Filter option
			wtempTotalDecoders=m_pStructPecHostInfo->wTotalDecoders;
			m_pStructPecBlockInfo=(PEC_BLOCK *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock];
			for(WORD i=0;i<m_pStructPecHostInfo->wNoOfPecBlocks;i++,m_pStructPecBlockInfo++)
			{
				if((m_pStructPecBlockInfo->wFlag_Encoded&0x200)==0x200)
				{
					if(!ResolveFilter())
					{
						free(byLoaderbuff);
						byLoaderbuff=NULL;
						free(byDestbuff);
						byDestbuff=NULL;
						m_pMaxPEFile=ctempFile;
						return false;
					}
				}
				else if((m_pStructPecBlockInfo->wFlag_Encoded&0x08)==0x08)
				{
					if(!ResolveE8E9Calls(byDestbuff))
					{
						free(byLoaderbuff);
						byLoaderbuff=NULL;
						free(byDestbuff);
						byDestbuff=NULL;
						m_pMaxPEFile=ctempFile;
						return false;
					}

				}
			}

			//Getting the pointer back to its original location
			m_pStructPecBlockInfo=(PEC_BLOCK *)&byLoaderbuff[m_objStructLdrDcdrInfo.dwOffsetToLoaderEntry-dwPecHostInfo+m_pStructPecHostInfo->OffsettoPecBlock];


			////Closing and opening the file again so that it reflects unpacked size
			m_objTempFile.CloseFile();

			if(!m_objTempFile.OpenFile(szTempFileName, true))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}


			//Resolving Import Addresses
			if(!ResolveAddresses(m_pStructPecHostInfo->dwImportTableRVA))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}

			//Writing the Import Address RVA
			if(!m_objTempFile.WriteBuffer(&m_pStructPecHostInfo->dwImportTableRVA,m_objTempFile.m_stPEHeader.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+0x68,sizeof(DWORD),sizeof(DWORD)))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}

			//If there is an Entry in Last Section then simply patches a Jump Call to Original AEP
			//Writing the AEP
			if(!m_objTempFile.WriteAEP(m_pStructPecHostInfo->dwOrigAEP))
			{
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				m_pMaxPEFile=ctempFile;
				return false;
			}
		}

		m_pMaxPEFile=ctempFile;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		free(byDestbuff);
		byDestbuff=NULL;
		return true;
	}
	__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception caught in PECompact Unpacking:Main Code"), m_pMaxPEFile->m_szFilePath, false))
	{
	}

	return true;
}

bool CPECompactUnpack::ResolveAddresses(DWORD dwImportRVA)
{
	BYTE byBuff[0x14]={0x00};
	DWORD dwIncrements=0x00;

	while(1)
	{
		if(m_objTempFile.ReadBuffer(byBuff,dwImportRVA,0x14,0x14))
		{
			dwIncrements=0x00;
			if(*(DWORD*)&byBuff[0]!=0x00 && *(DWORD*)&byBuff[0]<m_objTempFile.m_dwFileSize)
			{

				while(1)
				{
					if(!m_objTempFile.ReadBuffer(&byBuff[4],*(DWORD*)&byBuff[0]+dwIncrements,0x04,0x04))
					{
						return true;
					}
					if(*(DWORD*)&byBuff[4]==0x00 ||(*(DWORD*)&byBuff[4]&0x7FFFFFFF)>m_objTempFile.m_dwFileSize)
					{
						dwImportRVA+=0x14;
						break;
					}
					if(!m_objTempFile.WriteBuffer(&byBuff[4],*(DWORD*)&byBuff[0x10]+dwIncrements,0x04,0x04))
					{
						return true;
					}
					dwIncrements+=0x04;
				}
			}
			else
			{
				break;
			}

		}
		else
		{
			break;
		}
	}
	return true;	
}


bool CPECompactUnpack::ResolveFilter(void)
{
	BYTE *byResolveBuff=NULL;
	DWORD dwSize=0;
	if(!(byResolveBuff=(BYTE*)MaxMalloc(0x50)))
	{
		return false;
	}
	memset(byResolveBuff,0,dwSize);

	DWORD dwCounter=0x00;
	while(1)
	{

		if(!m_objTempFile.ReadBuffer(byResolveBuff,m_pStructPecBlockInfo->dwRVASource+dwSize,0x50,0x50))
		{
			free(byResolveBuff);
			byResolveBuff=NULL;
			return false;
		}

		for(dwCounter=0x00;dwCounter<=0x46;dwCounter+=4)
		{
			if(*(DWORD*)&byResolveBuff[dwCounter]!=0x00)
			{
				if(!m_objTempFile.WriteBuffer(&m_pStructPecBlockInfo->wFilterIndex,*(DWORD*)&byResolveBuff[dwCounter],sizeof(WORD),sizeof(WORD)))
				{
					if(byResolveBuff)
					{
						free(byResolveBuff);
						byResolveBuff=NULL;
						return false;
					}
				}
			}
			else if(*(DWORD*)&byResolveBuff[dwCounter]==0x00)
			{
				break;
			}
		}
		if(*(DWORD*)&byResolveBuff[dwCounter]==0x00)
		{
			break;
		}
		dwSize+=0x50;
	}

	free(byResolveBuff);
	byResolveBuff=NULL;
	return true;
}



bool CPECompactUnpack::ResolveE8E9Calls(BYTE *byBuff)
{
	if(!m_objTempFile.ReadBuffer(byBuff,m_pStructPecBlockInfo->dwRVASource,m_pStructPecBlockInfo->dwBlockCSize,m_pStructPecBlockInfo->dwBlockCSize))
	{
		return false;
	}

	for(DWORD dwCounter=0;dwCounter<=m_pStructPecBlockInfo->dwBlockCSize-0x05;dwCounter++)
	{
		//Checking for E8 and E9
		if((byBuff[dwCounter]==0xE8 && BYTE(*(DWORD*)&byBuff[dwCounter+0x01])==BYTE(m_pStructPecBlockInfo->wFilterIndex)) || (byBuff[dwCounter]==0xE9 && BYTE(*(DWORD*)&byBuff[dwCounter+0x01])==BYTE(m_pStructPecBlockInfo->wFilterIndex>>8)) )
		{
			DWORD dwtemp=*(DWORD*)&byBuff[dwCounter+0x01];
			dwtemp=(dwtemp&0xFFFF0000)|((WORD)dwtemp>>8);
			*(DWORD*)&byBuff[dwCounter+0x01]=(dwtemp<<16|dwtemp>>16);
			*(DWORD*)&byBuff[dwCounter+0x01]=(*(DWORD*)&byBuff[dwCounter+0x01]&0xFFFF0000)|((*(DWORD*)&byBuff[dwCounter+0x01]&0xFF)<<0x08)|((*(DWORD*)&byBuff[dwCounter+0x01]&0xFF00)>>0x08);
			*(DWORD*)&byBuff[dwCounter+0x01]-=dwCounter;
			dwCounter+=0x04;
		}
	}

	if(!m_objTempFile.WriteBuffer(byBuff,m_pStructPecBlockInfo->dwRVASource,m_pStructPecBlockInfo->dwBlockCSize,m_pStructPecBlockInfo->dwBlockCSize))
	{
		return false;
	}


	return true;
}




bool CPECompactUnpack::CheckAlgorithm(WORD wNoOfDecoders,DWORD dwDecompressionAlgoOffset,BYTE *byLoaderbuff,DWORD *dwDestSize,BYTE *byDestbuff,bool bType,bool bAddMoreBytestoSource,DWORD dwAddMoreBytesOffset,DWORD dwAddMoreBytesCount,bool bUseEarlierDecompression,bool bUseVirtualSizeforSource)
{

	const BYTE byLZMA1Sig[] = {0xE9 , 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x34, 0x8B, 0x45, 0x08, 0x8B, 0x48, 0x08 ,0x33};
	const BYTE byLZMA12Sig[] = {0xE9, 0x83, 0xEC, 0x2C, 0x8B, 0x44, 0x24, 0x30, 0x8B, 0x48, 0x08, 0x55, 0x56};
	const BYTE byLZMA13Sig[] = {0xE9 , 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x3C};
	const BYTE byLZMA21Sig[]= {0xE9 , 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x34, 0x8B, 0x45, 0x08, 0x8B, 0x48, 0x08 ,0x83};
	const BYTE byLZMA22Sig[] = {0xE9, 0x83, 0xEC, 0x30, 0x8B, 0x44, 0x24, 0x34, 0x8B, 0x48, 0x08, 0x53, 0x55, 0x56};
	const BYTE byLZMA23Sig[]= {0xE9 , 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x30, 0x8B, 0x45, 0x08, 0x8B, 0x48, 0x08 ,0x53};
	const BYTE byLZMA24Sig[]= {0x56,0x57,0x53,0x55,0x8B,0x5C,0x24,0x1C,0x85,0xDB};
	const BYTE bySimpleMoveAlgo[] ={0x56, 0x57, 0x53, 0x8B, 0x74, 0x24, 0x10, 0x8B, 0x7C, 0x24, 0x14, 0xFC, 0x8B, 0x0E};
    const BYTE bySimpleMoveAlgo1[] ={0x55, 0x8B, 0xEC, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB};
	const BYTE byFFCESig[] = {0x60, 0x8B, 0x74, 0x24, 0x24, 0x8B, 0x7C, 0x24, 0x28, 0xFC, 0xAD, 0x33, 0xC9};
	const BYTE byFFCESig2[] = {0x56, 0x57, 0x53, 0x55, 0x8B, 0x74, 0x24, 0x14, 0x8B, 0x7C, 0x24, 0x18, 0xFC,0x8B,0x1E};
	const BYTE byFFCESig3[] = {0x53, 0x56, 0x57, 0x8B, 0x74, 0x24, 0x10, 0x8B, 0x7C, 0x24, 0x14, 0xFC,0x8B,0x1E};
	const BYTE byAPLIBSig[] ={0x60, 0x8B, 0x74, 0x24, 0x24, 0x8B, 0x7C, 0x24, 0x28, 0xFC, 0xB2, 0x80, 0x33, 0xDB}; //Normal APLIB
	const BYTE byAPLIBSig3[] = {0x56, 0x57, 0x53, 0x55, 0x8B, 0x74, 0x24, 0x14, 0x8B, 0x7C, 0x24, 0x18, 0xFC,0xBA,0x00};
	const BYTE byJCALG1Sig[] ={0x55, 0x8B, 0xEC , 0x53, 0x57, 0x56, 0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x8};	
	const BYTE byAPLIBSig1[] ={0x56, 0x57, 0x53, 0x55, 0x8B, 0x74, 0x24, 0x14, 0x8B, 0x7C, 0x24, 0x18, 0xFC, 0xB2,0x80};
	const BYTE byAPLIBSig2[] ={0x60, 0x8B, 0x74, 0x24, 0x24, 0x8B, 0x7C, 0x24, 0x28, 0xFC, 0x33, 0xDB, 0x33, 0xD2}; //Modified APLIB
	// Trojan.Win32.VBKrypt.irlc
	const BYTE byXORSUB[] = {0x55,0x8B,0xEC,0x8B,0x45,0x08,0x8B,0x10,0x53,0x8D,0x48,0x04,0x8B,0x01,0x56,0x8B};
	const BYTE byCryptHash[] ={0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x56, 0x83, 0xA5};
	const BYTE byCryptHash2[] ={0x55, 0x8D, 0x6C, 0x24, 0x81, 0xEC};

	if(!bUseEarlierDecompression)
	{
		if((memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byLZMA1Sig,0x01)==0) && (memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+0x05],byLZMA1Sig+0x01,sizeof(byLZMA1Sig)-1)==0))
		{
			m_eDLLCompress=LZMA;
		}
		else if((memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byLZMA12Sig,0x01)==0) && (memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+0x05],byLZMA12Sig+0x01,sizeof(byLZMA12Sig)-1)==0))
		{
			m_eDLLCompress=LZMA;
		}
		else if((memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byLZMA13Sig,0x01)==0) && (memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+0x05],byLZMA13Sig+0x01,sizeof(byLZMA13Sig)-1)==0))
		{
			m_eDLLCompress=LZMA;
		}
		else if((memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byLZMA21Sig,0x01)==0) && (memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+0x05],byLZMA21Sig+0x01,sizeof(byLZMA21Sig)-1)==0))
		{
			m_eDLLCompress=LZMA2;
		}
		else if((memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byLZMA22Sig,0x01)==0) && (memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+0x05],byLZMA22Sig+0x01,sizeof(byLZMA22Sig)-1)==0))
		{
			m_eDLLCompress=LZMA2;
		}
		else if((memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byLZMA23Sig,0x01)==0) && (memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+0x05],byLZMA23Sig+0x01,sizeof(byLZMA23Sig)-1)==0))
		{
			m_eDLLCompress=LZMA2;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byLZMA24Sig,sizeof(byLZMA24Sig))==0)
		{
			m_eDLLCompress=LZMAMod;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byFFCESig,sizeof(byFFCESig))==0)
		{
			m_eDLLCompress=FFCE;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byAPLIBSig1,sizeof(byAPLIBSig1))==0)
		{
			m_eDLLCompress=APLIB;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byAPLIBSig2,sizeof(byAPLIBSig2))==0)
		{
			m_eDLLCompress=APLIBMod;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byFFCESig2,sizeof(byFFCESig2))==0)
		{
			m_eDLLCompress=FFCEMod;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byFFCESig3,sizeof(byFFCESig3))==0)
		{
			m_eDLLCompress=FFCEMod2;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byAPLIBSig,sizeof(byAPLIBSig))==0)
		{
			m_eDLLCompress=APLIB;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byAPLIBSig3,sizeof(byAPLIBSig3))==0)
		{
			m_eDLLCompress=APLIBMod;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byJCALG1Sig,sizeof(byJCALG1Sig))==0)
		{
			m_eDLLCompress=JCALG1;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],bySimpleMoveAlgo,sizeof(bySimpleMoveAlgo))==0)
		{
			m_eDLLCompress=SimpleMove;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],bySimpleMoveAlgo1,sizeof(bySimpleMoveAlgo1))==0)
		{
			m_eDLLCompress=SimpleMove;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byXORSUB,sizeof(byXORSUB))==0)
		{
			m_eDLLCompress=XORSUB;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byCryptHash,sizeof(byCryptHash)-3)==0) //&&
			   /* memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+9],&byCryptHash[sizeof(byCryptHash)-3],1)==0)*/
		{
			m_eDLLCompress=CryptHashADVAPI;

		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byCryptHash,sizeof(byCryptHash)-5)==0 &&
			    (*(DWORD*)&byLoaderbuff[dwDecompressionAlgoOffset+0x03]==0x81F8E483 && byLoaderbuff[dwDecompressionAlgoOffset+0x07]==0xEC))
		{
			m_eDLLCompress=CryptHashADVAPI;
		}
		else if(memcmp(&byLoaderbuff[dwDecompressionAlgoOffset],byCryptHash2,sizeof(byCryptHash2)-2)==0 &&
			    memcmp(&byLoaderbuff[dwDecompressionAlgoOffset+5],&byCryptHash2[sizeof(byCryptHash2)-2],2)==0)
		{
			m_eDLLCompress=CryptHashADVAPI;
		}
		else
		{
			return false;
		}	
	}



	DWORD dwSrcSize=0x00,dwtDestSize=0x00,dwRead=0x00,dwWrite=0x00;
	static BYTE* byDestbuff2=NULL;
	if(bType)
	{
		if(bUseVirtualSizeforSource)
		{
			WORD wSec=0xFF;
			wSec=m_objTempFile.Rva2FileOffset(m_pStructPecBlockInfo->dwRVASource,&m_pStructPecBlockInfo->dwRVASource);
			if(wSec==0xFF)
			{
				return false;
			}
			dwSrcSize=m_objTempFile.m_stSectionHeader[wSec].Misc.VirtualSize;

		}
		else
		{
			dwSrcSize=m_pStructPecBlockInfo->dwBlockCSize-m_pStructPecBlockInfo->dwOverKillSize;
		}
		dwtDestSize=m_pStructPecHostInfo->dwWorkingMemoryRequired;
		dwRead=m_pStructPecBlockInfo->dwRVASource;
		dwWrite=m_pStructPecBlockInfo->dwRVADest;

		if(wNoOfDecoders==0x02)
		{
			if(!(byDestbuff2=(BYTE*)MaxMalloc(m_pStructPecHostInfo->dwWorkingMemoryRequired)))
			{
				return false;
			}
		}

		if(wNoOfDecoders>0x01 && (wNoOfDecoders%0x02)==0x01)
		{
			/*if(dwSrcSize>m_pStructPecHostInfo->dwWorkingMemoryRequired)
			{
				dwSrcSize=
				if(byDestbuff2)
				{
					free(byDestbuff2);
					byDestbuff2=NULL;
				}
				return false;
			}*/
			for (DWORD i=0;i<m_pStructPecHostInfo->dwWorkingMemoryRequired;i++)
			{
				byDestbuff2[i]=byDestbuff[i];
			}
			dwRead=0x00;
		}
	}
	else
	{
		byDestbuff2=NULL;
		dwSrcSize=m_objStructLdrDcdrInfo.dwRvaDecoder-m_objStructLdrDcdrInfo.dwRvaCompressedLoader;
		dwtDestSize=m_objStructLdrDcdrInfo.dwUncompressedLoaderSize;
		dwRead=m_objStructLdrDcdrInfo.dwRvaCompressedLoader;
		dwWrite=0x00;
	}



	switch(m_eDLLCompress)
	{
	case APLIB:
		{
			if(!(~(*dwDestSize=APLIBDecompress(dwSrcSize,dwtDestSize,dwRead,dwWrite,byDestbuff,0,byDestbuff2))))
			{
				if(byDestbuff2)
				{
					free(byDestbuff2);
					byDestbuff2=NULL;
				}
				return false;
			}
			break;
		}
	case APLIBMod:
		{
			if(!(~(*dwDestSize=APLIBDecompress(dwSrcSize,dwtDestSize,dwRead,dwWrite,byDestbuff,0x2,byDestbuff2))))
			{
				if(byDestbuff2)
				{
					free(byDestbuff2);
					byDestbuff2=NULL;
				}
				return false;
			}
			break;
		}

	case LZMA:
	case LZMAMod:
		{
			BYTE byLZMAProp[15] = {0};
			if(m_eDLLCompress==LZMA)
			{
				if(!m_objTempFile.ReadBuffer(&byLZMAProp[3],dwRead+0x04,0x01,0x01))
				{
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}
				byLZMAProp[0]=byLZMAProp[3]%0x09;
				byLZMAProp[3]/=9;
				byLZMAProp[1]=byLZMAProp[3]%5;
				byLZMAProp[2]=byLZMAProp[3]/5;
				dwRead+=0x02;
			}
			else
			{
				if(!m_objTempFile.ReadBuffer(byLZMAProp,dwRead,sizeof(byLZMAProp),sizeof(byLZMAProp)))
				{
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}
				if(dwtDestSize<*(DWORD*)&byLZMAProp[4])
				{
					if(*(DWORD*)&byLZMAProp[4] > 10 * 1024 * 1024 || !(byDestbuff=(BYTE*)realloc(byDestbuff,*(DWORD*)&byLZMAProp[4])))
					{
						if(byDestbuff2)
						{
							free(byDestbuff2);
							byDestbuff2=NULL;
						}
						return false;
					}
					memset(byDestbuff,0x00,*dwDestSize);
				}
				dwSrcSize=*(DWORD*)&byLZMAProp[8];
				byLZMAProp[0]=byLZMAProp[0xE];
				byLZMAProp[1]=byLZMAProp[0xD];
				byLZMAProp[2]=byLZMAProp[0xC];
			}
			DWORD dwSrcRead=0x00;
			if(dwRead==0x00)
			{
				dwSrcRead=0x00;
			}
			else
			{
				dwSrcRead=dwRead+0x0F;
			}
			if(!(*dwDestSize=LZMADecompress(byLZMAProp,dwSrcSize,dwtDestSize,dwSrcRead,dwWrite,byDestbuff,&byDestbuff2[0x0F])))
			{
				if(byDestbuff2)
				{
					free(byDestbuff2);
					byDestbuff2=NULL;
				}
				return false;
			}

			break;
		}

	case FFCE:
	case FFCEMod:
	case FFCEMod2:
		{
			bool bFFCEMd=false;
			BYTE *bySrcbuff = NULL;
			if(bAddMoreBytestoSource && dwAddMoreBytesCount)
			{
				dwSrcSize+=dwAddMoreBytesCount;
			}
			if(dwRead!=0x00)
			{
				if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSrcSize)))
				{
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}

				if(!m_objTempFile.ReadBuffer(bySrcbuff,dwRead,dwSrcSize-dwAddMoreBytesCount,dwSrcSize-dwAddMoreBytesCount))
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}
				if(bAddMoreBytestoSource && dwAddMoreBytesCount)
				{
					memcpy(&bySrcbuff[dwSrcSize-dwAddMoreBytesCount],&byLoaderbuff[dwAddMoreBytesOffset],dwAddMoreBytesCount);
				}
			}
			else
			{
				bySrcbuff=byDestbuff2;
			}

			/*if(m_eDLLCompress==FFCEMod2)
			dwSrcSize=*(DWORD*)&bySrcbuff[0x0];
			else*/
			*dwDestSize=*(DWORD*)&bySrcbuff[0x0];

			
			if(*dwDestSize>dwtDestSize)
			{
				if(!(byDestbuff=(BYTE*)realloc(byDestbuff,*dwDestSize)))
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}
				memset(byDestbuff,0x00,*dwDestSize);
			}

			if(m_eDLLCompress==FFCEMod)
			{
				if(*(DWORD*)&byLoaderbuff[dwDecompressionAlgoOffset+0x16]==0xE6)
				{
					bFFCEMd=true;
				}
			}
			if(m_eDLLCompress==FFCEMod2)
			{
				if(!LZSSModUncompress(dwSrcSize-0x04,dwDestSize,dwRead,0x00,NULL,NULL,&bySrcbuff[0x04],byDestbuff))
				{
					if(dwRead!=0x00)
					{
						free(bySrcbuff);
						if(byDestbuff2)
						{
							free(byDestbuff2);
							byDestbuff2=NULL;
						}
					}
					bySrcbuff=NULL;
					return false;
				}

			}
			else if(!LZSSUncompress(dwSrcSize-0x04,dwDestSize,dwRead,0x00,NULL,NULL,&bySrcbuff[0x04],byDestbuff,bFFCEMd))
			{
				if(dwRead!=0x00)
				{
					free(bySrcbuff);	
				}
				if(byDestbuff2)
				{
					free(byDestbuff2);
					byDestbuff2=NULL;
				}
				bySrcbuff=NULL;
				return false;
			}

			if(dwRead!=0x00)
			{
				free(bySrcbuff);
			}
			bySrcbuff=NULL;
			break;
		}

	case SimpleMove:
		{
			BYTE *bySrcbuff = NULL;
			if(dwRead!=0x00)
			{
				if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSrcSize)))
				{
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}

				if(!m_objTempFile.ReadBuffer(bySrcbuff,dwRead,dwSrcSize,dwSrcSize))
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}
			}
			else
			{
				bySrcbuff=byDestbuff2;
			}

			for(DWORD i=0;i<*(DWORD*)&bySrcbuff[0];i++)
			{
				byDestbuff[i]=bySrcbuff[i+0x04];
			}
			*dwDestSize=*(DWORD*)&bySrcbuff[0];

			if(dwRead!=0x00)
			{
				free(bySrcbuff);
			}
			bySrcbuff=NULL;
			break;
		}
	    case XORSUB:
		{
			BYTE *bySrcbuff = NULL;
			if(dwRead!=0x00)
			{
				if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSrcSize)))
				{
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}

				if(!m_objTempFile.ReadBuffer(bySrcbuff,dwRead,dwSrcSize,dwSrcSize))
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}
			}
			else
			{
				bySrcbuff=byDestbuff2;
			}
			DWORD dwXORKey=*(DWORD*)&bySrcbuff[0]-*(DWORD*)&byLoaderbuff[dwDecompressionAlgoOffset+0x18];
			DWORD dwSrcSize=*(DWORD*)&bySrcbuff[0x4]-0x03;

			for(DWORD i=0;i<=(dwSrcSize-4);i+=4)
			{
				*(DWORD*)&byDestbuff[i]=*(DWORD*)&bySrcbuff[i+0x08]^dwXORKey;
				*(DWORD*)&byDestbuff[i]-=dwXORKey;
			}
			*dwDestSize=dwSrcSize;

			if(dwRead!=0x00)
			{
				free(bySrcbuff);
			}
			bySrcbuff=NULL;		
			break;
		}

		case CryptHashADVAPI:
		{
			if(dwRead !=0x00)
			{
				CEmulate objEmulate(m_pMaxPEFile);
				if(!objEmulate.IntializeProcess(true))
				{
					return false;
				}
				DWORD m_dwFirstAllocAddress	= objEmulate.AddVirtualPointer((DWORD)byLoaderbuff, 1,m_objStructLdrDcdrInfo.dwUncompressedLoaderSize);
				objEmulate.SetEip(m_dwFirstAllocAddress+dwDecompressionAlgoOffset);
				objEmulate.SetNoOfIteration(0x1000);
				bool bFlag=true;
				int RegisterIndex=0;
				//objEmulate.SetBreakPoint("__isinstruction('lea eax ,dword ptr [ebp + 0fffffd60h]')");
				objEmulate.SetBreakPoint("__isinstruction('call dword ptr [e')");

                LabelEmulate:
				if(7 == objEmulate.EmulateFile())
				{
					objEmulate.SetEip(objEmulate.GetEip()+0x02 + DWORD(!bFlag));
					DWORD dwOffset=objEmulate.GetEip()-(m_dwFirstAllocAddress);
					DWORD dwLength = 0, dwInstructionCountFound = 0;
					char	szInstruction[1024] = {0x00};
					while(dwOffset+0x30 <= m_objStructLdrDcdrInfo.dwUncompressedLoaderSize)
					{

						dwLength = objEmulate.DissassemBuffer((char*)&byLoaderbuff[dwOffset],szInstruction);
						if(strstr(szInstruction,"JNZ") && dwLength==0x02)
						{
							dwOffset+=byLoaderbuff[dwOffset+1];
						}

						else if( (bFlag && strstr(szInstruction,"MOV BYTE PTR [EBP +") && dwLength==0x07) ||
							(bFlag && strstr(szInstruction,"MOV BYTE PTR [ESP +") && dwLength==0x08 && (RegisterIndex=1)) )						
						{
							bFlag=false;
							objEmulate.SetEip(dwOffset+m_dwFirstAllocAddress);
							goto LabelEmulate;
						}

						else if(dwInstructionCountFound==0 && strstr(szInstruction,"PUSH 8003H") && dwLength==0x05)
						{
							dwInstructionCountFound++;
						}

						else if(dwInstructionCountFound==1 && strstr(szInstruction,"PUSH") && dwLength==0x05)
						{
							if(byLoaderbuff[dwOffset+0x05]==0x8D && byLoaderbuff[dwOffset+0x06]==0x85-RegisterIndex)
							{
								DWORD dwHashSize=*(DWORD*)&byLoaderbuff[dwOffset+0x01];
								BYTE *byHashbuff=NULL;
								if(!(byHashbuff=(BYTE*)MaxMalloc(dwHashSize)))
								{
									return false;
								}

								if(!objEmulate.ReadEmulateBuffer(byHashbuff,dwHashSize,objEmulate.GetSpecifyRegValue(5-RegisterIndex)+*(DWORD*)&byLoaderbuff[dwOffset+0x07+RegisterIndex]+(RegisterIndex*0x04)))
								{
									return false;
								}

								HCRYPTPROV hProv;
								HCRYPTHASH hHash;
								HCRYPTKEY  hKey;

								if(0==CryptAcquireContextA(&hProv,NULL,NULL,1,0))
								{
									return false;
								}

								if(0==CryptCreateHash(hProv,0x8003,0,0,&hHash))
								{
									return false;
								}

								if(0==CryptHashData(hHash,byHashbuff,dwHashSize,0))
								{
									return false;
								}

								if(0==CryptDeriveKey(hProv,0x6601,hHash,1,&hKey))
								{
									return false;
								}

								DWORD dwActualDestSize=0;
								if(!m_objTempFile.ReadBuffer(&dwActualDestSize,dwRead+0x04,0x04))
								{
									return false;
								}

								if(dwActualDestSize>dwtDestSize)
								{
									if(!(byDestbuff=(BYTE*)realloc(byDestbuff,dwActualDestSize)))
									{
										if(byDestbuff2)
										{
											free(byDestbuff2);
											byDestbuff2=NULL;
										}
										return false;
									}
									memset(byDestbuff,0x00,dwActualDestSize);
								}

								if(!m_objTempFile.ReadBuffer(byDestbuff,dwRead+0x08,dwActualDestSize))
								{
									return false;
								}

								if(0==CryptDecrypt(hKey,0,1,0,byDestbuff,&dwActualDestSize))
								{
									return false;
								}
								*dwDestSize=dwActualDestSize;
								
								if(0== CryptDestroyKey(hKey))
								{
									return false;
								}

								if(0 == CryptDestroyHash(hHash))
								{
									return false;
								}

								if(0 == CryptReleaseContext(hProv,0))
								{
									return false;
								}
								break;
							}

						}

						dwOffset+=dwLength;
					}


				}
				else
				{
					return false;
				}
				break;
			}
			else
				return false;
		}
	case LZMA2:
	case JCALG1:
		{
#ifndef WIN64	
			if(!LoadDLLs(m_eDLLCompress))
			{
				return false;
			}

			BYTE *bySrcbuff = NULL;
			if(dwRead!=0x00)
			{
				if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSrcSize)))
				{
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}

				if(!m_objTempFile.ReadBuffer(bySrcbuff,dwRead,dwSrcSize,dwSrcSize))
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					if(byDestbuff2)
					{
						free(byDestbuff2);
						byDestbuff2=NULL;
					}
					return false;
				}
			}
			else
			{
				bySrcbuff=byDestbuff2;
			}

			DWORD dwOut = 0;
			/*__try*/
			{
				*dwDestSize = m_PEBundle[m_eDLLCompress].lpfnDecodeSmall(bySrcbuff, byDestbuff, &m_DecoderExtra);
			}
			//__except(CMaxExceptionFilter::Filter(GetExceptionCode(), GetExceptionInformation(),_T("Exception caught in PECompact Unpacking"), m_pMaxPEFile->m_szFilePath, false))
			{
			}
			if(*dwDestSize >  dwtDestSize)
			{
				if(dwRead!=0x00)
				{
					free(bySrcbuff);	
				}
				if(byDestbuff2)
				{
					free(byDestbuff2);
					byDestbuff2=NULL;
				}
				bySrcbuff=NULL;
				return false;
			}

			if(dwRead!=0x00)
			{
				free(bySrcbuff);
			}
			bySrcbuff=NULL;
			break;
#else
			return false;
#endif
		}
	}
	if(*dwDestSize != 0x00 && bType && (wNoOfDecoders==0x01||(wNoOfDecoders%0x02)==0x01))
	{	
		if(wNoOfDecoders==m_pStructPecHostInfo->wTotalDecoders)
		{
			if(byDestbuff2)
			{
				free(byDestbuff2);
				byDestbuff2=NULL;
			}
		}
		if(!m_objTempFile.WriteBuffer(byDestbuff, dwWrite, *dwDestSize, *dwDestSize))
		{
			if(byDestbuff2)
			{
				free(byDestbuff2);
				byDestbuff2=NULL;
			}
			return false;
		}
		
	}

	if(bType && wNoOfDecoders==m_pStructPecHostInfo->wTotalDecoders && wNoOfDecoders%0x02==0x00)
	{
		if(byDestbuff2)
		{
			free(byDestbuff2);
			byDestbuff2=NULL;
		}
		if(!m_objTempFile.WriteBuffer(byDestbuff, dwWrite, *dwDestSize, *dwDestSize))
		{
			
			return false;
		}
	}
	return true;
}



