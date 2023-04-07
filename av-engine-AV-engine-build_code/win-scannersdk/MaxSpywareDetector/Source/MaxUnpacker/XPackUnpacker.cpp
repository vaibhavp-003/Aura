#include "XPackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CXPackUnpacker::CXPackUnpacker(CMaxPEFile *pMaxPEFile):CUnpackBase(pMaxPEFile)
{	
	m_dw2Sections = 0x01;//By default set true
}

CXPackUnpacker::~CXPackUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CXPackUnpacker::IsPacked() 
{
	if((memcmp(m_pMaxPEFile->m_stSectionHeader[0].Name, m_pMaxPEFile->m_stSectionHeader[1].Name, strlen((const char *)m_pMaxPEFile->m_stSectionHeader[0].Name) - 0x01))||
		((memcmp(m_pMaxPEFile->m_stSectionHeader[0].Name, m_pMaxPEFile->m_stSectionHeader[2].Name, strlen((const char *)m_pMaxPEFile->m_stSectionHeader[0].Name) - 0x01))))
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}

		BYTE byXPackbuff[0x4] = {0x68, 0x9C, 0x60, 0xE8};
		if(m_pMaxPEFile->ReadBuffer(m_pbyBuff, m_pMaxPEFile->m_dwAEPMapped, sizeof(byXPackbuff) + 0x08, sizeof(byXPackbuff) + 0x08))
		{
			if(m_pbyBuff[0] == 0x68)
			{
				if(memcmp(&m_pbyBuff[5], &byXPackbuff[1], sizeof(byXPackbuff) - 0x01) == 0x00 && 
					(((*(DWORD *)&m_pbyBuff[8] == 0x62D) || (*(DWORD *)&m_pbyBuff[8] == 0x6BB)) && 
					(m_eCompressionType = LZMA_XPack)) || (((*(DWORD*)&m_pbyBuff[8] == 0x297) || 
					(*(DWORD*)&m_pbyBuff[8] == 0x325)) && (m_eCompressionType=LZSS_XPack)) ||
					(*(DWORD*)&m_pbyBuff[8]==0x2E5&& (m_eCompressionType=LZSS_XComp)) || 
					(*(DWORD*)&m_pbyBuff[8]==0x675&& (m_eCompressionType=LZMA_XPackMod)))
				{
					m_dwOriAEP = *(DWORD *)&m_pbyBuff[1];
					if(*(DWORD *)&m_pbyBuff[1] > m_dwImageBase)
					{
						m_dwOriAEP -= m_dwImageBase;
						m_dw2Sections = 0x00;
					}
					m_dwOffset = *(DWORD*)&m_pbyBuff[8];
					return true;
				}
			}
		}
	}
	return false;
}


bool CXPackUnpacker::Unpack(LPCTSTR szTempFileName)
{	
	DWORD dwSize = 0x14;
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections == 0x02)
	{
		dwSize += 0x08;
	}
	BYTE *UnpackInfo = NULL;
	if(!(UnpackInfo = (BYTE *)MaxMalloc(dwSize)))
	{
		return false;
	}

	DWORD dwUnpackInfo = m_pMaxPEFile->m_dwAEPMapped + 0x0C + m_dwOffset + 0x05;
	if(!m_pMaxPEFile->ReadBuffer(UnpackInfo, dwUnpackInfo, dwSize, dwSize))
	{
		free(UnpackInfo);
		UnpackInfo = NULL;
		return false;
	}
	DWORD dwNoOfSectionsToDecompress = *(DWORD *)&(UnpackInfo[0x10 + (m_dw2Sections * 0x08)]);
	if(dwNoOfSectionsToDecompress == 0x00)
	{
		free(UnpackInfo);
		UnpackInfo = NULL;
		return false;
	}
	DWORD dwOffset=dwSize+dwNoOfSectionsToDecompress*0x08+0x0C-(m_dw2Sections*0x0C);
	if(m_eCompressionType==LZSS_XComp)
	{
		dwOffset-=0x0C;
	}
	if(dwOffset > 10 * 1024 * 1024)
	{
		free(UnpackInfo);
		UnpackInfo=NULL;
		return false;
	}

	if(!(UnpackInfo=(BYTE*)realloc(UnpackInfo,dwOffset)))
	{
		free(UnpackInfo);
		UnpackInfo=NULL;
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(&UnpackInfo[dwSize],dwUnpackInfo+dwSize,dwOffset-dwSize,dwOffset-dwSize))
	{
		free(UnpackInfo);
		UnpackInfo=NULL;
		return false;
	}

	if(!ReOrganizeFile(szTempFileName))
	{
		free(UnpackInfo);
		UnpackInfo=NULL;
		return false;
	}
	BYTE byLZMAProp[4]={0};
	DWORD dwSrcSize;
	DWORD dwDesSize;
	DWORD dwRead;
	DWORD dwWrite;
	DWORD dwIncrement;
	DWORD dwToCompareResolve=0x00;
	BYTE *byResolveCallsbuff=NULL;
	BYTE *byCallsbuff=NULL;

	dwUnpackInfo+=dwSize+dwNoOfSectionsToDecompress*0x08;
	dwRead=dwUnpackInfo;


	if(!m_pMaxPEFile->ReadBuffer(&dwIncrement,dwRead,sizeof(DWORD),sizeof(DWORD)))
	{
		free(UnpackInfo);
		UnpackInfo=NULL;	
		return false;
	}
	dwRead+=(dwIncrement*0x08)+0x04;

	for(DWORD dwCounter=0;dwCounter<dwNoOfSectionsToDecompress;dwCounter++)
	{		
		if(m_eCompressionType==LZSS_XComp)
		{
			if(m_pMaxPEFile->Rva2FileOffset(*(DWORD*)&(UnpackInfo[dwSize+dwCounter*0x08])-(m_dwImageBase*(!m_dw2Sections)),&dwRead)==0xFF)
			{
			  free(UnpackInfo);
			  UnpackInfo=NULL;
			  return false;
			}
		}
		//If m_dw2Sections=true then we have to subtract Image Base also
		dwWrite=*(DWORD*)&(UnpackInfo[dwSize+dwCounter*0x08])-(m_dwImageBase*(!m_dw2Sections));
		//For the last loop run
		if(dwCounter==dwNoOfSectionsToDecompress-0x01)
		{
			WORD wSec=m_pMaxPEFile->Rva2FileOffset(*(DWORD*)&(UnpackInfo[dwSize+dwCounter*0x08])-(!m_dw2Sections*m_dwImageBase),NULL);
			if(wSec==0xFF)
			{
				free(UnpackInfo);
				UnpackInfo=NULL;
				return false;

			}
			dwDesSize=m_pMaxPEFile->m_stSectionHeader[wSec].Misc.VirtualSize+(!m_dw2Sections*m_dwImageBase)+m_pMaxPEFile->m_stSectionHeader[wSec].VirtualAddress-*(DWORD*)&(UnpackInfo[dwSize+dwCounter*0x08]);
		}
		//For all loop runs except last
		else
		{
			dwDesSize=*(DWORD*)&(UnpackInfo[dwSize+(dwCounter+1)*0x08])-*(DWORD*)&(UnpackInfo[dwSize+dwCounter*0x08]);
		}
		dwSrcSize=*(DWORD*)&(UnpackInfo[dwSize+(dwCounter)*0x08+0x04]);

		if(!(byResolveCallsbuff=(BYTE*)MaxMalloc(dwDesSize)))
		{
			free(UnpackInfo);
			UnpackInfo=NULL;
			return false;
		}

		if(m_eCompressionType==LZMA_XPack || m_eCompressionType==LZMA_XPackMod)
		{
			byLZMAProp[0]=8;
			byLZMAProp[1]=0;
			byLZMAProp[2]=2;
			
			if(m_eCompressionType == LZMA_XPackMod)
			{
				dwRead = dwWrite;
				if(OUT_OF_FILE==m_pMaxPEFile->Rva2FileOffset(dwRead,&dwRead))
				{
					free(byResolveCallsbuff);
					byResolveCallsbuff=NULL;
					free(UnpackInfo);
					UnpackInfo=NULL;
					return false;
				}
			}
			
			if(!m_pMaxPEFile->ReadBuffer(&dwIncrement,dwRead,sizeof(DWORD),sizeof(DWORD)))
			{
				free(UnpackInfo);
				UnpackInfo=NULL;
				return false;
			}
			dwSrcSize-=((dwIncrement*0x04)+0x04);

			if(!(dwDesSize=LZMADecompress(byLZMAProp,dwSrcSize,dwDesSize,dwRead+(dwIncrement*0x04)+0x04,0x00,byResolveCallsbuff)))
			{
				free(byResolveCallsbuff);
				byResolveCallsbuff=NULL;
				free(UnpackInfo);
				UnpackInfo=NULL;
				free(byCallsbuff);
				byCallsbuff=NULL;
				return false;
			}

			if(dwIncrement!=0x00)
			{
				if(!(byCallsbuff=(BYTE*)MaxMalloc(dwIncrement*0x04)))
				{
					free(byResolveCallsbuff);
					byResolveCallsbuff=NULL;
					free(UnpackInfo);
					UnpackInfo=NULL;
					return false;
				}
				if(!m_pMaxPEFile->ReadBuffer(byCallsbuff,dwRead+0x04,dwIncrement*0x04,dwIncrement*0x04))
				{
					free(byResolveCallsbuff);
					byResolveCallsbuff=NULL;
					free(UnpackInfo);
					UnpackInfo=NULL;
					free(byCallsbuff);
					byCallsbuff=NULL;
					return false;
				}

				if(!ResolveCalls(byResolveCallsbuff,dwDesSize,byCallsbuff,dwIncrement))
				{
					free(UnpackInfo);
					UnpackInfo=NULL;
					free(byResolveCallsbuff);
					byResolveCallsbuff=NULL;
					free(byCallsbuff);
					byCallsbuff=NULL;
					return false;
				}
			}

		}
		else if(m_eCompressionType==LZSS_XPack || m_eCompressionType==LZSS_XComp)
		{
			BYTE *bySrcbuff=NULL;
			if(!(bySrcbuff = (BYTE *)MaxMalloc(dwSrcSize)))
			{
				return false;
			}
			memset(bySrcbuff, 0x00, dwSrcSize);
			if(!m_pMaxPEFile->ReadBuffer(bySrcbuff,dwRead,dwSrcSize,dwSrcSize))
			{
				free(UnpackInfo);
				UnpackInfo=NULL;
				free(byResolveCallsbuff);
				byResolveCallsbuff=NULL;
				byCallsbuff=NULL;
				free(bySrcbuff);
				bySrcbuff=NULL;
				return false;
			}

			//Performing XOR
			for(DWORD i=0;i<(dwSrcSize-1);i++)
			{
				bySrcbuff[i+1]^=bySrcbuff[i];
			}

			if((*(DWORD*)&(bySrcbuff[0]))*0x04+0x04 > dwSrcSize)
			{
				free(UnpackInfo);
				UnpackInfo=NULL;
				free(byResolveCallsbuff);
				byResolveCallsbuff=NULL;
				byCallsbuff=NULL;
				free(bySrcbuff);
				bySrcbuff=NULL;
				return false;
			}

			//If the initial Allocated dessize<the actual destsize kept in code then realloc
			if(dwDesSize<*(DWORD*)&(bySrcbuff[(*(DWORD*)&(bySrcbuff[0]))*0x04+0x04]))
			{
				if((*(DWORD*)&(bySrcbuff[0]))*0x04+0x04 < dwSrcSize)
				{
					free(UnpackInfo);
					UnpackInfo=NULL;
					free(byResolveCallsbuff);
					byResolveCallsbuff=NULL;
					byCallsbuff=NULL;
					free(bySrcbuff);
					bySrcbuff=NULL;
					return false;
				}

				//Allocating this size to destSize
			
				if(!(byResolveCallsbuff=(BYTE*)realloc(byResolveCallsbuff,*(DWORD*)&(bySrcbuff[(*(DWORD*)&(bySrcbuff[0]))*0x04+0x04]))))
				{
					free(UnpackInfo);
					UnpackInfo=NULL;
					free(byResolveCallsbuff);
					byResolveCallsbuff=NULL;
					byCallsbuff=NULL;
					free(bySrcbuff);
					bySrcbuff=NULL;
					return false;
				}
			}
			dwDesSize=*(DWORD*)&(bySrcbuff[(*(DWORD*)&(bySrcbuff[0]))*0x04+0x04]);
			memset(byResolveCallsbuff,0x0,dwDesSize);

			dwIncrement=*(DWORD*)&(bySrcbuff[0]);

			//LZSS Decompression
           	if(!LZSSUncompress(dwSrcSize,&dwDesSize,dwRead,0x00,m_pMaxPEFile,&dwIncrement,&bySrcbuff[*(DWORD*)&(bySrcbuff[0])*0x04+0x08],byResolveCallsbuff))
			{
				free(UnpackInfo);
				UnpackInfo=NULL;
				free(byResolveCallsbuff);
				byResolveCallsbuff=NULL;
				byCallsbuff=NULL;
				free(bySrcbuff);
				bySrcbuff=NULL;
				return false;
			}

			if(dwIncrement!=0x00)
			{
				if(!ResolveCalls(byResolveCallsbuff,dwDesSize,&bySrcbuff[0x04],dwIncrement))
				{
					free(bySrcbuff);
					bySrcbuff=NULL;
					return false;
				}
			}
			free(bySrcbuff);
			bySrcbuff=NULL;
		}

		//Writing in buffer the output

		if(!m_objTempFile.WriteBuffer(byResolveCallsbuff,dwWrite,dwDesSize,dwDesSize))
		{
			free(UnpackInfo);
			UnpackInfo=NULL;
			free(byResolveCallsbuff);
			byResolveCallsbuff=NULL;
			return false;
		}
		dwRead+=*(DWORD*)&(UnpackInfo[dwSize+(dwCounter)*0x08+0x04]);
		free(byResolveCallsbuff);
		byResolveCallsbuff=NULL;
		free(byCallsbuff);
		byCallsbuff=NULL;
	}

	dwRead=*(DWORD*)&(UnpackInfo[0x08]);
	if(m_dw2Sections==0x00)
	{
		dwRead-=m_dwImageBase;
		//Closing and opening the File again to reflect the changes
		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			free(UnpackInfo);
			UnpackInfo=NULL;
			return false;
		}

		if(!ResolveImportAddresses(dwRead))
		{
			free(UnpackInfo);
			UnpackInfo=NULL;
			return false;
		}
	}
	free(UnpackInfo);
	UnpackInfo=NULL;

	//To write in the Data Directory
	if(!m_objTempFile.WriteBuffer(&dwRead,m_objTempFile.m_stPEHeader.e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+0x68,0x04,0x04))
	{
		return false;
	}
	if(!m_objTempFile.WriteAEP(m_dwOriAEP))
	{
		free(UnpackInfo);
		UnpackInfo=NULL;
		return false;
	}

	return true;
}




bool CXPackUnpacker::ResolveImportAddresses(DWORD dwStart)
{
	BYTE *byImportbuff=NULL;
	DWORD dwSize=0x0;
	while(1)
	{
		if(!(byImportbuff=(BYTE*)realloc(byImportbuff,dwSize+0x14)))
		{
			byImportbuff=NULL;
			return false;
		}
		memset(&byImportbuff[dwSize],0,0x14);

		if(!m_objTempFile.ReadBuffer(&byImportbuff[dwSize],dwStart+dwSize,0x14,0x14))
		{
			free(byImportbuff);
			byImportbuff=NULL;
		}
		//Loop breaking condition
		if(*(DWORD*)&(byImportbuff[dwSize+0x0C])==0x00 || *(DWORD*)&(byImportbuff[dwSize+0x10])==0x00 || (dwSize+0x14)>(m_objTempFile.m_stSectionHeader[0].Misc.VirtualSize-dwStart))
		{
			break;
		}
		//To subtract the ImageBase from the going to be Import Directory Table
		*(DWORD*)&(byImportbuff[dwSize+0x0C])-=m_dwImageBase;
		*(DWORD*)&(byImportbuff[dwSize+0x10])-=m_dwImageBase;
		dwSize+=0x14;
	}

	//To write the modified buffer back to memory
	if(!m_objTempFile.WriteBuffer(byImportbuff,dwStart,dwSize,dwSize))
	{
		free(byImportbuff);
		byImportbuff=NULL;
		return false;
	}

	free(byImportbuff);
	byImportbuff=NULL;

	return true;
}

bool CXPackUnpacker::ResolveCalls(BYTE* bySrcBuff,DWORD dwSize,BYTE *byCallsbuff,DWORD dwIncrement)
{
	boolean bflag = false;
	DWORD dwCompareResolve = 0, dwCompareCounter = 0;
	for(DWORD dwCounter=0x04;dwCounter<=(dwSize-0x05+0x04);dwCounter++)
	{
		dwCompareResolve=*(DWORD*)&byCallsbuff[dwCompareCounter];
		if(bySrcBuff[dwCounter-0x04]==0xE8 || bySrcBuff[dwCounter-0x04]==0xE9 || ((bySrcBuff[dwCounter-0x04]==0x0F)&&(bflag=true)))
		{
			if(bflag)
			{
				if(bySrcBuff[dwCounter-0x04+0x01]<0x80 || bySrcBuff[dwCounter-0x04+0x01]>0x8F)
				{
					bflag=false;
					continue;
				}
				if((dwCounter==(dwSize-0x05+0x04)))
				{
					return false;
				}
				dwCounter++;
				bflag=false;
			}
			if((dwCounter+0x01)!=dwCompareResolve)
			{
				DWORD dwtemp=*(DWORD*)&(bySrcBuff[dwCounter-0x04+0x01]);
				if((dwtemp&0xFF)==0x0D)
				{
					dwtemp&=0xFFFFFF00;
					dwtemp=(dwtemp<<24)|(dwtemp>>24)|((dwtemp<<8)&0x00FF0000)|((dwtemp>>8)&0x0000FF00);
					*(DWORD*)&(bySrcBuff[dwCounter-0x04+0x01])=dwtemp-(dwCounter+0x01);
					dwCounter+=0x04;
				}
			}
			else
			{
				dwCompareCounter += 0x04;
				if(dwCompareCounter > (dwIncrement * 0x04))
				{
					return false;
				}
			}
		}
	}
	return true;
}


