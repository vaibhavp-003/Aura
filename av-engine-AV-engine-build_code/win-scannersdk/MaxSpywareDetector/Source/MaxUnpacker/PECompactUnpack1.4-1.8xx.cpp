#include "PECompactUnpack1.4-1.8xx.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CPECompactOldUnpack::CPECompactOldUnpack(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{	
	m_pStructDecompressInfo=NULL;
	m_pStructBlockDecompressInfo=NULL;
}

CPECompactOldUnpack::~CPECompactOldUnpack(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CPECompactOldUnpack::IsPacked() 
{
	if (m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&
		(m_pMaxPEFile->m_stSectionHeader[0].SizeOfRawData<m_pMaxPEFile->m_stSectionHeader[0].Misc.VirtualSize || m_iCurrentLevel>0) &&
		((m_pMaxPEFile->m_stSectionHeader[1].Characteristics & 0xC0000000) == 0xC0000000))
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}

		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x0B,0x0B))
		{
			return false;
		}

		if(*(WORD*)&m_pbyBuff[0]==0x06EB && m_pbyBuff[0x2]==0x68 && *(DWORD*)&m_pbyBuff[0x7]==0xE8609CC3)
		{
			return true;
		}
	}
	return false;	
}


bool CPECompactOldUnpack::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName,true,false))
	{
		return false;
	}

	BYTE *byFullFilebuff=NULL;
	if(!(byFullFilebuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize)))
	{
		return false;
	}

	if(!m_objTempFile.ReadBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;

	if(dwOffset+0x1E+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwEBPValue=*(DWORD*)&byFullFilebuff[dwOffset+0x1E];
	dwOffset+=0x3B;

	if(dwOffset+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	BYTE *bybuff=new BYTE[sizeof(DecompressInfo)];
	if(*(DWORD*)&byFullFilebuff[dwOffset]+m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x0F-dwEBPValue+sizeof(DecompressInfo)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	memcpy(bybuff,&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwOffset]+m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x0F-dwEBPValue],sizeof(DecompressInfo));
	m_pStructDecompressInfo=(DecompressInfo*)&bybuff[0];
	bool bDecompressInfofromLoader=false;
	//dwEBPValue=*(DWORD*)&byFullFilebuff[dwOffset]-dwEBPValue;
	//dwEBPValue+=0x2E;
	DWORD dwtemp=*(DWORD*)&byFullFilebuff[dwOffset]-dwEBPValue-0x2E+m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x0F;
	if(*(DWORD*)&byFullFilebuff[dwOffset]-dwEBPValue-0x2E!=0x6D)
	{
		bDecompressInfofromLoader=true;
	}
	dwEBPValue=*(DWORD*)&byFullFilebuff[dwOffset]-0x2E;
	dwOffset=dwtemp;

	if(dwOffset-0x09+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwLoaderSize=*(DWORD*)&byFullFilebuff[dwOffset-0x09]*0x04;


	if(dwOffset+0x05+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}


	BYTE *byLoaderbuff=NULL;
	if(!(byLoaderbuff=(BYTE*)MaxMalloc(dwLoaderSize+0x30)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	memset(byLoaderbuff,0,dwLoaderSize+0x30);

	if(dwOffset+0x0C+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}

	if(m_pStructDecompressInfo->dwDecompressionOffset+0x10 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}
	dwEBPValue+=byFullFilebuff[dwOffset+0x9];

	if(!CheckAlgorithm(m_pStructDecompressInfo->dwDecompressionOffset,byFullFilebuff,dwOffset+byFullFilebuff[dwOffset+0x9],dwOffset+*(DWORD*)&byFullFilebuff[dwOffset+0xC],*(DWORD*)&byFullFilebuff[dwOffset+0xC],dwLoaderSize,&dwLoaderSize,byLoaderbuff))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}

	CEmulate objEmulate(&m_objTempFile);
	DWORD dwOffsetToResolve=0;
	DWORD dwSizetoResolve=0;
	BYTE byKey[6]={0};

	//Using the loader to decompress the main source code
	if(!(~(dwOffset=CallEmulatorDissambler(3,0,byLoaderbuff,objEmulate,dwLoaderSize,&dwOffsetToResolve,&dwSizetoResolve,byKey))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}

	if(dwOffset+0x02+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwMaxDestSize=*(DWORD*)&byLoaderbuff[dwOffset+0x02]+0x18;
	dwMaxDestSize-=dwEBPValue;

	if(dwMaxDestSize+0x04>dwLoaderSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}
	dwMaxDestSize=*(DWORD*)&byLoaderbuff[dwMaxDestSize]; //Max Destbuffer of all the decompressions

	//Only if information is not present in original file

	BYTE *bytemp=byLoaderbuff;
	DWORD dwtempsize=dwLoaderSize;
	if(bDecompressInfofromLoader)
	{
		if(!(~(dwOffset=CallEmulatorDissambler(0,0,byLoaderbuff,objEmulate,dwLoaderSize,&dwOffsetToResolve,&dwSizetoResolve,byKey))))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			return false;
		}
		if(dwOffset+0x02+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			return false;
		}
		m_pStructDecompressInfo->dwBlockInfoOffset=*(DWORD*)&byLoaderbuff[dwOffset+0x02]-dwEBPValue;
	}
	else
	{
		byLoaderbuff=byFullFilebuff;
		dwLoaderSize=m_objTempFile.m_dwFileSize;
	}

	if(m_pStructDecompressInfo->dwBlockInfoOffset+sizeof(BlockDecompressInfo) > dwLoaderSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}
	DWORD dwDestSize;

	BYTE *byDestbuff=NULL;

	if(!(byDestbuff=(BYTE*)MaxMalloc(dwMaxDestSize)))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}
	memset(byDestbuff,0,dwMaxDestSize);

	while(*(DWORD*)&byLoaderbuff[m_pStructDecompressInfo->dwBlockInfoOffset]!=0x00)
	{
		dwDestSize=0;
		m_pStructBlockDecompressInfo=(BlockDecompressInfo*)&byLoaderbuff[m_pStructDecompressInfo->dwBlockInfoOffset];
		if(m_pStructBlockDecompressInfo->dwRVASource+m_pStructBlockDecompressInfo->dwSrcSize>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			return false;
		}
		if(!CheckAlgorithm(m_pStructDecompressInfo->dwDecompressionOffset,byFullFilebuff,m_pStructBlockDecompressInfo->dwRVASource,0x00,m_pStructBlockDecompressInfo->dwSrcSize,dwMaxDestSize,&dwDestSize,byDestbuff))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			return false;
		}

		if(m_pStructBlockDecompressInfo->dwRVASource+dwDestSize>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			return false;
		}

		for(DWORD i=0;i<dwDestSize;i++)
		{
			byFullFilebuff[m_pStructBlockDecompressInfo->dwRVASource+i]=byDestbuff[i];
		}

		m_pStructDecompressInfo->dwBlockInfoOffset+=sizeof(BlockDecompressInfo);

		if(m_pStructDecompressInfo->dwBlockInfoOffset+sizeof(BlockDecompressInfo) > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			free(byDestbuff);
			byDestbuff=NULL;
			return false;
		}

	}

	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff=NULL;
	}

	if(bDecompressInfofromLoader)
	{
		dwOffset+=0x06;
		if(!(~(dwOffset=CallEmulatorDissambler(0,dwOffset,byLoaderbuff,objEmulate,dwLoaderSize,&dwOffsetToResolve,&dwSizetoResolve,byKey))))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			return false;
		}
		if(dwOffset+0x02+0x04>dwLoaderSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			return false;
		}
		m_pStructDecompressInfo->dwCopyBlockInfoOffset=*(DWORD*)&byLoaderbuff[dwOffset+0x02]-dwEBPValue;
	}

	if(m_pStructDecompressInfo->dwCopyBlockInfoOffset+sizeof(BlockCopyInfo) > dwLoaderSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}

	while(*(DWORD*)&byLoaderbuff[m_pStructDecompressInfo->dwCopyBlockInfoOffset]!=0x00 && *(DWORD*)&byLoaderbuff[m_pStructDecompressInfo->dwCopyBlockInfoOffset]!=0xFFFFFFFF)
	{
		m_pStructBlockCopyInfo=(BlockCopyInfo*)&byLoaderbuff[m_pStructDecompressInfo->dwCopyBlockInfoOffset];

		if(m_pStructBlockCopyInfo->dwSize>0 && m_pStructBlockCopyInfo->dwRVADest!=m_pStructBlockCopyInfo->dwRVASource)
		{
			if(m_pStructBlockCopyInfo->dwRVADest+m_pStructBlockCopyInfo->dwSize>m_objTempFile.m_dwFileSize ||
				(m_pStructBlockCopyInfo->dwRVASource+m_pStructBlockCopyInfo->dwSize>m_objTempFile.m_dwFileSize))
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				byLoaderbuff=bytemp;
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				return false;
			}

			for(DWORD i=0;i<m_pStructBlockCopyInfo->dwSize;i++)
			{
				byFullFilebuff[m_pStructBlockCopyInfo->dwRVADest+i]=byFullFilebuff[m_pStructBlockCopyInfo->dwRVASource+i];
			}

			DWORD dwFillWithZeroSize=m_pStructBlockCopyInfo->dwSize;
			if(m_pStructBlockCopyInfo->dwRVASource<m_pStructBlockCopyInfo->dwRVADest && m_pStructBlockCopyInfo->dwRVASource+m_pStructBlockCopyInfo->dwSize>m_pStructBlockCopyInfo->dwRVADest)
			{
				dwFillWithZeroSize=m_pStructBlockCopyInfo->dwRVADest-m_pStructBlockCopyInfo->dwRVASource;
			}
			else if(m_pStructBlockCopyInfo->dwRVADest<m_pStructBlockCopyInfo->dwRVASource && m_pStructBlockCopyInfo->dwRVADest+m_pStructBlockCopyInfo->dwSize>m_pStructBlockCopyInfo->dwRVASource)
			{
				dwFillWithZeroSize=m_pStructBlockCopyInfo->dwRVASource-m_pStructBlockCopyInfo->dwRVADest;
				m_pStructBlockCopyInfo->dwRVASource=m_pStructBlockCopyInfo->dwRVADest+m_pStructBlockCopyInfo->dwSize;
			}

			if(m_pStructBlockCopyInfo->dwRVASource+m_pStructBlockCopyInfo->dwSize>m_objTempFile.m_dwFileSize)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				byLoaderbuff=bytemp;
				free(byLoaderbuff);
				byLoaderbuff=NULL;
				return false;
			}

			for(DWORD i=0;i<m_pStructBlockCopyInfo->dwSize;i++)
			{
				byFullFilebuff[m_pStructBlockCopyInfo->dwRVASource+i]=0x0;
			}
		}

		if(m_pStructBlockCopyInfo->dwRVADest+m_pStructBlockCopyInfo->dwSize>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			return false;
		}

		for(DWORD i=0;i<m_pStructBlockCopyInfo->dwDestFillWithZeroSize;i++)
		{
			byFullFilebuff[m_pStructBlockCopyInfo->dwRVADest+m_pStructBlockCopyInfo->dwSize+i]=0x0;
		}		

		m_pStructDecompressInfo->dwCopyBlockInfoOffset+=sizeof(BlockCopyInfo);

		if(m_pStructDecompressInfo->dwCopyBlockInfoOffset+sizeof(BlockCopyInfo) > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			byLoaderbuff=bytemp;
			free(byLoaderbuff);
			byLoaderbuff=NULL;
			return false;
		}
	}

	dwOffset+=0x06;
	if(!bDecompressInfofromLoader)
	{
		byLoaderbuff=bytemp;
		dwLoaderSize=dwtempsize;
	}
	if(!(~(dwOffset=CallEmulatorDissambler(1,dwOffset,byLoaderbuff,objEmulate,dwLoaderSize,&dwOffsetToResolve,&dwSizetoResolve,byKey))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}

	if(dwOffsetToResolve-dwEBPValue+0x04>dwLoaderSize ||
		dwSizetoResolve-dwEBPValue+0x04 >dwLoaderSize || 
		*(DWORD*)&byLoaderbuff[dwOffsetToResolve-dwEBPValue]+*(DWORD*)&byLoaderbuff[dwSizetoResolve-dwEBPValue]>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}

	if(!ResolveE8E9Calls(byFullFilebuff,*(DWORD*)&byLoaderbuff[dwOffsetToResolve-dwEBPValue],*(DWORD*)&byLoaderbuff[dwSizetoResolve-dwEBPValue],byKey))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}

	dwOffset+=0x06;
	if(!(~(dwOffset=CallEmulatorDissambler(2,dwOffset,byLoaderbuff,objEmulate,dwLoaderSize,&dwOffsetToResolve,&dwSizetoResolve,byKey))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=*(DWORD*)&m_pbyBuff[0x3];

	if(dwOffset+0x02+0x04 > m_objTempFile.m_dwFileSize || 
		*(DWORD*)&byLoaderbuff[dwOffset+0x02]-dwEBPValue+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
		return false;
	}
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+(sizeof(DWORD)*0x03)]=*(DWORD*)&byLoaderbuff[*(DWORD*)&byLoaderbuff[dwOffset+0x02]-dwEBPValue];

	if(byLoaderbuff)
	{
		byLoaderbuff=bytemp;
		free(byLoaderbuff);
		byLoaderbuff=NULL;
	}

	if(!m_objTempFile.WriteBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(byFullFilebuff)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
	}

	return true;
}

bool CPECompactOldUnpack::CheckAlgorithm(DWORD dwOffset,BYTE *byFullFilebuff,DWORD dwSrcRVA,DWORD dwDestRVA,DWORD dwSrcSize,DWORD dwMAxDestSize,DWORD *dwDestSize,BYTE *byDestbuff)
{
	const BYTE byAPLIBSig[] ={0xC8, 0x00, 0x00, 0x00, 0x55, 0x8B, 0x75, 0x08, 0x8B, 0x7D, 0x0C, 0xFC, 0xB2, 0x80}; //Normal APLIB
	const BYTE byNeoliteSig[] ={0xC8, 0x0C, 0x00, 0x00, 0xFC, 0x53, 0x57, 0x56, 0x8B, 0x74, 0x24, 0x20}; //Neolite
	const BYTE byNeoliteModSig[] ={0x55, 0x8B, 0xEC, 0x83, 0xC4, 0xF4, 0xFC, 0x53, 0x57, 0x56, 0x8B, 0x74}; //Neolite

	if(memcmp(&byFullFilebuff[dwOffset],byAPLIBSig,sizeof(byAPLIBSig))==0)
	{
		m_eDLLCompress=APLIB;
	}
	else if(memcmp(&byFullFilebuff[dwOffset],byNeoliteSig,sizeof(byNeoliteSig))==0 || 
			memcmp(&byFullFilebuff[dwOffset],byNeoliteModSig,sizeof(byNeoliteModSig))==0)
	{
		m_eDLLCompress=Neolite;
	}


	switch (m_eDLLCompress)
	{
	case APLIB:
		{
			if(!(~(*dwDestSize=APLIBDecompress(dwSrcSize,dwMAxDestSize,0,0,&byDestbuff[0],4,&byFullFilebuff[dwSrcRVA]))))
			{
				return false;
			}
			break;
		}

	case Neolite:
		{
			if(!(*dwDestSize=NeoliteUncompress(dwSrcSize,&dwMAxDestSize,0,0,NULL,NULL,&byFullFilebuff[dwSrcRVA+0x06+((byFullFilebuff[dwOffset]==0x55)*0x04)],byDestbuff)))
			{
				return false;
			}
			break;
		}
	}
	return true;
}

bool CPECompactOldUnpack::ResolveE8E9Calls(BYTE *byBuff,DWORD dwOffset,DWORD dwSize,BYTE *byKey)
{
	if(dwSize<0x06)
	{
		return false;
	}
	DWORD dwZeroCounter=0;
	for(DWORD dwCounter=0;dwCounter<=dwSize-0x06;dwCounter++)
	{
		if(dwCounter==0x25F)
		{
			dwCounter=dwCounter;
		}
		//Checking for E8 and E9
		if((byBuff[dwOffset+dwCounter]==0xE8 || byBuff[dwOffset+dwCounter]==0xE9))
		{
			if(byKey[3]==0x01 && byBuff[dwOffset+dwCounter+0x01]==byKey[4])
			{
				*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]=*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]&0xFFFF0000;
				*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]=ntohl(*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]);
				*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]=*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]-dwCounter;	
				dwCounter+=0x04;
			}
			else if(byKey[5]==0x00)
			{
				if(byKey[3]==0x00)
				{
					*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]=*(DWORD*)&byBuff[dwOffset+dwCounter+0x01]-dwCounter;	
				}
				dwCounter+=0x04;
			}
		}
		else if(*(WORD*)&byBuff[dwOffset+dwCounter]==0x25FF)
		{
			if(byKey[0]==0x01)
			{
				*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]-=dwZeroCounter;
			}
			else
			{
				*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]+=dwZeroCounter;
			}
			if(byKey[0]==0x01)
			{
				dwCounter-=0x02;
			}
			dwZeroCounter-=0x04;
			dwCounter+=0x07;
		}
		else if(byBuff[dwOffset+dwCounter]==0x0F)
		{
			if(byBuff[dwOffset+dwCounter+1]>=0x80 && byBuff[dwOffset+dwCounter+1]<=0x8F)
			{
				if(byKey[1]==0x01 && byKey[2]==byBuff[dwOffset+dwCounter+2])
				{
					*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]=*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]&0xFFFF0000;
					*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]=ntohl(*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]);
				}
				*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]=*(DWORD*)&byBuff[dwOffset+dwCounter+0x02]-dwCounter;	
				dwCounter+=0x05;
			}
		}
	}
	return true;
}

DWORD CPECompactOldUnpack::CallEmulatorDissambler(int iType,DWORD dwOffset,BYTE *byFullFilebuff,CEmulate objEmulate,DWORD dwSize,DWORD *dwOffsettoResolve,DWORD *dwSizetoResolve,BYTE *byKey)
{
	DWORD dwLength = 0, dwInstructionCountFound = 0;
	char	szInstruction[1024] = {0x00};
	bool bCheckForZero=true;
	while(dwOffset<dwSize)
	{
		dwLength = objEmulate.DissassemBuffer((char*)&byFullFilebuff[dwOffset],szInstruction);

		if(iType==0x00 && strstr(szInstruction,"LEA ESI"))
		{
			return dwOffset;
		}
		if(iType==0x03 && strstr(szInstruction,"LEA EDI"))
		{
			return dwOffset;
		}
		else if(bCheckForZero && strstr(szInstruction,"JZ") && dwLength==0x02)
		{
			dwOffset+=byFullFilebuff[dwOffset+0x01];
		}
		else if(iType==0x01 && strstr(szInstruction,"MOV EDI") && dwLength==0x06)
		{
			*dwOffsettoResolve=*(DWORD*)&byFullFilebuff[dwOffset+0x02];
		}
		else if(iType==0x01 && strstr(szInstruction,"MOV ECX") && dwLength==0x06)
		{
			*dwSizetoResolve=*(DWORD*)&byFullFilebuff[dwOffset+0x02];
			bCheckForZero=false;
		}
		else if(iType==0x01 && strstr(szInstruction,"CMP AX ,2517H") && dwLength==0x04)
		{
			if(dwOffset+byFullFilebuff[dwOffset+0x05]+0x06+0x01>dwSize)
			{
				return false;
			}
			if(byFullFilebuff[dwOffset+byFullFilebuff[dwOffset+0x05]+0x06]==0x29)
			{
				byKey[0]=1;
			}
		}
		else if(iType==0x01 && strstr(szInstruction,"CMP AL ,1H") && dwLength==0x02)
		{
			if(dwOffset+byFullFilebuff[dwOffset+0x03]+0x04+0x07>dwSize)
			{
				return false;
			}
			if(byFullFilebuff[dwOffset+byFullFilebuff[dwOffset+0x03]+0x04+0x04]!=0x90)
			{
				byKey[3]=1;
				byKey[4]=byFullFilebuff[dwOffset+byFullFilebuff[dwOffset+0x03]+0x04+0x04];
			}
			if(byFullFilebuff[dwOffset+byFullFilebuff[dwOffset+0x03]+0x04+0x06]>0x0E)
			{
				byKey[5]=1;
			}
		}
		else if(iType==0x01 && strstr(szInstruction,"CMP AH ,8FH") && dwLength==0x03)
		{
			if(dwOffset+byFullFilebuff[dwOffset+0x04]+0x05+0x05>dwSize)
			{
				return false;
			}
			if(byFullFilebuff[dwOffset+byFullFilebuff[dwOffset+0x04]+0x05+0x04]!=0x90)
			{
				byKey[1]=1;
				byKey[2]=byFullFilebuff[dwOffset+byFullFilebuff[dwOffset+0x04]+0x05+0x04];
			}
			return dwOffset;
		}
		else if(iType==0x02 && strstr(szInstruction,"MOV ESI") && dwLength==0x06)
		{
			return dwOffset;
		}
		else if(iType==0x02 && strstr(szInstruction,"CALL") && dwLength==0x05)
		{
			if(dwOffset+*(DWORD*)&byFullFilebuff[dwOffset+0x01]+0x05 + 1 > m_objTempFile.m_dwFileSize)
			{
				return -1;
			}
			if(byFullFilebuff[dwOffset+*(DWORD*)&byFullFilebuff[dwOffset+0x01]+0x05]!=0xC3)
			{
				dwOffset+=*(DWORD*)&byFullFilebuff[dwOffset+0x01];
			}

		}
		dwOffset+=dwLength;
	}
	return -1;
}

