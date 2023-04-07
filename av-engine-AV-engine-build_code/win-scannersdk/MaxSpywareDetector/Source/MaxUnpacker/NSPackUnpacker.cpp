#include "NsPackUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CNSPackUnpacker::CNSPackUnpacker(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{	
	m_NSPackType=NORMAL_NS;
}

CNSPackUnpacker::~CNSPackUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff=NULL;
	}
	m_objTempFile.CloseFile();
}

bool CNSPackUnpacker::IsPacked() 
{
	m_pbyBuff = new BYTE[255];
	
	BYTE byNspackbuff[]={0x9C,0x60,0xE8,0x00,0x00,0x00,0x00,0x5D,0x83,0xED,0x07,0x8D};
	BYTE byNspackbuff2[]={0x9C,0x60,0xE8,0x00,0x00,0x00,0x00,0x5D,0xB8,0x07,0x00,0x00,0x00,0x2B,0xE8};
	BYTE JmpNspackbuff[]={0x70,0x61,0x63,0x6B,0x65,0x64,0x20,0x62,0x79,0x20,0x6E,0x73,0x70,0x61,0x63,0x6B};
	if(BYTE(m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint)%0x1B==0x00)
	{
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,0x2B,sizeof(JmpNspackbuff),sizeof(JmpNspackbuff)))
		{
			return false;
		}
		if(memcmp(m_pbyBuff,JmpNspackbuff,sizeof(JmpNspackbuff))==0x00)
		{
			m_NSPackType=JMP_NS;
			return true;
		}

	}
	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,sizeof(byNspackbuff2),sizeof(byNspackbuff2)))
	{
		return false;
	}
	if(memcmp(m_pbyBuff,byNspackbuff,sizeof(byNspackbuff))==0x00 ||
		memcmp(m_pbyBuff,byNspackbuff2,sizeof(byNspackbuff2))==0x00 ||
		(memcmp(m_pbyBuff,&byNspackbuff2[2],sizeof(byNspackbuff2)-0x02)==0x00 && (m_NSPackType=MODIFIED_NOP)))
	{
		return true;
	}
	return false;
}


bool CNSPackUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName, true, false,m_NSPackType))
	{
		return false;
	}

	if(m_NSPackType==JMP_NS)
	{
		m_objTempFile.m_stPEHeader.AddressOfEntryPoint=0x101B;
		if(!m_objTempFile.ReadBuffer(m_pbyBuff,m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x01,0x04,0x04))
		{
			return false;
		}
		m_objTempFile.m_stPEHeader.AddressOfEntryPoint+=0x05+*(DWORD*)&m_pbyBuff[0];
	}

	if(m_NSPackType==MODIFIED_NOP)
	{
		m_objTempFile.m_stPEHeader.AddressOfEntryPoint-=0x02;		
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


	DWORD dwOffsetInFile=0x08;
	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+1>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]!=0x83)
	{
		dwOffsetInFile+=0x05;
	}
	dwOffsetInFile+=0xA;

	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+1>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]!=0x3C)
	{
		dwOffsetInFile+=0x01;
	}
	dwOffsetInFile+=0x03;


	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x02>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile-1]==0x74)
	{
		dwOffsetInFile+=0x01;
		if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x02>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		if(*(WORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]==0xF58B)
		{
			dwOffsetInFile+=0x02;
		}
		dwOffsetInFile+=0x08;
		if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		if(byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]!=0x3C)
		{
			dwOffsetInFile+=0x01;
		}
		dwOffsetInFile+=0x04;
	}



	//Original AEP
	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwAEPUnmapped=*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]+m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x04;
	DWORD dwType2=0x00;
	if(dwAEPUnmapped+0x03>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwType2=0x01;
	if(*(WORD*)&byFullFilebuff[dwAEPUnmapped]==0x9D61)
	{
		dwType2=0x00;
	}

	if(dwAEPUnmapped+(dwType2*0x11)+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwResolveDLLOffset=dwAEPUnmapped+(dwType2*0x14)+0x03+0x37;
	if(dwResolveDLLOffset+0x04 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwAEPUnmapped=dwAEPUnmapped+(dwType2*0x14)+0x03+*(DWORD*)&byFullFilebuff[dwAEPUnmapped+(dwType2*0x14)+0x03]+0x04;



	//Decompression
	dwOffsetInFile+=0x04;
	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x01>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	if(byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]==0xC7)
	{
		dwOffsetInFile+=0x03;
	}
	dwOffsetInFile+=0x03;

	dwOffsetInFile+=0x2;
	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x02>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	if(*(WORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]==0x858B)
	{
		dwOffsetInFile+=0x02;
	}
	dwOffsetInFile+=0x08;

	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]-0x10;

	dwOffsetInFile+=0x6;

	if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]>0x00 && m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]+0x14>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}


	if(dwOffset>0 && dwOffset+0x04<m_objTempFile.m_dwFileSize)
	{
		DWORD dwDestSize=0x00;
		BYTE *byDestbuff=NULL;
		dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[dwOffset];
		if(dwOffset+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		DWORD dwtempOffset=0;
		bool bDecryptMorebytes=false;
		if(*(DWORD*)&byFullFilebuff[dwOffset]!=0x00)
		{
			bDecryptMorebytes=true;		
			dwtempOffset=(*(DWORD*)&byFullFilebuff[dwOffset])-0x04;
		}
		dwOffset+=0x04;
		if(dwOffset+0x08>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		DWORD dwLoopCounter=0;
		while(*(DWORD*)&byFullFilebuff[dwOffset+(dwLoopCounter*0x08)]!=0x00)
		{
			if(bDecryptMorebytes)
			{
				dwtempOffset+=*(DWORD*)&byFullFilebuff[dwOffset+(dwLoopCounter*0x08)+0x04];
			}
			if(dwOffset+dwtempOffset+0x05+sizeof(LZMAInfo)>m_objTempFile.m_dwFileSize)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
		
			BYTE byLZMAProp[0x04]={0};
			byLZMAProp[0]=byFullFilebuff[dwOffset+dwtempOffset];

			m_pStructLZMAInfo=(LZMAInfo*)&byFullFilebuff[dwOffset+dwtempOffset+0x05];
			if(!(byDestbuff=(BYTE*)MaxMalloc(m_pStructLZMAInfo->dwDestSize)))
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}

			if(dwOffset+dwtempOffset+0x0D+ m_pStructLZMAInfo->dwSrcSize > m_objTempFile.m_dwFileSize)
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				free(byDestbuff);
				byDestbuff=NULL;
				return false;
			}

			if(!(dwDestSize = LZMADecompress(byLZMAProp, m_pStructLZMAInfo->dwSrcSize, m_pStructLZMAInfo->dwDestSize, 0x00, 0x00, byDestbuff,&byFullFilebuff[dwOffset+dwtempOffset+0x0D])))
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}

			if(!bDecryptMorebytes)
			{
				break;
			}

			m_pStructLZMAInfo->dwDestRVA=*(DWORD*)&byFullFilebuff[dwOffset+(dwLoopCounter*0x08)];
			if(m_pStructLZMAInfo->dwDestRVA+dwDestSize > m_objTempFile.m_dwFileSize)
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}

			for(DWORD i=0;i<dwDestSize && (i+m_pStructLZMAInfo->dwDestRVA+1<=m_objTempFile.m_dwFileSize);i++)
			{
				byFullFilebuff[i+m_pStructLZMAInfo->dwDestRVA]=byDestbuff[i];
			}
			dwtempOffset-=*(DWORD*)&byFullFilebuff[dwOffset+(dwLoopCounter*0x08)+0x04];
			dwLoopCounter++;

			if(dwOffset+dwLoopCounter*0x08+0x08 > m_objTempFile.m_dwFileSize)
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}


		}


		m_pStructResolveCallsInfo=(ResolveCallsInfo*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]];
		if(m_pStructResolveCallsInfo->dwAddressOffset==0x00)
		{
			m_pStructResolveCallsInfo->dwAddressOffset=*(DWORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile+0x06]+m_objTempFile.m_stPEHeader.AddressOfEntryPoint];
		}

		if(m_pStructResolveCallsInfo->dwAddressOffset>=m_objTempFile.m_stPEHeader.ImageBase)
		{
			m_pStructResolveCallsInfo->dwAddressOffset-=m_objTempFile.m_stPEHeader.ImageBase;
		}
		
		if(!bDecryptMorebytes)
		{
			for(DWORD i=0;i<dwDestSize && (i+m_pStructResolveCallsInfo->dwAddressOffset+1<=m_objTempFile.m_dwFileSize);i++)
			{
				byFullFilebuff[i+m_pStructResolveCallsInfo->dwAddressOffset]=byDestbuff[i];
			}
		}

		if(byDestbuff)
		{
			free(byDestbuff);
			byDestbuff=NULL;
		}


		if(m_pStructResolveCallsInfo->dwCallsCounter>0x00)
		{
			//Resolve E8/E9 Calls
			if(!ResolveE8E9Calls(&byFullFilebuff[m_pStructResolveCallsInfo->dwAddressOffset],dwDestSize,m_pStructResolveCallsInfo))
			{
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
		}


		if(m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]-0x08-0x30+0x04>m_objTempFile.m_dwFileSize ||
			m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]-0x30+0x1B0+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}


		BYTE *byImportTablebuff=NULL;
		DWORD dwImportSizeBuild=0x00;

		if(!ResolveImportTable(
			&byImportTablebuff,&byFullFilebuff[*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]-0x08-0x30]],
			&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwResolveDLLOffset]+m_objTempFile.m_stPEHeader.AddressOfEntryPoint],
			*(DWORD*)&byFullFilebuff[dwResolveDLLOffset]+m_objTempFile.m_stPEHeader.AddressOfEntryPoint,
			m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint+dwOffsetInFile]-0x08-0x30,
			byFullFilebuff,
			dwImportSizeBuild))
			//if(!ResolveImportTable(&byImportTablebuff,&byFullFilebuff[*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint-0x30D]],&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint-0x155],m_objTempFile.m_stPEHeader.AddressOfEntryPoint-0x155,*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEHeader.AddressOfEntryPoint-0x30D],byFullFilebuff,dwImportSizeBuild))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(dwImportSizeBuild!=0x00)
		{
		 *(WORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NumberOfSections]=m_objTempFile.m_stPEHeader.NumberOfSections+1;
		}
		*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=/**/(m_objTempFile.m_dwFileSize);
		*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=dwAEPUnmapped;

		//Writing the complete buffer back to file
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

		if(dwImportSizeBuild!=0x00)
		{
			if(*(DWORD*)&m_objTempFile.m_stSectionHeader[m_objTempFile.m_stPEHeader.NumberOfSections-0x01].Name[0]==0x6164692E &&
				*(DWORD*)&m_objTempFile.m_stSectionHeader[m_objTempFile.m_stPEHeader.NumberOfSections-0x01].Name[4]==0x00326174 )
			{
				//m_objTempFile.RemoveLastSections();
			}


			m_objTempFile.CloseFile();
			if(!m_objTempFile.OpenFile(szTempFileName, true))
			{
				free(byImportTablebuff);
				byImportTablebuff=NULL;
				return false;
			}



			//Adding a new Section
			if(!AddNewSection(dwImportSizeBuild,1))
			{
				free(byImportTablebuff);
				byImportTablebuff=NULL;
				return false;
			}

			m_objTempFile.CloseFile();
			if(!m_objTempFile.OpenFile(szTempFileName, true))
			{
				free(byImportTablebuff);
				byImportTablebuff=NULL;
				return false;
			}

			//Writing the basic Import Directory Table buffer to memory
			if(!m_objTempFile.WriteBuffer(byImportTablebuff, /**/(m_objTempFile.m_dwFileSize), dwImportSizeBuild, dwImportSizeBuild))
			{
				free(byImportTablebuff);
				byImportTablebuff=NULL;
				return false;
			}	

			if(byImportTablebuff)
			{
				free(byImportTablebuff);
				byImportTablebuff=NULL;
			}

		}
		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			return false;
		}

		if(!ReOrganizeFile(szTempFileName, false))
		{
			return false;
		}

		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			return false;
		}

		if(!m_objTempFile.CalculateImageSize())
		{
			return false;
		}
		return true;
	}

	if(byFullFilebuff)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
	}

	return false;
}

bool CNSPackUnpacker::ResolveE8E9Calls(BYTE *bybuff, DWORD dwSize, ResolveCallsInfo *pStructResolveCalls)
{

	if(dwSize<0x05)
	{
		return false;
	}
	dwSize-=0x05;
	DWORD dwResolveCounter=m_pStructResolveCallsInfo->dwCallsCounter;
	for(DWORD i=0;i<dwSize && dwResolveCounter>0;i++)
	{
		if(bybuff[i]==0xE8 || bybuff[i]==0xE9)
		{
			if(pStructResolveCalls->dwCallValue[1]==0x00)
			{
				*(DWORD*)&bybuff[i+1] = ntohl(*(DWORD*)&bybuff[i+1]);
				*(DWORD*)&bybuff[i+1] -= i + 1;
				i+=0x04;
				dwResolveCounter--;
			}
			else if(pStructResolveCalls->dwCallValue[0]==bybuff[i+1])
			{
				*(WORD*)&bybuff[i+1]>>=0x08;
				MAX_ROL(*(DWORD*)&bybuff[i+1],0x10);
				bybuff[i+1]^=bybuff[i+2];
				bybuff[i+2]=bybuff[i+1]^bybuff[i+2];
				bybuff[i+1]^=bybuff[i+2];
				*(DWORD*)&bybuff[i+1]-=(i+1);
				i+=0x04;
				dwResolveCounter--;
			}
		}
	}
	return true;

}

bool CNSPackUnpacker::ResolveImportTable(BYTE ** byImportTableBuildbuff,BYTE *byImportReadbuff,BYTE * byImportTableDLLReadbuff,DWORD dwImportDLLOffset,DWORD dwImportAPIOffset,BYTE *byFullFilebuff,DWORD &dwImportSizeBuild)
{
	DWORD dwImportCounter=0x00;
	DWORD dwImportSize=m_objTempFile.m_stPEHeader.SectionAlignment;
	DWORD dwImportDLLsCounter=0x00;
	BYTE *byImportAPIReadBuff=NULL;

	if(!(*byImportTableBuildbuff=(BYTE*)MaxMalloc(dwImportSize)))
	{
		return false;
	}
	memset(*byImportTableBuildbuff,0,dwImportSize);

	if(*(DWORD*)&byImportReadbuff[0]==0x00 && *(DWORD*)&byImportReadbuff[4]==0x00 && *(DWORD*)&byImportReadbuff[8]==0x00)
	{
		return true;
	}


	dwImportDLLOffset+=*(DWORD*)&byImportReadbuff[dwImportCounter+0x04];

	//Reading DLL Names 1 by 1

	DWORD dwImportDLLCounter=0x00;
	while(byImportTableDLLReadbuff[dwImportDLLCounter+*(DWORD*)&byImportReadbuff[dwImportCounter+0x04]]!=0x00)
	{
		while(byImportTableDLLReadbuff[dwImportDLLCounter+*(DWORD*)&byImportReadbuff[dwImportCounter+0x04]]!=0x00 && dwImportDLLOffset+dwImportDLLCounter<m_objTempFile.m_dwFileSize)
		{
			dwImportDLLCounter++;
		}
		if(dwImportDLLOffset+dwImportDLLCounter>m_objTempFile.m_dwFileSize)
		{
			free(*byImportTableBuildbuff);
			*byImportTableBuildbuff=NULL;
			return false;
		}
		dwImportDLLCounter++;
		dwImportDLLsCounter+=1;
	}
	dwImportDLLsCounter+=1;
	dwImportDLLOffset-=*(DWORD*)&byImportReadbuff[dwImportCounter+0x04];


	dwImportDLLCounter=0x00;
	while(dwImportDLLsCounter*0x14 > dwImportSize)
	{
		if(!(*byImportTableBuildbuff=(BYTE*)realloc(*byImportTableBuildbuff,dwImportSize+m_objTempFile.m_stPEHeader.SectionAlignment)))
		{
			free(*byImportTableBuildbuff);
			*byImportTableBuildbuff=NULL;
			return false;
		}
		memset(&(*byImportTableBuildbuff)[dwImportSize],0,m_objTempFile.m_stPEHeader.SectionAlignment);
		dwImportSize+=m_objTempFile.m_stPEHeader.SectionAlignment;
	}

	dwImportSizeBuild=dwImportDLLsCounter*0x14;

	DWORD dwOrigAPIOffset=dwImportAPIOffset;
	DWORD dwAPICounter=0x00;


	while(dwImportDLLCounter!=(dwImportDLLsCounter-1))
	{
		if(dwImportCounter+0x11+dwOrigAPIOffset > m_objTempFile.m_dwFileSize)
		{
			free(*byImportTableBuildbuff);
			*byImportTableBuildbuff=NULL;
			return false;
		}
		dwImportCounter+=0x04;	
		dwAPICounter=0x00;
		dwImportAPIOffset=dwImportCounter-0x04+*(DWORD*)&byImportReadbuff[dwImportCounter+0x08];
		*(DWORD*)&(*byImportTableBuildbuff)[(dwImportDLLCounter*0x14)+0x0C]=dwImportDLLOffset+*(DWORD*)&byImportReadbuff[dwImportCounter];
		*(DWORD*)&(*byImportTableBuildbuff)[(dwImportDLLCounter*0x14)+0x10]=*(DWORD*)&byImportReadbuff[dwImportCounter+0x04];
		if(dwImportDLLCounter==0x00)
		{
			*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x64]=*(DWORD*)&byImportReadbuff[dwImportCounter+0x04];
			*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x68]=m_objTempFile.m_stPEHeader.SectionAlignment;
		}

		dwImportCounter+=0x0C;


		while(byImportReadbuff[dwImportCounter]!=0x00)
		{
			if(dwImportCounter+dwOrigAPIOffset+0x01 > m_objTempFile.m_dwFileSize)
			{
				free(*byImportTableBuildbuff);
				*byImportTableBuildbuff=NULL;
				return false;
			}
			while(dwImportSize<dwImportSizeBuild+0x03+byImportReadbuff[dwImportCounter])
			{
				if(!(*byImportTableBuildbuff=(BYTE*)realloc(*byImportTableBuildbuff,dwImportSize+m_objTempFile.m_stPEHeader.SectionAlignment)))
				{
					free(*byImportTableBuildbuff);
					*byImportTableBuildbuff=NULL;
					return false;
				}
				memset(&(*byImportTableBuildbuff)[dwImportSize],0x00,m_objTempFile.m_stPEHeader.SectionAlignment);
				dwImportSize+=m_objTempFile.m_stPEHeader.SectionAlignment;
			}

			if(dwImportAPIOffset + dwOrigAPIOffset + 0x01 > m_objTempFile.m_dwFileSize)
			{
				free(*byImportTableBuildbuff);
				*byImportTableBuildbuff=NULL;
				return false;
			}
			if(byImportReadbuff[dwImportAPIOffset]==0xFF)
			{
				if(dwImportAPIOffset+0x05+dwOrigAPIOffset > m_objTempFile.m_dwFileSize)
				{
					free(*byImportTableBuildbuff);
					*byImportTableBuildbuff=NULL;
					return false;	
				}
				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportTableBuildbuff)[(dwImportDLLCounter*0x14)+0x10]+dwAPICounter]=*(DWORD*)&byImportReadbuff[dwImportAPIOffset+0x01];
			}
			else
			{
				if(*(DWORD*)&(*byImportTableBuildbuff)[(dwImportDLLCounter*0x14)+0x10]+dwAPICounter+0x04 > m_objTempFile.m_dwFileSize)
				{
					free(*byImportTableBuildbuff);
					*byImportTableBuildbuff=NULL;
					return false;
				}
				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportTableBuildbuff)[(dwImportDLLCounter*0x14)+0x10]+dwAPICounter]=SA(m_objTempFile.m_dwFileSize)+dwImportSizeBuild;
				dwImportSizeBuild+=0x02;
				if(dwImportCounter+dwImportAPIOffset+dwOrigAPIOffset+byImportReadbuff[dwImportCounter]>m_objTempFile.m_dwFileSize)
				{
					free(*byImportTableBuildbuff);
					*byImportTableBuildbuff=NULL;
					return false;
				}
				memcpy(&(*byImportTableBuildbuff)[dwImportSizeBuild],&byImportReadbuff[dwImportAPIOffset],byImportReadbuff[dwImportCounter]);
				dwImportSizeBuild+=byImportReadbuff[dwImportCounter];
			}
			dwImportAPIOffset+=byImportReadbuff[dwImportCounter];
			dwImportCounter++;
			dwAPICounter+=0x04;
		}
		dwImportCounter++;
		dwImportDLLCounter++;
	}	dwImportSizeBuild=dwImportSize;
	return true;
}
