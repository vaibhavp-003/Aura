#pragma once
#include "WinUpackUnpack.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CWinUpackUnpacker::CWinUpackUnpacker(CMaxPEFile *pMaxPEFile): CUnpackBase(pMaxPEFile)
{
	m_dwOffset = m_pMaxPEFile->m_dwAEPMapped;
	m_UpackType = NORMAL;	
}

CWinUpackUnpacker::~CWinUpackUnpacker(void)
{
	m_objTempFile.CloseFile();
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
}

bool CWinUpackUnpacker::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections >= 2 && 
		((_memicmp(m_pMaxPEFile->m_stSectionHeader[0].Name, ".Upack", 6) == 0 &&
		_memicmp(m_pMaxPEFile->m_stSectionHeader[1].Name, ".rsrc", 5) == 0) ||
		(m_pMaxPEFile->m_dwAEPMapped<m_pMaxPEFile->m_stPEHeader.SizeOfHeaders) ||(m_iCurrentLevel>0)))	
	{	
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}
		DWORD dwAEPMappedRead=m_pMaxPEFile->m_dwAEPMapped;
		if(m_pMaxPEFile->m_dwAEPMapped<m_pMaxPEFile->m_stPEHeader.SizeOfHeaders)
		{
			dwAEPMappedRead-=m_pMaxPEFile->m_stSectionHeader[0].PointerToRawData;
		}

		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,dwAEPMappedRead,0xC,0xC))
		{
			return false;
		}

		//By default
		if(m_pbyBuff[0]==0xBE && *(DWORD*)&m_pbyBuff[0x5]==0x76FF50AD && *(WORD*)&m_pbyBuff[0x09]==0xEB34)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
			m_dwOffset+=0x0C+m_pbyBuff[0x0B];
			return true;
		}
		else if(m_pbyBuff[0]==0xBE && *(DWORD*)&m_pbyBuff[0x5]==0x95F88BAD && *(WORD*)&m_pbyBuff[0x09]==0x91AD)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
			m_UpackType=NORMALMOD2;
			return true;
		}
		else if(m_pbyBuff[0]==0xBE && *(WORD*)&m_pbyBuff[0x5]==0x50AD && m_pbyBuff[0x7]==0xE8)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&m_pbyBuff[0x08]+0x0C;
			m_UpackType=DECRYPT_NORMAL;
			return true;
		}
		else if(m_pbyBuff[0]==0xE8 && *(DWORD*)&m_pbyBuff[0x5]==0x76FF50AD && m_pbyBuff[0x9]==0x34)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&m_pbyBuff[0x01]+0x05;
			m_UpackType=DECRYPT_NORMAL2;
			return true;
		}
		else if(m_pbyBuff[0]==0xBE && *(WORD*)&m_pbyBuff[0x05]==0x36FF && m_pbyBuff[7]==0xE9)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
			m_dwOffset+=0x08+*(DWORD*)&m_pbyBuff[0x8]+0x04;
			m_UpackType=NORMALMOD;
			return true;

		}
		else if(*(WORD*)&m_pbyBuff[0]==0xE860 && *(DWORD*)&m_pbyBuff[2]==0x09 && m_pbyBuff[0xA]==0xE9)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint;
			m_UpackType=PUSHAD;
			return true;
		}
		else if(m_pbyBuff[0]==0xE9)
		{
			m_dwOffset=m_pMaxPEFile->m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&m_pbyBuff[0x1]+0x05;
			if(OUT_OF_FILE==m_pMaxPEFile->Rva2FileOffset(m_dwOffset,&dwAEPMappedRead))
			{
				return false;
			}
			if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,dwAEPMappedRead,0xC,0xC))
			{
				return false;
			}
			if(m_pbyBuff[0]==0xBE && *(DWORD*)&m_pbyBuff[5]==0x95F88BAD && m_pbyBuff[0x9]==0xAD)
			{
				m_UpackType=JMP;
				return true;
			}
		}
	}
	return false;
}

bool CWinUpackUnpacker::Unpack(LPCTSTR szTempFileName)
{
	if(!ReOrganizeFile(szTempFileName,true,false))
	{
		return false;
	}

	BYTE *byFullFilebuff=NULL;
	if(!(byFullFilebuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize+0x30)))
	{
		return false;
	}
	memset(&byFullFilebuff[m_objTempFile.m_dwFileSize],0,0x30);
	if(!m_objTempFile.ReadBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}



	BYTE byLZMAProp[4]={0x00};
	BYTE *byImportBuff=NULL;
	DWORD dwImportSize=0x0;
	DWORD dwNewAEPUnmapped=0x00;
	BYTE byCompare=0x00;

	//Checking for Decryption if there is one
	if(m_UpackType==DECRYPT_NORMAL || m_UpackType==DECRYPT_NORMAL2)
	{
		CEmulate objEmulate(&m_objTempFile);
		DWORD dwLength = 0, dwInstructionCountFound = 0;
		DWORD dwTotalInstructionCount=0;
		char	szInstruction[1024] = {0x00};
		DWORD dwSize=0,dwXORKey=0;

		DWORD dwSrcRVA=*(DWORD*)&m_pbyBuff[0x01]-m_dwImageBase;
		while(m_dwOffset<m_objTempFile.m_dwFileSize && dwTotalInstructionCount<0x100)
		{
			dwLength=objEmulate.DissassemBuffer((char*)&byFullFilebuff[m_dwOffset],szInstruction);
			dwTotalInstructionCount++;
			if(strstr(szInstruction,"MOV ECX") && dwLength==0x05)
			{
				dwSize=*(DWORD*)&byFullFilebuff[m_dwOffset+0x01];				
			}
			if(strstr(szInstruction,"MOV ESI") && dwLength==0x05)
			{
				dwSrcRVA=*(DWORD*)&byFullFilebuff[m_dwOffset+0x01]-m_dwImageBase;				
			}
			else if(strstr(szInstruction,"XOR") && dwLength==0x06)
			{
				dwXORKey=*(DWORD*)&byFullFilebuff[m_dwOffset+0x02];
				break;
			}
			else if(strstr(szInstruction,"JMP") && dwLength==0x02)
			{
				m_dwOffset+=byFullFilebuff[m_dwOffset+0x01];
			}
			m_dwOffset+=dwLength;
		}

		
		if(dwSrcRVA<0x28)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		dwSrcRVA=*(DWORD*)&byFullFilebuff[dwSrcRVA-0x28];
		dwSrcRVA-=m_dwImageBase;

		if(dwSrcRVA+dwSize>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		for(DWORD i=0;i<dwSize;i+=4)
		{
			*(DWORD*)&byFullFilebuff[dwSrcRVA+i]^=dwXORKey;
		}

		m_dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;
		m_dwOffset+=0x0C+0x7C;
		m_UpackType=NORMAL;
	}



	//Normal Decompressions
	if(m_UpackType==NORMAL)
	{
		m_dwOffset+=0x08;

		if(m_dwOffset+0x06>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(*(DWORD*)&byFullFilebuff[m_dwOffset]-m_dwImageBase+(byFullFilebuff[m_dwOffset+0x05]*0x04)+sizeof(BLOCKINFO)-0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		BLOCKINFO *pStructBlockInfo=(BLOCKINFO*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[m_dwOffset]-m_dwImageBase+(byFullFilebuff[m_dwOffset+0x05]*0x04)-0x04];

		m_dwOffset+=0x06;
		m_dwOffset+=0x0D;
		if(m_dwOffset+0x01 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		m_dwOffset+=byFullFilebuff[m_dwOffset]+0x01;
		m_dwOffset+=0x14;

		DWORD dwTempOffset=0x00;

		if(m_dwOffset+0x05 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(byFullFilebuff[m_dwOffset+0x04]==0x56)
		{
			dwTempOffset+=0x03;
		}
		dwTempOffset+=0x04;

		dwTempOffset+=0x17;

		if(m_dwOffset+dwTempOffset+0x01 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(byFullFilebuff[m_dwOffset+dwTempOffset]==0x33)
		{
			dwTempOffset+=0x01;
		}

		dwTempOffset+=0x36;

		if(m_dwOffset+dwTempOffset+0x1 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		byCompare=byFullFilebuff[m_dwOffset+dwTempOffset];
		if(m_dwOffset+0x04 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		m_dwOffset+=*(DWORD*)&byFullFilebuff[m_dwOffset]+0x04;

		dwTempOffset=0x00;
		m_dwOffset+=0x09;

		if(byFullFilebuff[m_dwOffset]==0x04)
		{
			m_dwOffset+=0x11;
		}
		else
		{
			m_dwOffset+=0x13;
		}

		if(m_dwOffset+0x01 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}	


		//To determine the LC parameter used
		byLZMAProp[0]=0x08-byFullFilebuff[m_dwOffset];

		if(pStructBlockInfo->dwWriteOffset-m_dwImageBase+pStructBlockInfo->dwWriteEnd-pStructBlockInfo->dwWriteOffset>m_objTempFile.m_dwFileSize || 
			pStructBlockInfo->dwSrcRead-m_dwImageBase +pStructBlockInfo->dwSrcEnd-pStructBlockInfo->dwSrcRead>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!LZMADecompress(byLZMAProp,pStructBlockInfo->dwSrcEnd-pStructBlockInfo->dwSrcRead,
			pStructBlockInfo->dwWriteEnd-pStructBlockInfo->dwWriteOffset,
			0x00,0x00,&byFullFilebuff[pStructBlockInfo->dwWriteOffset-m_dwImageBase],&byFullFilebuff[pStructBlockInfo->dwSrcRead-m_dwImageBase],1))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveE8E9Calls(&byFullFilebuff[pStructBlockInfo->dwWriteOffset-m_dwImageBase],pStructBlockInfo->dwWriteEnd-pStructBlockInfo->dwWriteOffset,pStructBlockInfo->dwResolveCallsLoop,pStructBlockInfo->dwResolveCallsOffs,pStructBlockInfo->dwWriteOffset,byCompare))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}


		if(!ResolveImports(&byFullFilebuff[0],&byImportBuff,&dwImportSize,pStructBlockInfo->dwResolveImports-m_dwImageBase))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			if(byImportBuff)
			{
				free(byImportBuff);
			}
			byImportBuff=NULL;
			return false;
		}
		dwNewAEPUnmapped=pStructBlockInfo->dwAEP-m_dwImageBase;
	}

	else if(m_UpackType==PUSHAD)
	{
		m_dwOffset+=0xB;

		if(m_dwOffset+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		m_dwOffset+=*(DWORD*)&byFullFilebuff[m_dwOffset]+0x04;

		if(m_dwOffset+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		byCompare=byFullFilebuff[m_dwOffset-0x54];
		m_dwOffset+=0x02;
		dwNewAEPUnmapped=*(DWORD*)&byFullFilebuff[m_dwOffset]+m_dwOffset+0x04;

		m_dwOffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+0x06;

		if(m_dwOffset-*(DWORD*)&byFullFilebuff[m_dwOffset]+CUnpackBase::m_iDataCnt*0x28+sizeof(BLOCKINFOPUSHAD)>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		BLOCKINFOPUSHAD	*pStructPUSHADBlockInfo=(BLOCKINFOPUSHAD*)&byFullFilebuff[m_dwOffset-*(DWORD*)&byFullFilebuff[m_dwOffset]+CUnpackBase::m_iDataCnt*0x28];

		m_dwOffset=pStructPUSHADBlockInfo->dwLZMAOffset-m_dwImageBase;
		m_dwOffset+=0x1C;

		if(m_dwOffset+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		byLZMAProp[0]=byFullFilebuff[m_dwOffset];

		if(pStructPUSHADBlockInfo->dwWriteOffset-m_dwImageBase+pStructPUSHADBlockInfo->dwWriteEnd-pStructPUSHADBlockInfo->dwWriteOffset>m_objTempFile.m_dwFileSize || 
			pStructPUSHADBlockInfo->dwSrcRead-m_dwImageBase +pStructPUSHADBlockInfo->dwSrcEnd-pStructPUSHADBlockInfo->dwSrcRead>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!LZMADecompress(byLZMAProp,pStructPUSHADBlockInfo->dwSrcEnd-pStructPUSHADBlockInfo->dwSrcRead,
			pStructPUSHADBlockInfo->dwWriteEnd-pStructPUSHADBlockInfo->dwWriteOffset,
			0x00,pStructPUSHADBlockInfo->dwWriteOffset-m_dwImageBase,&byFullFilebuff[pStructPUSHADBlockInfo->dwWriteOffset-m_dwImageBase],
			&byFullFilebuff[pStructPUSHADBlockInfo->dwSrcRead-m_dwImageBase],1))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveE8E9Calls(&byFullFilebuff[pStructPUSHADBlockInfo->dwWriteOffset-m_dwImageBase],pStructPUSHADBlockInfo->dwWriteEnd-pStructPUSHADBlockInfo->dwWriteOffset,pStructPUSHADBlockInfo->dwResolveCallsLoop,pStructPUSHADBlockInfo->dwResolveCallsOffsetSubtract,pStructPUSHADBlockInfo->dwWriteOffset,byCompare))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveImports(&byFullFilebuff[0],&byImportBuff,&dwImportSize,pStructPUSHADBlockInfo->dwResolveImports-m_dwImageBase))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			if(byImportBuff)
			{
				free(byImportBuff);
			}
			byImportBuff=NULL;
			return false;
		}

	}
	else if(m_UpackType==JMP)
	{
		if(m_dwOffset+0x02>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		m_dwOffset=*(DWORD*)&byFullFilebuff[m_dwOffset+0x01]-m_dwImageBase+CUnpackBase::m_iDataCnt*0x28;
		m_dwOffset+=0x04;

		if(m_dwOffset+0x08>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		dwNewAEPUnmapped=*(DWORD*)&byFullFilebuff[m_dwOffset+0x04];
		m_dwOffset+=*(DWORD*)&byFullFilebuff[m_dwOffset]*0x04+0x04;

		if(m_dwOffset+sizeof(BLOCKINFOJMP)>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		BLOCKINFOJMP *pStructJMPBlockInfo=(BLOCKINFOJMP*)&byFullFilebuff[m_dwOffset];
		pStructJMPBlockInfo->dwSrcRead=dwNewAEPUnmapped;
		if(pStructJMPBlockInfo->dwToCalculateAEP<m_dwImageBase || pStructJMPBlockInfo->dwToCalculateAEP-m_dwImageBase-0x23>m_objTempFile.m_dwFileSize )
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;         
		}
		dwNewAEPUnmapped=pStructJMPBlockInfo->dwToCalculateAEP-m_dwImageBase-0x23+*(DWORD*)&byFullFilebuff[pStructJMPBlockInfo->dwToCalculateAEP-m_dwImageBase-0x23]+0x04;
		if(pStructJMPBlockInfo->dwToCalculateAEP-m_dwImageBase-0x3E+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		byCompare=byFullFilebuff[pStructJMPBlockInfo->dwToCalculateAEP-m_dwImageBase-0x3E];
		m_dwOffset=pStructJMPBlockInfo->dwToCalculateLZMAlcAndSrcEnd-m_dwImageBase+0x1C;

		if(m_dwOffset+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		byLZMAProp[0]=byFullFilebuff[m_dwOffset];

		if(pStructJMPBlockInfo->dwWriteOffSet-m_dwImageBase+pStructJMPBlockInfo->dwWriteEnd-pStructJMPBlockInfo->dwWriteOffSet>m_objTempFile.m_dwFileSize || 
			pStructJMPBlockInfo->dwSrcRead-m_dwImageBase +pStructJMPBlockInfo->dwToCalculateLZMAlcAndSrcEnd-pStructJMPBlockInfo->dwSrcRead>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!LZMADecompress(byLZMAProp,pStructJMPBlockInfo->dwToCalculateLZMAlcAndSrcEnd-pStructJMPBlockInfo->dwSrcRead,
			pStructJMPBlockInfo->dwWriteEnd-pStructJMPBlockInfo->dwWriteOffSet,0x00,
			pStructJMPBlockInfo->dwWriteOffSet-m_dwImageBase,&byFullFilebuff[pStructJMPBlockInfo->dwWriteOffSet-m_dwImageBase],&byFullFilebuff[pStructJMPBlockInfo->dwSrcRead-m_dwImageBase],0x1))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveE8E9Calls(&byFullFilebuff[pStructJMPBlockInfo->dwWriteOffSet-m_dwImageBase],pStructJMPBlockInfo->dwWriteEnd-pStructJMPBlockInfo->dwWriteOffSet,pStructJMPBlockInfo->dwResolveCallsLoop,pStructJMPBlockInfo->dwResolveCallsOffsetSubtract,pStructJMPBlockInfo->dwWriteOffSet,byCompare))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveImports(&byFullFilebuff[0],&byImportBuff,&dwImportSize,pStructJMPBlockInfo->dwResolveImports-m_dwImageBase))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			if(byImportBuff)
			{
				free(byImportBuff);
			}
			byImportBuff=NULL;
			return false;
		}
	}
	else if(m_UpackType==NORMALMOD)
	{
		dwNewAEPUnmapped=*(DWORD*)&m_pbyBuff[0x1]-m_dwImageBase;

		if(dwNewAEPUnmapped+0x04 > m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		dwNewAEPUnmapped=*(DWORD*)&byFullFilebuff[dwNewAEPUnmapped]-m_dwImageBase;

		m_dwOffset+=0x07;

		if(m_dwOffset+0x0B > m_objTempFile.m_dwFileSize || *(DWORD*)&byFullFilebuff[m_dwOffset]-m_dwImageBase+(byFullFilebuff[m_dwOffset+0xA]*0x04)-0x04+sizeof(BLOCKNORMALMODINFO)>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		BLOCKNORMALMODINFO *pStructNORMALMODBlockInfo=(BLOCKNORMALMODINFO*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[m_dwOffset]-m_dwImageBase+(byFullFilebuff[m_dwOffset+0xA]*0x04)-0x04];
		m_dwOffset+=0x0A;

		m_dwOffset+=0x1F;

		if(m_dwOffset+0x1E>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		byCompare=byFullFilebuff[m_dwOffset+0x1D];

		m_dwOffset+=*(DWORD*)&byFullFilebuff[m_dwOffset+0x01]+0x05;
		m_dwOffset+=0x1A;

		if(*(WORD*)&byFullFilebuff[m_dwOffset]==0xEDC1 && *(WORD*)&byFullFilebuff[m_dwOffset+0x03]==0xE5C1)
		{
			byLZMAProp[0]=0x08-byFullFilebuff[m_dwOffset+0x02];
		}
		else
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		pStructNORMALMODBlockInfo->dwWriteOffset+=m_dwImageBase;

		if(pStructNORMALMODBlockInfo->dwWriteOffset-m_dwImageBase+pStructNORMALMODBlockInfo->dwWriteEnd-pStructNORMALMODBlockInfo->dwWriteOffset>m_objTempFile.m_dwFileSize || 
			pStructNORMALMODBlockInfo->dwSrcRead-m_dwImageBase +pStructNORMALMODBlockInfo->dwSrcEnd-pStructNORMALMODBlockInfo->dwSrcRead>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!LZMADecompress(byLZMAProp,pStructNORMALMODBlockInfo->dwSrcEnd-pStructNORMALMODBlockInfo->dwSrcRead,
			pStructNORMALMODBlockInfo->dwWriteEnd-pStructNORMALMODBlockInfo->dwWriteOffset,
			0x00,pStructNORMALMODBlockInfo->dwWriteEnd-pStructNORMALMODBlockInfo->dwWriteOffset,&byFullFilebuff[pStructNORMALMODBlockInfo->dwWriteOffset-m_dwImageBase],&byFullFilebuff[pStructNORMALMODBlockInfo->dwSrcRead-m_dwImageBase],0x1))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveE8E9Calls(&byFullFilebuff[pStructNORMALMODBlockInfo->dwWriteOffset-m_dwImageBase],pStructNORMALMODBlockInfo->dwWriteEnd-pStructNORMALMODBlockInfo->dwWriteOffset,pStructNORMALMODBlockInfo->dwResolveCallsLoop,pStructNORMALMODBlockInfo->dwResolveCallsOffsetSubtract,pStructNORMALMODBlockInfo->dwWriteOffset,byCompare))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveImports(&byFullFilebuff[0],&byImportBuff,&dwImportSize,pStructNORMALMODBlockInfo->dwResolveImports-m_dwImageBase))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			if(byImportBuff)
			{
				free(byImportBuff);
			}
			byImportBuff=NULL;
			return false;
		}
	}
	else if(m_UpackType==NORMALMOD2)
	{
		dwNewAEPUnmapped=*(DWORD*)&m_pbyBuff[0x1]-m_dwImageBase+CUnpackBase::m_iDataCnt*0x28;
		dwNewAEPUnmapped+=0x08;

		if(dwNewAEPUnmapped+sizeof(BLOCKNORMALMOD2INFO)>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		BLOCKNORMALMOD2INFO *m_pStructBlockMod2Info=(BLOCKNORMALMOD2INFO*)&byFullFilebuff[dwNewAEPUnmapped];

		if(m_pStructBlockMod2Info->dwSrcEndLZMACalculatelc-m_dwImageBase-0x3E+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		byCompare=byFullFilebuff[m_pStructBlockMod2Info->dwSrcEndLZMACalculatelc-m_dwImageBase-0x3E];

		if(m_pStructBlockMod2Info->dwSrcEndLZMACalculatelc-m_dwImageBase-0x23+0x04>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		dwNewAEPUnmapped=*(DWORD*)&byFullFilebuff[m_pStructBlockMod2Info->dwSrcEndLZMACalculatelc-m_dwImageBase-0x23]+(m_pStructBlockMod2Info->dwSrcEndLZMACalculatelc-m_dwImageBase-0x23)+0x04;

		if(m_pStructBlockMod2Info->dwStartofLZMA-m_dwImageBase+0x1C+0x01>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		byLZMAProp[0]=byFullFilebuff[m_pStructBlockMod2Info->dwStartofLZMA-m_dwImageBase+0x1C];

		if(m_pStructBlockMod2Info->dwWriteOffset-m_dwImageBase+m_pStructBlockMod2Info->dwWriteEnd-m_pStructBlockMod2Info->dwWriteOffset>m_objTempFile.m_dwFileSize || 
			m_pStructBlockMod2Info->dwSrcRead-m_dwImageBase +m_pStructBlockMod2Info->dwSrcEndLZMACalculatelc-m_pStructBlockMod2Info->dwSrcRead>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!LZMADecompress(byLZMAProp,m_pStructBlockMod2Info->dwSrcEndLZMACalculatelc-m_pStructBlockMod2Info->dwSrcRead,
			m_pStructBlockMod2Info->dwWriteEnd-m_pStructBlockMod2Info->dwWriteOffset,
			0x00,m_pStructBlockMod2Info->dwWriteEnd-m_pStructBlockMod2Info->dwWriteOffset,&byFullFilebuff[m_pStructBlockMod2Info->dwWriteOffset-m_dwImageBase],&byFullFilebuff[m_pStructBlockMod2Info->dwSrcRead-m_dwImageBase],0x1))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveE8E9Calls(&byFullFilebuff[m_pStructBlockMod2Info->dwWriteOffset-m_dwImageBase],m_pStructBlockMod2Info->dwWriteEnd-m_pStructBlockMod2Info->dwWriteOffset,m_pStructBlockMod2Info->dwResolveCallsLoop,m_pStructBlockMod2Info->dwResolveCallsOffsetSubtract,m_pStructBlockMod2Info->dwWriteOffset,byCompare))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!ResolveImports(&byFullFilebuff[0],&byImportBuff,&dwImportSize,m_pStructBlockMod2Info->dwResolveImports-m_dwImageBase))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			if(byImportBuff)
			{
				free(byImportBuff);
			}
			byImportBuff=NULL;
			return false;
		}




	}

	*(WORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NumberOfSections]=m_objTempFile.m_stPEHeader.NumberOfSections+1;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=/**/(m_objTempFile.m_dwFileSize);
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=dwNewAEPUnmapped;

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

	if(dwImportSize!=0x00)
	{
		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			free(byImportBuff);
			byImportBuff=NULL;
			return false;
		}

		//Adding a new Section
		if(!AddNewSection(dwImportSize,1))
		{
			free(byImportBuff);
			byImportBuff=NULL;
			return false;
		}

		m_objTempFile.CloseFile();
		if(!m_objTempFile.OpenFile(szTempFileName, true))
		{
			free(byImportBuff);
			byImportBuff=NULL;
			return false;
		}

		//Writing the basic Import Directory Table buffer to memory
		if(!m_objTempFile.WriteBuffer(byImportBuff, /**/(m_objTempFile.m_dwFileSize), dwImportSize, dwImportSize))
		{
			free(byImportBuff);
			byImportBuff=NULL;
			return false;
		}	

		if(byImportBuff)
		{
			free(byImportBuff);
			byImportBuff=NULL;
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


bool CWinUpackUnpacker::ResolveImports(BYTE *byFullFilebuff,BYTE **byImportbuff,DWORD *dwImportSize,DWORD dwImportsOffset)
{
	if(dwImportsOffset+0x05>m_objTempFile.m_dwFileSize)
	{
		return false;
	}

	dwImportsOffset++;
	DWORD dwImportAPIOffset=0x00;
	DWORD dwStrLenAPI=0x00;

	while(*(DWORD*)&byFullFilebuff[dwImportsOffset]!=0x00)
	{
		if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,*dwImportSize+0x14)))
		{
			return false;
		}
		memset( &(*byImportbuff)[*dwImportSize],0x00,0x14);
		*(DWORD*)&(*byImportbuff)[*dwImportSize+0x10]=*(DWORD*)&byFullFilebuff[dwImportsOffset]-m_dwImageBase;

		dwImportsOffset+=0x04;

		dwStrLenAPI=0x00;
		while(byFullFilebuff[dwImportsOffset+dwStrLenAPI]!=0x00)
		{
			if(dwImportsOffset+dwStrLenAPI>m_objTempFile.m_dwFileSize)
			{
				return false;
			}
			dwStrLenAPI++;
		}
		*(DWORD*)&(*byImportbuff)[*dwImportSize+0x0C]=dwImportsOffset;


		if(dwImportsOffset+dwStrLenAPI+0x01>m_objTempFile.m_dwFileSize)
		{
			return false;
		}

		dwImportsOffset+=dwStrLenAPI+1;

		dwImportAPIOffset=0x00;
		while(1)
		{
			dwStrLenAPI=0x00;
			if((byFullFilebuff[dwImportsOffset]&0x80)!=0x80)
			{
				while(byFullFilebuff[dwImportsOffset+dwStrLenAPI]!=0x00)
				{
					if(dwImportsOffset+dwStrLenAPI>m_objTempFile.m_dwFileSize)
					{
						return false;
					}
					dwStrLenAPI++;
				}
			}

			if(*(DWORD*)&(*byImportbuff)[*dwImportSize+0x10]+dwImportAPIOffset+0x04>m_objTempFile.m_dwFileSize)
			{
				return false;
			}


			if(dwImportsOffset+dwStrLenAPI+0x02>m_objTempFile.m_dwFileSize)
			{
				return false;
			}

			if((byFullFilebuff[dwImportsOffset]&0x80)==0x80)
			{

				if(dwImportsOffset+dwStrLenAPI+0x04>m_objTempFile.m_dwFileSize)
				{
					return false;
				}

				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportbuff)[*dwImportSize+0x10]+dwImportAPIOffset]=
					IMAGE_ORDINAL_FLAG32|*(WORD*)&byFullFilebuff[dwImportsOffset+0x01];
				dwImportsOffset+=0x03;				
			}
			else
			{
				*(DWORD*)&byFullFilebuff[*(DWORD*)&(*byImportbuff)[*dwImportSize+0x10]+dwImportAPIOffset]=dwImportsOffset-0x02;

			}

			dwImportAPIOffset+=0x04;
			dwImportsOffset+=dwStrLenAPI+1;

			if(byFullFilebuff[dwImportsOffset]==0x00)
			{
				*dwImportSize+=0x14;
				dwImportsOffset+=0x01;
				break;
			}
		}

		if(dwImportsOffset+0x04>m_objTempFile.m_dwFileSize)
		{
			return false;
		}
	}

	if(!(*byImportbuff=(BYTE*)realloc(*byImportbuff,SA(*dwImportSize))))
	{
		return false;
	}
	memset( &(*byImportbuff)[*dwImportSize],0x00,SA(*dwImportSize)-*dwImportSize);
	*dwImportSize=SA(*dwImportSize);
	return true;
}


bool CWinUpackUnpacker::ResolveE8E9Calls(BYTE *bySrcbuff,DWORD dwUncompressedLengthSize,DWORD dwCounterSize,DWORD dwResolveCallsOffs,DWORD dwResolveCallsStart,BYTE byCompare)
{
	DWORD dwCounter=0x00;
	for(dwCounter;dwCounter<dwUncompressedLengthSize-0x05 && dwCounterSize>0;dwCounter++)
	{
		if(bySrcbuff[dwCounter]==0xE8 || bySrcbuff[dwCounter]==0xE9)
		{
			if(bySrcbuff[dwCounter+0x01]==byCompare)
			{
				bySrcbuff[dwCounter+0x01]=0x00;
				*(DWORD*)&bySrcbuff[dwCounter+0x01]=ntohl(*(DWORD*)&bySrcbuff[dwCounter+0x01]);		
				*(DWORD*)&bySrcbuff[dwCounter+0x01]+=dwResolveCallsOffs;
				*(DWORD*)&bySrcbuff[dwCounter+0x01]-=(dwCounter+1+dwResolveCallsStart);
				dwCounter+=0x04;
				dwCounterSize--;
			}
		}

	}
	return true;
}