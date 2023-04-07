#include "TelockDecryptor.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CTelockDecryptor::CTelockDecryptor(CMaxPEFile *pMaxPEFile): 
CUnpackBase(pMaxPEFile)
{
}

CTelockDecryptor::~CTelockDecryptor(void)
{
	if(m_pbyBuff)
	{
		delete[] m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CTelockDecryptor::IsPacked() 
{
	if( m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 &&  
		(m_pMaxPEFile->m_wAEPSec==m_pMaxPEFile->m_stPEHeader.NumberOfSections-1) &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].SizeOfRawData<=m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize &&
		(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Misc.VirtualSize%0x1000)==0x0 &&
		m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Characteristics==0xC0000040 )		
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pbyBuff)
		{
			return false;
		}
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x05,0x05))
		{
			return false;
		}
		if(m_pbyBuff[0]==0xE9 && (*(DWORD*)&m_pbyBuff[1]&0x80000000)==0x80000000 && m_pMaxPEFile->m_dwAEPMapped+*(DWORD*)&m_pbyBuff[1]+0x05==m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData)
		{
			if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[5],m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].PointerToRawData,0x0C,0x0C))
			{
				return false;
			}
			if(m_pbyBuff[0x07]==0xE8 && *(DWORD*)&m_pbyBuff[0x08]==0x00000002 &&
				m_pbyBuff[0x0C]==0xE8 && *(DWORD*)&m_pbyBuff[0x0D]==0x0000E800)
			{
				return true;
			}

		}
	}
	return false;
}

bool CTelockDecryptor::Unpack(LPCTSTR szTempFileName)
{	
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	DWORD dwoffset=m_objTempFile.m_stPEHeader.AddressOfEntryPoint+*(DWORD*)&m_pbyBuff[0x1]+0x05;

	BYTE *byFullFilebuff=NULL;
	//Just allocating a buffer of 30h extra for the length of the max_instruction
	if(!(byFullFilebuff=(BYTE*)MaxMalloc(m_objTempFile.m_dwFileSize+0x30)))
	{
		return false;
	}
	//Filling the extra 30h bytes with zeroes
	memset(&byFullFilebuff[m_objTempFile.m_dwFileSize],0x00,0x30);
	if(!m_objTempFile.ReadBuffer(byFullFilebuff,0,m_objTempFile.m_dwFileSize,m_objTempFile.m_dwFileSize))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DWORD dwCounter=*(DWORD*)&byFullFilebuff[dwoffset+0x17];
	dwoffset+=0x0E+0x33;


	//****************First Decryption ********************
	//Simple XOR
	if(dwoffset+dwCounter >m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	DWORD dwKey=dwCounter;
	for(DWORD i=0;i<dwCounter;i++)
	{
		dwKey=dwKey*0x04 + (dwCounter-i) +0x67;
		byFullFilebuff[dwoffset+i]^=BYTE(dwKey);
		dwKey=(dwKey&0xFFFF00FF)|WORD((BYTE(dwKey)/9)<<8);
		dwKey=(dwKey&0xFFFFFF00)|BYTE((BYTE(dwKey)%9));
	}
	//****************First Decryption ********************

	//End of the first decryption acts as the offset for the file to continue
	DWORD dwDecryptOffset=0;
	DWORD dwDecryptOffset2=0;
	if(dwoffset+0x05>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwDecryptOffset2=dwoffset+0x06;
	dwoffset+=dwCounter;


	BYTE byKey2[4]={0};
	DWORD dwMulKey=0;
	DWORD dwRegIndex=0x8;
	bool bContinue=true;

	CEmulate objEmulate(&m_objTempFile);

	int iType=0;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//*********************Performing the 0x0D bytes decryption**************************/

	if(dwDecryptOffset+(0x0D*0x04)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(dwoffset+0x0C >m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//Getting the keys first
	//DWORD dwMulKey IMUL Reg,Reg,Value
	//XOR   dwDecrytOffset,dwMulKey
	//ROL   dwMulKey,0x03
	//DWORD dwADCKey ADC dwMulKey,dwADCKey
	//Plus 1 ADD Operation later down


	DWORD dwMulValue=byKey2[0];
	DWORD dwADCValue=byKey2[2];

	//Incase of STC opcode
	if(byKey2[3]==0x1) 
	{
		dwADCValue+=1;
	}

	for(DWORD i=0;i<0x0D;i++)
	{
		dwMulKey*=dwMulValue;
		*(DWORD*)&byFullFilebuff[dwDecryptOffset+(i<<2)]^=dwMulKey;
		MAX_ROL(dwMulKey,byKey2[1]);
		dwMulKey+=dwADCValue;
		dwMulKey+=dwRegIndex;
	}

	//*********************End of 0x0D bytes decryption**************************/


	//*********************Performing the 0x194A bytes decryption**************************/

	dwoffset=dwDecryptOffset;
	dwDecryptOffset=dwDecryptOffset2;

	if(dwoffset+0x14>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwCounter=*(DWORD*)&byFullFilebuff[dwoffset+0x08];
	dwMulKey=byFullFilebuff[dwoffset+0x08+0xF];
	dwMulValue=byFullFilebuff[dwoffset+0x08+0xF+0x07];

	//ROL Memory,MulKey
	//ADD Memory,Counter(Reverse)
	//XOR Memory,dwMulValue
	//INC Memory

	if(dwDecryptOffset+dwCounter>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	for(DWORD i=dwCounter;i>0;i--)
	{
		MAX_ROL(byFullFilebuff[dwDecryptOffset+i],BYTE(dwMulKey));
		byFullFilebuff[dwDecryptOffset+i]+=BYTE(i);
		byFullFilebuff[dwDecryptOffset+i]^=BYTE(dwMulValue);		
		byFullFilebuff[dwDecryptOffset+i]+=1;
	}

	//*********************End of 0x194A bytes decryption**************************/


	//*************Decryption of bytes which leads to the exception handler routine*****/

	dwoffset=dwDecryptOffset;
	dwoffset+=0x07;

	//dwoffset+=0x03;
	dwMulKey=0;
	dwDecryptOffset=0;
	dwRegIndex=0;
	iType=1;
	byKey2[1]=1;

	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwCounter=dwMulKey;
	dwDecryptOffset-=0x01;

	//DEC AL
	//XOR AL,CL
	//ROL AL,1
	//ADD AL,constant

	if(dwDecryptOffset+dwCounter>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	for(DWORD i=0;i<dwCounter;i++)
	{
		byFullFilebuff[dwDecryptOffset+i]-=1;
		byFullFilebuff[dwDecryptOffset+i]^=(dwCounter-i);
		MAX_ROL(byFullFilebuff[dwDecryptOffset+i],1);
		byFullFilebuff[dwDecryptOffset+i]+=byKey2[0];

	}

	//*************End of Decryption of bytes which leads to the exception handler routine*****/


	//*************Bypassing the Exception handler and setting of Hardware Debug breakpoints*****/
	dwoffset=dwDecryptOffset;
	DWORD dwEBPValue=dwoffset+0x05;

	dwoffset+=5;
	dwoffset+=1;

	if(dwoffset+0x03>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwoffset=dwEBPValue+byFullFilebuff[dwoffset+2];
	dwoffset+=*(DWORD*)&byFullFilebuff[dwoffset-0x04];

	//************Coming to the next set of decryptions after it resolves its Imports to use for decompression

	dwMulKey=0;
	dwDecryptOffset=0;
	dwRegIndex=0;

	iType=2;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,NULL,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	/*******Performing all decryptions till the CRC function is implemented*****/


	dwRegIndex=0;
	bContinue=true;

	while(bContinue)
	{
		dwMulKey=0;
		dwDecryptOffset=0;


		iType=3;
		byKey2[2]=0;
		byKey2[1]=0;
		if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		dwDecryptOffset+=dwEBPValue;
		if(dwDecryptOffset+dwMulKey>m_objTempFile.m_dwFileSize)
		{
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		//Operations performed
		//XOR AL,BL
		//INC AL
		//XOR AL,constant
		//ROL or ADD
		//XCHG AL,BL
		byKey2[3]=0;
		for(DWORD i=0;i<dwMulKey;i++)
		{
			byFullFilebuff[dwDecryptOffset+i]^=byKey2[3];
			byFullFilebuff[dwDecryptOffset+i]+=1;
			byFullFilebuff[dwDecryptOffset+i]^=byKey2[1];
			if(byKey2[2]==0x01)
			{
				MAX_ROL(byFullFilebuff[dwDecryptOffset+i],byKey2[0]);
			}
			else
			{
				byFullFilebuff[dwDecryptOffset+i]+=byKey2[0];
			}
			byKey2[3]=byFullFilebuff[dwDecryptOffset+i];
		}
		dwoffset=dwDecryptOffset;

	}


	//**********Implement the CRC function which is used as a key***************
	DWORD dwCRCLoop=dwDecryptOffset+dwMulKey-m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress;


	dwCRCLoop=ImplementCRCFunction(&byFullFilebuff[m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].VirtualAddress],dwCRCLoop);

	//******************End of CRC Implementation*******************************


	//XOR the CRCValue to get the final key to be used for decryption
	dwMulKey=0;
	dwDecryptOffset=0;
	dwRegIndex=0;
	iType=4;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(dwoffset+0x07 > m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwCRCLoop=(dwCRCLoop&0xFFFF0000)|WORD(WORD(dwCRCLoop)^*(WORD*)&byFullFilebuff[*(DWORD*)&byFullFilebuff[dwoffset+0x03]+dwEBPValue]);

	/**************************/


	dwoffset+=0x07;

	if(dwoffset+0x06>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwDecryptOffset2=*(DWORD*)&byFullFilebuff[dwoffset+0x02]+dwEBPValue;
	dwDecryptOffset2-=0x24;

	if(dwDecryptOffset2+sizeof(DecompressInfo)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	DecompressInfo *m_pStructDecompressInfo=(DecompressInfo*)&byFullFilebuff[dwDecryptOffset2];

	dwMulKey=0;
	dwDecryptOffset=0;
	dwRegIndex=0;
	iType=5;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwDecryptOffset+=dwEBPValue;
	dwRegIndex+=dwEBPValue;

	if(dwRegIndex+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwRegIndex=*(DWORD*)&byFullFilebuff[dwRegIndex];

	if(dwDecryptOffset+dwMulKey>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//for(DWORD i=0;i<0x1C4;i++)
	for(DWORD i=0;i<dwMulKey;i++)
	{
		MAX_ROL(dwRegIndex,1);
		byFullFilebuff[dwDecryptOffset+i]^=BYTE(dwRegIndex);
		dwRegIndex+=1;
	}

	DWORD dwStructureDecryptOffset=dwDecryptOffset2+0x24+0x08;
	dwDecryptOffset2=dwDecryptOffset+0x1B4;
	dwRegIndex=dwMulKey-0x1B4;

	dwMulKey=0;
	dwDecryptOffset=0;
	//dwRegIndex=0;
	iType=7;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwDecryptOffset+=dwEBPValue;

	if(dwDecryptOffset<0x14 && dwDecryptOffset+dwMulKey>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	for(DWORD i=0;i<dwMulKey;i++)
	{
		byFullFilebuff[dwDecryptOffset+i]^=byFullFilebuff[dwDecryptOffset-(i%0x14)-1];
		byFullFilebuff[dwDecryptOffset+i]-=byKey2[2];
		byFullFilebuff[dwDecryptOffset+i]^=BYTE((dwMulKey-i));
		byKey2[0]=byFullFilebuff[dwDecryptOffset+i];
		MAX_ROR(byFullFilebuff[dwDecryptOffset+i],BYTE((dwMulKey-i)));
		byFullFilebuff[dwDecryptOffset+i]^=byKey2[1];
		byKey2[1]+=byKey2[0];

	}

	//*************To Decrypt the main structure*************

	byKey2[0]=0;
	byKey2[1]=0;
	byKey2[2]=0;
	byKey2[3]=0;

	if(dwDecryptOffset2+0x10 >m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(!BuildJunkCodeandDecrypt(byFullFilebuff,dwDecryptOffset2,dwStructureDecryptOffset,byKey2,dwRegIndex))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//*******End of Decryption of Main Structure*********

	dwoffset=dwDecryptOffset;
	dwMulKey=0;
	dwDecryptOffset=0;
	dwRegIndex=0;
	iType=6;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(dwoffset+0x0C>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwoffset=dwEBPValue+*(DWORD*)&byFullFilebuff[dwoffset+0x08]+byFullFilebuff[dwEBPValue+*(DWORD*)&byFullFilebuff[dwoffset+0x02]]+0x04;


	//************Very close to decrypting the main Decryption routine...One more************/
	dwMulKey=0;
	dwDecryptOffset=0;
	dwRegIndex=0;
	iType=0;
	byKey2[0]=0;
	byKey2[1]=0;
	byKey2[2]=0;
	byKey2[3]=0;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(dwDecryptOffset+(0x40*0x04)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	if(dwoffset+0x0C >m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	//Getting the keys first
	//DWORD dwMulKey IMUL Reg,Reg,Value
	//XOR   dwDecrytOffset,dwMulKey
	//ROL   dwMulKey,0x01
	//DWORD dwADCKey ADC dwMulKey,dwADCKey
	//Plus 1 ADD Operation later down


	dwMulValue=byKey2[0];
	dwADCValue=byKey2[2];

	//Incase of STC opcode
	if(byKey2[3]==0x1) 
	{
		dwADCValue+=1;
	}

	for(DWORD i=0;i<0x40;i++)
	{
		dwMulKey*=dwMulValue;
		*(DWORD*)&byFullFilebuff[dwDecryptOffset+(i<<2)]^=dwMulKey;
		MAX_ROL(dwMulKey,byKey2[1]);
		dwMulKey+=dwADCValue;
		dwMulKey+=dwRegIndex;
	}

	//**********End of last decryption before the main source code decryption begins

	if(dwoffset+0x21+0x04>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	dwoffset=dwDecryptOffset;
	dwEBPValue=dwStructureDecryptOffset+0x08-(*(DWORD*)&byFullFilebuff[dwoffset+0x21]-m_dwImageBase);
	dwStructureDecryptOffset-=(0x08+0x024);
	dwoffset+=0x3D;
	m_pStructDecompressInfo->dwCRCKey=dwCRCLoop;

	iType=0x10;
	if(!(~(dwoffset=CallEmulatorDissambler(dwoffset,byFullFilebuff,objEmulate,&dwMulKey,&dwDecryptOffset,&dwRegIndex,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	iType=0x11;
	DWORD dwMulKey2=0;
	DWORD dwRegIndex2=0;
	if(!(~(dwRegIndex2=CallEmulatorDissambler(dwEBPValue+*(DWORD*)&byFullFilebuff[dwoffset+0x09]-m_dwImageBase,byFullFilebuff,objEmulate,&dwMulKey2,&dwDecryptOffset2,&dwRegIndex2,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}

	dwMulKey2=1;
	iType=0x12;
	if(!(~(dwRegIndex2=CallEmulatorDissambler(dwRegIndex2,byFullFilebuff,objEmulate,&dwMulKey2,&dwDecryptOffset2,&dwRegIndex2,byKey2,iType,&bContinue))))
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}
	int iDecompressionType=dwMulKey2;


	if(dwStructureDecryptOffset+sizeof(DecompressInfo)+sizeof(SingleBlockInfo)>m_objTempFile.m_dwFileSize)
	{
		free(byFullFilebuff);
		byFullFilebuff=NULL;
		return false;
	}


	dwStructureDecryptOffset+=sizeof(DecompressInfo);
	SingleBlockInfo *m_pStructSingleBlockInfo = NULL;



	BYTE *byDestbuff=new BYTE[1];
	DWORD dwDestSize=0;
	dwMulKey*=LOWORD(HIBYTE(dwRegIndex));
	while(m_pStructDecompressInfo->dwNoOfPECBlocks!=0x00)
	{
		m_pStructSingleBlockInfo=(SingleBlockInfo*)&byFullFilebuff[dwStructureDecryptOffset];

		if((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))!=0x00)
		{
			if(m_pStructSingleBlockInfo->dwRVA+(m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))>m_objTempFile.m_dwFileSize)
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			DWORD dwReg[3]={0};
			dwReg[0]=m_pStructSingleBlockInfo->dwSize; //EDX
			dwReg[1]=dwRegIndex;
			dwReg[2]=dwMulKey;
			if(!UnPackTelockCryporPolyEmulator(&byFullFilebuff[dwDecryptOffset],&byFullFilebuff[m_pStructSingleBlockInfo->dwRVA],(m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1)),dwoffset-dwDecryptOffset,dwReg))
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}

			DWORD dwCRC=m_pStructDecompressInfo->dwCRCKey;
			for(DWORD i=0;i<(m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1));i++)
			{
				byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i]^=byKey2[1];
				byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i]-=byKey2[2];
				byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i]^=BYTE((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))-i);
				byKey2[0]=byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i];
				MAX_ROR(byKey2[0],BYTE((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))-i));
				byKey2[0]^=BYTE(dwCRC);
				byKey2[3]=BYTE(BYTE(dwCRC)+byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i]);

				if(BYTE(dwCRC)<byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i])
				{

					if(byKey2[3]<BYTE(dwCRC))
					{
						dwCRC=(dwCRC&0xFFFFFF00)|byKey2[3];					
						byKey2[3]=1;
					}
					else
					{
						dwCRC=(dwCRC&0xFFFFFF00)|byKey2[3];
						byKey2[3]=0;
					}
				}
				else// if(BYTE(dwCRC)>byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i])
				{
					dwCRC=(dwCRC&0xFFFFFF00)|byKey2[3];
					if(byKey2[3]<byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i])
					{
						byKey2[3]=1;
					}
					else
					{
						byKey2[3]=0;
					}
				}

				dwCRC+=byKey2[3];
				dwCRC=(dwCRC&0xFFFFFF00)|BYTE(BYTE(dwCRC)+BYTE((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))-i));

				if(BYTE((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))-i)%2==0x00)
				{
					dwCRC>>=1;
					if((dwCRC&0x00000008)!=0x00000008)
					{
						MAX_ROL(dwCRC,BYTE((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))-i));
						dwCRC=dwCRC*8+dwCRC;
					}
				}
				byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i]=byKey2[0];
			}


			if((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32))==0x80000000)
			{
				WORD wRVASec=0xFF;
				if(!(~(wRVASec=m_objTempFile.Rva2FileOffset(m_pStructSingleBlockInfo->dwRVA,&m_pStructSingleBlockInfo->dwRVA))))
				{
					free(byDestbuff);
					byDestbuff=NULL;
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}
				if(dwDestSize<(m_objTempFile.m_stSectionHeader[wRVASec].Misc.VirtualSize))
				{
					if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_objTempFile.m_stSectionHeader[wRVASec].Misc.VirtualSize)))
					{
						free(byDestbuff);
						byDestbuff=NULL;
						free(byFullFilebuff);
						byFullFilebuff=NULL;
						return false;
					}
					dwDestSize=m_objTempFile.m_stSectionHeader[wRVASec].Misc.VirtualSize;

				}
				memset(byDestbuff,0,dwDestSize);




				if(!(~(m_pStructSingleBlockInfo->dwSize=APLIBDecompress((m_pStructSingleBlockInfo->dwSize&(IMAGE_ORDINAL_FLAG32-1))+0x10,m_objTempFile.m_stSectionHeader[wRVASec].Misc.VirtualSize,0,0,byDestbuff,iDecompressionType,&byFullFilebuff[m_pStructSingleBlockInfo->dwRVA]))))
				{
					free(byDestbuff);
					byDestbuff=NULL;
					free(byFullFilebuff);
					byFullFilebuff=NULL;
					return false;
				}

				for(DWORD i=0;i<m_pStructSingleBlockInfo->dwSize;i++)
				{
					byFullFilebuff[m_pStructSingleBlockInfo->dwRVA+i]=byDestbuff[i];
				}
			}
		}


		if(dwStructureDecryptOffset+sizeof(SingleBlockInfo)+sizeof(SingleBlockInfo)>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		dwStructureDecryptOffset+=sizeof(SingleBlockInfo);
		m_pStructDecompressInfo->dwNoOfPECBlocks--;

	}

	if(m_pStructDecompressInfo->dwRVADecompressRes!=0x00 && m_pStructDecompressInfo->dwOffsetInsideResolveImp!=0x00 && m_pStructDecompressInfo->dwDestResolveImpSize!=0x00)
	{
		WORD wRVASec=0xFF;
		if(!(~(wRVASec=m_objTempFile.Rva2FileOffset(m_pStructDecompressInfo->dwRVADecompressRes+m_pStructDecompressInfo->dwOffsetAddResolve+m_pStructDecompressInfo->dwOffsetInsideResolveImp,&m_pStructDecompressInfo->dwRVADecompressRes))))
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}
		if(dwDestSize<m_objTempFile.m_stSectionHeader[wRVASec].Misc.VirtualSize)
		{
			if(!(byDestbuff=(BYTE*)realloc(byDestbuff,m_objTempFile.m_stSectionHeader[wRVASec].Misc.VirtualSize)))
			{
				free(byDestbuff);
				byDestbuff=NULL;
				free(byFullFilebuff);
				byFullFilebuff=NULL;
				return false;
			}
			dwDestSize=m_pStructDecompressInfo->dwDestResolveImpSize;

		}
		memset(byDestbuff,0,dwDestSize);

		if(m_pStructDecompressInfo->dwRVADecompressRes+m_pStructDecompressInfo->dwDestResolveImpSize>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(!(~(dwDestSize=APLIBDecompress(m_pStructDecompressInfo->dwDestResolveImpSize+0x10,m_objTempFile.m_stSectionHeader[wRVASec].Misc.VirtualSize,0,0,byDestbuff,iDecompressionType,&byFullFilebuff[m_pStructDecompressInfo->dwRVADecompressRes]))))
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		if(m_pStructDecompressInfo->dwRVADecompressRes+dwDestSize>m_objTempFile.m_dwFileSize)
		{
			free(byDestbuff);
			byDestbuff=NULL;
			free(byFullFilebuff);
			byFullFilebuff=NULL;
			return false;
		}

		for(DWORD i=0;i<dwDestSize;i++)
		{
			byFullFilebuff[m_pStructDecompressInfo->dwRVADecompressRes+i]=byDestbuff[i];
		}



	}

	if(byDestbuff)
	{
		free(byDestbuff);
		byDestbuff=NULL;
	}

	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.NoOfDataDirs+0x0C]=m_pStructDecompressInfo->dwResolveImports;
	*(DWORD*)&byFullFilebuff[m_objTempFile.m_stPEOffsets.AddressOfEntryPoint]=~(m_pStructDecompressInfo->dwAEP);
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

bool CTelockDecryptor::BuildJunkCodeandDecrypt(BYTE *bybuff,DWORD dwDecryptOffsetKey,DWORD dwDecryptOffset,BYTE *bykey2,DWORD dwKeySize)
{
	BYTE *bytempbuff=NULL;
	if(!(bytempbuff=(BYTE*)MaxMalloc(0x200)))
	{
		return false;
	}
	memset(bytempbuff,0,0x200);

	for(DWORD i=0;i<0x100;i++)
	{
		bytempbuff[i]=BYTE(i);
	}

	if(dwKeySize!=0x00)
	{
		for(DWORD i=0;i<0x100;i+=dwKeySize)
		{
			memcpy(&bytempbuff[0x100+i],&bybuff[dwDecryptOffsetKey],dwKeySize);
		}
	}

	for(DWORD i=0;i<0x100;i++)
	{
		bykey2[1]+=bytempbuff[i];
		bykey2[1]+=bytempbuff[0x100+i];
		if(bykey2[1]>0x200)
		{
			free(bytempbuff);
			bytempbuff=NULL;
			return false;
		}
		bykey2[3]=bytempbuff[bykey2[1]];
		bytempbuff[bykey2[1]]=bytempbuff[i];
		bytempbuff[i]=bykey2[3];
	}

	bykey2[0]=0;
	bykey2[1]=0;
	bykey2[2]=0;
	bykey2[3]=0;

	if(dwDecryptOffset+0xBC > m_objTempFile.m_dwFileSize)
	{
		free(bytempbuff);
		bytempbuff=NULL;
		return false;
	}

	for(DWORD i=1;i<=0xBC;i++)
	{
		bykey2[1]+=bytempbuff[i];
		if(bykey2[1]>0x200)
		{
			free(bytempbuff);
			bytempbuff=NULL;
			return false;
		}
		bykey2[3]=bytempbuff[bykey2[1]];
		bytempbuff[bykey2[1]]=bytempbuff[i];
		bytempbuff[i]=bykey2[3];
		bykey2[2]=bytempbuff[i]+bytempbuff[bykey2[1]];
		if(bykey2[2]>0x200)
		{
			free(bytempbuff);
			bytempbuff=NULL;
			return false;
		}
		bykey2[1]=bytempbuff[bykey2[2]];
		bybuff[dwDecryptOffset+i-1]^=bykey2[2];
	}

	free(bytempbuff);
	bytempbuff=NULL;
	return true;
}

DWORD CTelockDecryptor::ImplementCRCFunction(BYTE *byFileBuff, DWORD dwLoopSize)
{
	DWORD dwCRCValue=0xFFFFFFFF;
	DWORD dwEAX=0,dwECX=0;
	for(DWORD i=0;i<dwLoopSize;i++)
	{
		if(i==0x10)
		{
			dwEAX=dwEAX;
		}
		dwEAX=byFileBuff[i];
		dwEAX=(dwEAX&0xFFFFFF00)|BYTE(BYTE(dwEAX)^(BYTE)dwCRCValue);

		for(DWORD j=0;j<8;j++)
		{
			if((dwEAX&0x01)==0x01)
			{
				dwEAX>>=1;
				dwEAX^=0xCDC795E1;
			}
			else
			{
				dwEAX>>=1;
			}
		}
		dwCRCValue>>=8;
		dwCRCValue^=dwEAX;
	}

	return dwCRCValue;
}

DWORD CTelockDecryptor::CallEmulatorDissambler(DWORD dwOffset,BYTE *byFullFilebuff,CEmulate objEmulate,DWORD *dwKey,DWORD *dwDecryptOffset,DWORD *dwRegIndex,BYTE *byKey2,int itype,bool *bContinue)
{
	DWORD dwLength = 0, dwInstructionCountFound = 0;
	DWORD dwTotalInstructionCount=0;
	char	szInstruction[1024] = {0x00};
	*bContinue=false;
	while(dwOffset<m_objTempFile.m_dwFileSize && dwTotalInstructionCount<0x100)
	{
		dwLength = objEmulate.DissassemBuffer((char*)&byFullFilebuff[dwOffset],szInstruction);
		dwTotalInstructionCount++;

		if(itype!=0x02 && itype!=0x04 && itype!=0x06 && itype!=0x12 && strstr(szInstruction,"JMP") && dwLength==0x02 && byFullFilebuff[dwOffset]==0xEB)
		{
			if(byFullFilebuff[dwOffset+1]>0x80)
			{
				dwOffset-=(0x100-byFullFilebuff[dwOffset+1]);
			}
			else
			{
				dwOffset+=byFullFilebuff[dwOffset+0x01];
			}
		}
		else if(itype!=0x04 && itype!=0x12 && strstr(szInstruction,"CALL") && dwLength==0x05 && byFullFilebuff[dwOffset]==0xE8)
		{
			if(dwInstructionCountFound==0x00)
			{
				if(itype!=0x00 || (itype==0x00 && *(DWORD*)&byFullFilebuff[dwOffset+0x01]>0x10))
				{
					*dwDecryptOffset=dwOffset+0x05;
					dwInstructionCountFound=1;
				}				
			}
			dwOffset+=*(DWORD*)&byFullFilebuff[dwOffset+0x01];
			if(itype==0x06)
			{
				return dwOffset+0x05;
			}

		}
		else if(strstr(szInstruction,"STC") && dwLength==0x1 && byFullFilebuff[dwOffset+0x1]==0x72)
		{
			dwOffset+=byFullFilebuff[dwOffset+0x02]+0x02;
		}
		else if(strstr(szInstruction,"CLC") && dwLength==0x1 && byFullFilebuff[dwOffset+0x1]==0x73)
		{
			dwOffset+=byFullFilebuff[dwOffset+0x02]+0x02;
		}
		else if(strstr(szInstruction,"PUSHAD") && dwLength==0x01)
		{
			if(byFullFilebuff[dwOffset+0x01]==0xE8 && *(DWORD*)&byFullFilebuff[dwOffset+0x06]==0x0824648B)
			{
				dwOffset+=0x06;
				dwOffset-=dwLength;
			}
		}
		else if(strstr(szInstruction,"OR ESP") && dwLength==0x2 && byFullFilebuff[dwOffset+0x2]==0x75)
		{
			dwOffset+=byFullFilebuff[dwOffset+0x03]+0x02;
		}
		else if(strstr(szInstruction,"TEST ESP") && dwLength==0x2 && byFullFilebuff[dwOffset+0x2]==0x79)
		{
			dwOffset+=byFullFilebuff[dwOffset+0x03]+0x02;
		}
		else if(itype==0 && dwInstructionCountFound==0x01 && ((strstr(szInstruction,"XOR") && dwLength==0x6 && *(WORD*)&byFullFilebuff[dwOffset]>=0xF081)||(strstr(szInstruction,"PUSH") && dwLength==0x5 && (*(WORD*)&byFullFilebuff[dwOffset+0x05]&0x0F8)==WORD(0x58))))
		{
			if(!objEmulate.IntializeProcess(true))
			{
				return false;
			}
			DWORD dwFileSize = objEmulate.GetEmulatorFileSize() > m_objTempFile.m_dwFileSize ? m_objTempFile.m_dwFileSize : objEmulate.GetEmulatorFileSize();
			if(0==objEmulate.WriteBuffer(byFullFilebuff, dwFileSize, m_objTempFile.m_stPEHeader.ImageBase))
			{
				return false;
			}

			objEmulate.SetEip(dwOffset+m_dwImageBase);
			objEmulate.SetNoOfIteration(0x30);
			objEmulate.SetBreakPoint("__isinstruction('imul')");
			if(7 == objEmulate.EmulateFile())
			{
				*dwKey=objEmulate.GetSpecifyRegValue(objEmulate.GetDestRegNo());
				byKey2[0]=byFullFilebuff[objEmulate.GetEip()-m_dwImageBase+0x02];

				dwOffset=(objEmulate.GetEip()-m_dwImageBase);
				objEmulate.UpdateSpecifyReg((byFullFilebuff[dwOffset+0x04]%0x08),*dwDecryptOffset+m_dwImageBase);
				CHAR RegisterBuffNames[8][4]={"EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"};
				CHAR TEMPSTRINGADD[0x20]={0};
				sprintf_s(TEMPSTRINGADD,0x20,"__isinstruction('ROL %s')",RegisterBuffNames[objEmulate.GetDestRegNo()]);
				objEmulate.ModifiedBreakPoint(TEMPSTRINGADD,0);
				if(7 == objEmulate.EmulateFile())
				{
					byKey2[1]=BYTE(objEmulate.GetImmidiateConstant());
				}
				else
				{
					return -1;
				}
				sprintf_s(TEMPSTRINGADD,0x20,"__isinstruction('ADC %s')",RegisterBuffNames[objEmulate.GetDestRegNo()]);
				objEmulate.ModifiedBreakPoint(TEMPSTRINGADD,0);
				if(7 == objEmulate.EmulateFile())
				{
					byKey2[2]=BYTE(objEmulate.GetImmidiateConstant());
					if(byFullFilebuff[objEmulate.GetEip()-m_dwImageBase-0x01]==0xF9)
					{
						byKey2[3]=0x1;	
					}
				}
				else
				{
					return -1;
				}
				objEmulate.SetEip(objEmulate.GetEip()+objEmulate.GetInstructionLength());
				sprintf_s(TEMPSTRINGADD,0x20,"__isinstruction('ADD %s')",RegisterBuffNames[objEmulate.GetDestRegNo()]);
				CHAR TEMPSTRINGXCHG[0x30]={0};
				sprintf_s(TEMPSTRINGXCHG,0x20,"__isinstruction('%s')",RegisterBuffNames[objEmulate.GetDestRegNo()]);
				objEmulate.SetBreakPoint(TEMPSTRINGXCHG);
				objEmulate.ModifiedBreakPoint(TEMPSTRINGADD,0);
				while(1)
				{
					if(7 == objEmulate.EmulateFile())
					{
						memset(TEMPSTRINGXCHG,0,0x30);
						objEmulate.GetInstruction(TEMPSTRINGXCHG);

						*dwRegIndex=objEmulate.GetImmidiateConstant();						
						if(strstr(TEMPSTRINGXCHG,"mov"))// || strstr(TEMPSTRINGXCHG,"XCHG") )
						{
							sprintf_s(TEMPSTRINGADD,0x20,"__isinstruction('ADD %s')",RegisterBuffNames[objEmulate.GetDestRegNo()]);
							objEmulate.PauseBreakPoint(1);
							objEmulate.ModifiedBreakPoint(TEMPSTRINGADD,0);
							if(7 == objEmulate.EmulateFile())
							{
								*dwRegIndex=objEmulate.GetImmidiateConstant();
								return dwOffset;
							}
							else
							{
								return -1;
							}

						}
						else if(strstr(TEMPSTRINGXCHG,"add"))
						{
							return dwOffset;
						}
					}
					else
					{
						return -1;
					}
					objEmulate.SetEip(objEmulate.GetEip()+objEmulate.GetInstructionLength());
				}
			}
			else
			{
				return -1;
			}
		}
		else if(itype==1 && strstr(szInstruction,"LEA ESI") && dwLength==0x03)
		{
			*dwDecryptOffset=dwOffset+byFullFilebuff[dwOffset+0x02];
		}
		else if(itype==3 && strstr(szInstruction,"LEA ESI") && dwLength==0x04)
		{
			*dwDecryptOffset=*dwRegIndex;
		}
		else if(itype==3 && strstr(szInstruction,"ADD EDX") && dwLength==0x03)
		{
			*dwRegIndex+=byFullFilebuff[dwOffset+0x02];
			*bContinue=true;
		}
		else if((itype%2)==0x1 && strstr(szInstruction,"MOV ECX") && dwLength==0x05)
		{
			*dwKey=*(DWORD*)&byFullFilebuff[dwOffset+0x01];
			if(itype==0x05)
			{
				return dwOffset;
			}
		}
		else if((itype%2)==0x1 && strstr(szInstruction,"ADD AL") && dwLength==0x02 && byKey2[1]!=0x00)
		{
			byKey2[0]=byFullFilebuff[dwOffset+1];
			return dwOffset;
		}
		else if(itype==0x03 && strstr(szInstruction,"ROL AL") && dwLength==0x03)
		{
			byKey2[0]=byFullFilebuff[dwOffset+2];
			byKey2[2]=1;
			return dwOffset;
		}
		else if((itype==0x03||itype==0x11) && strstr(szInstruction,"XOR AL") && dwLength==0x02 && byFullFilebuff[dwOffset]==0x34)
		{
			byKey2[1]=byFullFilebuff[dwOffset+1];
		}
		else if((itype==3||itype==0x10) &&  strstr(szInstruction,"MOV EDX") && dwLength==0x05)
		{
			*dwRegIndex=*(DWORD*)&byFullFilebuff[dwOffset+1];
		}
		else if(itype==2 && strstr(szInstruction,"JNZ") && dwLength==0x02 && *(WORD*)&byFullFilebuff[dwOffset+0x02]==0x840F)
		{
			return dwOffset+0x02+0x06+*(DWORD*)&byFullFilebuff[dwOffset+0x04];
		}
		else if(itype==4 && strstr(szInstruction,"SUB EDI ,8H") && dwLength==0x03 && *(WORD*)&byFullFilebuff[dwOffset+0x03]==0xF9E2)
		{
			return dwOffset+0x05;
		}
		else if(itype==5 && strstr(szInstruction,"LEA EDI") && dwLength==0x06)
		{
			*dwDecryptOffset=*(DWORD*)&byFullFilebuff[dwOffset+0x02];
		}
		else if(itype==5 && strstr(szInstruction,"MOV EDX") && dwLength==0x06)
		{
			*dwRegIndex=*(DWORD*)&byFullFilebuff[dwOffset+2];
		}
		else if(itype==7 && strstr(szInstruction,"LEA ESI") && dwLength==0x06)
		{
			*dwDecryptOffset=*(DWORD*)&byFullFilebuff[dwOffset+0x02];
		}
		else if(itype==7 && strstr(szInstruction,"MOV BL") && dwLength==0x02)
		{
			byKey2[1]=byFullFilebuff[dwOffset+1];
		}
		else if((itype==7||itype==0x11) && strstr(szInstruction,"SUB AL") && dwLength==0x02)
		{
			byKey2[2]=byFullFilebuff[dwOffset+1];
			return dwOffset;
		}
		else if(strstr(szInstruction,"JNZ") && dwLength==0x06 && byFullFilebuff[dwOffset+0x06]==0x74)
		{
			dwOffset+=byFullFilebuff[dwOffset+0x07]+0x08;
		}
		else if(itype==0x10 && byKey2[1]!=0x00 && strstr(szInstruction,"IMUL EBX") && dwLength==0x06)
		{
			*dwKey=*(DWORD*)&byFullFilebuff[dwOffset+0x02];
			byKey2[1]=0x0;
		}
		else if(itype==0x10 && strstr(szInstruction,"LODSB") && dwLength==0x01)
		{
			*dwDecryptOffset=(dwOffset+1);
		}
		else if(itype==0x10 && strstr(szInstruction,"DEC ECX") && dwLength==0x01)
		{
			return dwOffset;
		}
		else if(itype==0x12 && strstr(szInstruction,"MOV DL ,80H") && dwLength==0x02)
		{
			if(*(WORD*)&byFullFilebuff[dwOffset+0x02]==0xDB33)
			{
				*dwKey=0;
			}
			return dwOffset;
		}
		dwOffset+=dwLength;
	}
	return 0xFFFFFFFF;
}

bool CTelockDecryptor::UnPackTelockCryporPolyEmulator(BYTE* byDecryptor_offset, BYTE* byCode_offset, DWORD dwDecryptionSize,DWORD dwDecryptorSize,DWORD *dwRegKeys)
{
	for(DWORD i=0;i<dwDecryptionSize;i++) /* Byte looper - Decrypts every byte and write it back */
	{
		for(DWORD j=0;j<dwDecryptorSize;j++)   /* Poly Decryptor "Emulator" */
		{
			switch(byDecryptor_offset[j])
			{

			case 0x72:	/* JMP short */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				j = j + byDecryptor_offset[j];
				break;
			case 0x0B:	/* OR REG,REG */
				j+=1;
				break;
			case 0x8B:	/* OR REG,REG */
				j+=1;
				break;
			case 0x85:	/* OR REG,REG */
				j+=1;
				break;
			case 0x0A:	/* OR REG,REG */
				j+=1;
				break;
			case 0x8A:	/* MOV WORD REG,WORD REG */
				j+=1;
				break;
			case 0x8D:	/* LEA DWORD,[DWORD] */
				j+=1;
				break;
			case 0x03:
				dwRegKeys[2]+=dwRegKeys[1];
				j+=1;
				break;
			case 0xD1:
				j++;
				if(j+1 > dwDecryptorSize)
				{
					return false;					
				}
				MAX_ROL(dwRegKeys[((byDecryptor_offset[j])%0x08)-1],1);

				break;
			case 0x69:
				if(j+6 > dwDecryptorSize)
				{
					return false;
				}
				dwRegKeys[((byDecryptor_offset[j+1])%0x08)-1]*=*(DWORD*)&byDecryptor_offset[j+2];
				j+=0x05;
				break;
			case 0xF6:	/* NEG AL & NOT */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]=~byCode_offset[i];
				if(byDecryptor_offset[j]>=0xD8)
				{
					byCode_offset[i]+=1;
				}

				break;

			case 0xFE:	/* DEC  AL */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				if(byDecryptor_offset[j]>=0xC8)
					byCode_offset[i]--;
				else
					byCode_offset[i]++;

				break;

			case 0x2A:	/* SUB AL,CL */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]-= BYTE(dwRegKeys[((byDecryptor_offset[j])%0x08)-1]);

				break;

			case 0x02:	/* ADD AL,CL */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]+=BYTE(dwRegKeys[((byDecryptor_offset[j])%0x08)-1]);

				break
					;
			case 0x32:	/* XOR AL,CL */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]^=BYTE(dwRegKeys[((byDecryptor_offset[j])%0x08)-1]);

				break;
				;
			case 0x04:	/* ADD AL,num */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]+= byDecryptor_offset[j];
				break;
				;
			case 0x34:	/* XOR AL,num */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]^= byDecryptor_offset[j];
				break;

			case 0x2C:	/* SUB AL,num */
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				byCode_offset[i]-= byDecryptor_offset[j];
				break;


			case 0xC0:
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				if(byDecryptor_offset[j]==0xC0) /* ROL AL,num */
				{
					j++;
					if(j+1>dwDecryptorSize)
					{
						return false;
					}
					MAX_ROL(byCode_offset[i],byDecryptor_offset[j]);
				}
				else			/* ROR AL,num */
				{
					j++;
					if(j+1>dwDecryptorSize)
					{
						return false;
					}
					MAX_ROR(byCode_offset[i],byDecryptor_offset[j]);
				}
				break;

			case 0xD2:
				j++;
				if(j+1>dwDecryptorSize)
				{
					return false;
				}
				if(byDecryptor_offset[j]>=0xC8) /* ROR AL,CL */
				{
					MAX_ROR(byCode_offset[i],BYTE(dwRegKeys[((byDecryptor_offset[j])%0x08)]));
				}
				else			/* ROL AL,CL */
				{
					MAX_ROL(byCode_offset[i],BYTE(dwRegKeys[((byDecryptor_offset[j])%0x08)]));
				}
				break;

			case 0x90:
			case 0xF8:
			case 0xF9:
			case 0xE9:
			case 0xE8:
			case 0xAA:
			case 0xFC:
				break;

			default:
				//DBGMessage("yC: Unhandled opcode %x\n", (unsigned char)byDecryptor_offset[j]);
				return false;
			}
		}
		dwRegKeys[0]--;
	}
	return true;

}

