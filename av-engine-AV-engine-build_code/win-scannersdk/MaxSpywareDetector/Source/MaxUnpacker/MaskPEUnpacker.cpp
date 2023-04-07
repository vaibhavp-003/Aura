#pragma once
#include "MaskPEUnpacker.h"
#include "MaxExceptionFilter.h"
#include "Packers.h"

CMaskPEUnpacker::CMaskPEUnpacker(CMaxPEFile *pMaxPEFile):
CUnpackBase(pMaxPEFile)
{
}

CMaskPEUnpacker::~CMaskPEUnpacker(void)
{
	if(m_pbyBuff)
	{
		delete []m_pbyBuff;
		m_pbyBuff = NULL;
	}
	m_objTempFile.CloseFile();
}

bool CMaskPEUnpacker::IsPacked() 
{
	if(m_pMaxPEFile->m_stPEHeader.NumberOfSections > 1 && 
		((m_pMaxPEFile->m_wAEPSec == 0x00 && m_iCurrentLevel > 0) || _memicmp(m_pMaxPEFile->m_stSectionHeader[m_pMaxPEFile->m_wAEPSec].Name,".MaskPE",0x07)==0))
	{
		m_pbyBuff = new BYTE[255];
		if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped,0x10,0x10))
		{
			return false;
		}

		BYTE byOpcodeCompare[]={0x03,0x11,0x3B,0x33,0x85,0x8B,0x2B,0x1B,0x09,0x21,0x58,0x50,0x61};

		//Begins with one PUSHAD
		//if(m_pbyBuff[0]==0x60 && (m_pbyBuff[1]&0x50)==0x50)
		if(m_pbyBuff[0]==0x60)
		{
			for(m_dwOffset=0x1;m_dwOffset<0x10-0x01;m_dwOffset++)
			{
				if(m_dwOffset>0x07)
				{
					return true;				
				}
				for(DWORD i=0;i<sizeof(byOpcodeCompare);i++)
				{
					if(i<0x0A && m_pbyBuff[m_dwOffset]==byOpcodeCompare[i])
					{
						if((m_pbyBuff[m_dwOffset+1]&0xC0)==0xC0)
						{
							m_dwOffset+=0x01;
						}
						else
						{
							return false;
						}
						break;
					}
					else if(i>=0x0A && (m_pbyBuff[m_dwOffset]&byOpcodeCompare[i])==byOpcodeCompare[i])
					{
						break;
					}
					else if(i==sizeof(byOpcodeCompare)-1)
					{
						return false;
					}
				}
			}
		}
	}
	return false;
}




bool CMaskPEUnpacker::Unpack(LPCTSTR szTempFileName)
{
	//Just Follows a sequential series of Junk Code consisiting of Opcodes
	//ADD,ADC,PUSH,CMP,TEST,XOR,SUB,SBB,OR,AND,POP
	if(!ReOrganizeFile(szTempFileName))
	{
		return false;
	}

	if(!m_pMaxPEFile->ReadBuffer(m_pbyBuff,m_pMaxPEFile->m_dwAEPMapped+m_dwOffset,0xF0,0xF0))
	{
		return false;
	}

	BYTE byOpcodeCompare[]={0x03,0x11,0x3B,0x33,0x85,0x8B,0x2B,0x1B,0x09,0x21,0x58,0x50,0x61,0x60};
	bool bterminateFlag=false;
	DWORD dwOffset=0x00;

	for(;dwOffset<(0xF0-0x01) && !bterminateFlag;dwOffset++)
	{
		for(DWORD i=0;i<sizeof(byOpcodeCompare);i++)
		{
			if(i<0x0A && m_pbyBuff[dwOffset]==byOpcodeCompare[i])
			{
				if((m_pbyBuff[dwOffset+1]&0xC0)==0xC0)
				{
					dwOffset+=0x01;
				}
				else
				{
					return false;
				}
				break;
			}
			else if(i>=0x0A && (m_pbyBuff[dwOffset]&byOpcodeCompare[i])==byOpcodeCompare[i])
			{
				if(i==sizeof(byOpcodeCompare)-0x01)
				{
					bterminateFlag=true;
				}
				break;
			}
			else if(i==sizeof(byOpcodeCompare)-1)
			{
				return false;
			}
		}
	}

	if(bterminateFlag==false)
	{
		return false;
	}


	if(dwOffset+0x0C+0x04>0xF0)
	{
		if(!m_pMaxPEFile->ReadBuffer(&m_pbyBuff[dwOffset],dwOffset+m_dwOffset+m_pMaxPEFile->m_dwAEPMapped,0x10,0x10))
		{
			return false;
		}
	}

	bool bSimpletype=true;
	DWORD dwAEP=dwOffset;
	if(m_pbyBuff[dwOffset+0xB]==0xE8)
	{
		bSimpletype=false;
	}

	if(bSimpletype==false)
	{
		dwOffset+=0x0C;
		dwOffset+=*(DWORD*)&m_pbyBuff[dwOffset]+0x04;
		dwOffset+=m_dwOffset;
		dwOffset+=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;
		dwAEP+=0x10;
		dwAEP+=m_dwOffset;
		dwAEP+=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;;

		if(!m_objTempFile.ReadBuffer(m_pbyBuff,dwOffset,0xB,0xB))
		{
			return false;
		}

		dwAEP+=m_pbyBuff[0xA];
		dwAEP+=0x02;
		if(!m_objTempFile.ReadBuffer(m_pbyBuff,dwAEP,0x04,0x04))
		{
			return false;
		}

		if(!m_objTempFile.WriteAEP(dwAEP+*(DWORD*)&m_pbyBuff[0]+0x04))
		{
			return false;
		}
	}
	else
	{
		dwOffset+=*(DWORD*)&m_pbyBuff[dwOffset]+0x04;
		dwOffset+=m_dwOffset;
		dwOffset+=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;
		dwAEP+=m_objTempFile.m_stPEHeader.AddressOfEntryPoint;
		dwAEP+=m_dwOffset;
		dwAEP+=0x04;
		if(dwOffset+0x04+0x04>m_objTempFile.m_dwFileSize)
		{
			return false;
		}
		if(!m_objTempFile.ReadBuffer(m_pbyBuff,dwOffset+0x04,0x04,0x04))
		{
			return false;
		}
		dwAEP-=*(DWORD*)&m_pbyBuff[0];
		if(!m_objTempFile.WriteAEP(dwAEP))
		{
			return false;
		}

	}

	return true;
}