/*======================================================================================
FILE				: MacFileScanner.h
ABSTRACT			: Virus Name list.
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: This class module keeps the information of virus names identifiers of signature loaded in memory.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:23-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "MaxPEFile.h"
#include "MacStruct.h"

const int  MAC_FILE_METADATA	= 0x01;
const int  MAC_FILE_OBJ_32		= 0x02;
const int  MAC_FILE_OBJ_64		= 0x03;
const int  MAC_BUFF_SIZE		= 0x8C00;	

class CMACFileScanner
{
	bool				m_bIsBigEndian;
	int					m_iFileType;
	DWORD				m_ulTextSecOffSet;
	DWORD				m_ulTextSecSize;
	DWORD				m_ulStringSecStart;
	DWORD				m_ulStringSecSize;
	LPMAC_LOAD_COMMAND	*m_pobjLoadCmds;
	CMaxPEFile			*m_pMaxPEFile;

	bool	CheckMACMagic();
	bool	GetMACHeaderStruct();
	bool	GetMAC32FileBuffer(unsigned char *byBuffer, DWORD& cbBuffer);
	bool	GetMAC64FileBuffer(unsigned char *byBuffer, DWORD& cbBuffer);
	bool	ConvertBEHeaderToLE();
	bool	ConvertBESegmentToLE(void *pSegCmd);
	//bool	GetMAC64HdrStruct();
    
public:
    CMACFileScanner(CMaxPEFile *pMaxPEFile);
	~CMACFileScanner(void);
    
	MAC_HEADER_32	m_objMACO32;
	MAC_HEADER_64	m_objMACO64;
	
	bool IsValidMACFile();
	bool GetBuffer(LPBYTE byBuffer, DWORD& cbBuffer);
};
