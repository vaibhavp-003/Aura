/*======================================================================================
FILE				: MaxTTF.h
ABSTRACT			: Scanner for File Type : TTF Files
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
NOTES				: This class module identifies and scan file types : TTF.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#include "MaxPEFile.h"

typedef struct TTF_OFFSET_SUBTABLE
{
  DWORD Version;		// 0x00010000 for version 1.0. 
  WORD Num_Tables;		//Number of tables. 
  WORD Search_Range;	//(Maximum power of 2 <= numTables) x 16. 
  WORD Entry_Selector;	//Log2(maximum power of 2 <= numTables). 
  WORD Range_Shift;		//NumTables x 16 - searchRange.
}OFFSET_SUBTABLE;

typedef struct TTF_TABLE_DIRECTORY
{
	DWORD Tag;		//4 bytes and placed in alphabetical order
	DWORD Checksum; //Checksum of each table
	DWORD Offset_Beginning_Of_sfnt; 
	DWORD Length;	//Length of Table
}TABLE_DIRECTORY;

typedef struct _TTF_FONT_DIRECTORY
{
  OFFSET_SUBTABLE stOffset_Table;
  TABLE_DIRECTORY *pTable_Directory;	
}TTF_HEADER;

class CMaxTTF
{
	TTF_HEADER m_stTTFHeader;

	bool	SortValues();
	
public:
	CMaxTTF();
	~CMaxTTF();

	DWORD 	m_dwStartOffset;
	DWORD 	m_dwBufferSize;

	int		Check4TTFDelOrRepair(CMaxPEFile *pMaxPEFile);
	bool	IsValidTTFFile(CMaxPEFile *pMaxPEFile);
};