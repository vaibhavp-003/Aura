/*======================================================================================
   FILE				: StringFunctions.h
   ABSTRACT			: This file contains declarations for string related functions
   DOCUMENTS		: SpecialSpyHandler_DesignDoc.doc
   AUTHOR			: Anand Srivastava
   COMPANY			: Aura 
   COPYRIGHT NOTICE : (C) Aura
      				  Created as an unpublished copyright work.  All rights reserved.
     				  This document and the information it contains is confidential and
      				  proprietary to Aura.  Hence, it may not be 
      				  used, copied, reproduced, transmitted, or stored in any form or by any 
      				  means, electronic, recording, photocopying, mechanical or otherwise, 
      				  without the prior written permission of Aura
   CREATION DATE	: 25/12/2003
   NOTE				:
   VERSION HISTORY	:
					version: 2.5.0.23
					Resource : Anand
					Description: Ported to VS2005 with Unicode and X64 bit Compatability
========================================================================================*/
#include <io.h>
#include <stdio.h>
#include <shlwapi.h>

//Remove Spyware
#define MAX_BUF			0x100
#define ONE_KB			0x400
#define LARGE_ARRAY		0x400

//version: 15.5
//resource: anand
#define IO_BUF_SIZE		ONE_KB * 200

//version: 19.0.0.032
//resource: Avinash

bool SearchString(int hFile, unsigned char * string, DWORD length, bool * found);
bool SearchString(int hFile, const char * string, bool * found=false);

void* MemIChr(void * Buffer, int Char, unsigned long cbBuffer);

//version: 15.5
//resource: anand
//Version:19.0.0.040
//Description: Changed the return type
UCHAR* StrNIStr(UCHAR * HayStack, size_t cbHayStack, UCHAR * Needle, size_t cbNeedle);

//bool StrcpyW(WCHAR * Dst, DWORD cbDst, CHAR * Src);
bool StrcatW(WCHAR * Dst, DWORD cbDst, CHAR * Src);

