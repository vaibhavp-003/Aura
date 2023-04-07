/*=============================================================================
   FILE			: Crypto.h
   ABSTRACT		: 
   DOCUMENTS	: 
   AUTHOR		: 
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 
   NOTES		:
VERSION HISTORY	: 13 Feb 2008, Nupur : Unicode & Multi Language Support
									   Coding Standards and Code Cleanup
============================================================================*/
#pragma once

//#include "resource.h"      
#include "globals.h"

#define CR 13
#define LF 10

class  CCrypt 
{
public:
	CCrypt();

	CStringA prtB64code;

	char* base64enc(char *strIn, int len1);
	char* base64dec(char *strIn, int *len);

	CStringA* base64enc(CStringA *strIn);
	CStringA* base64dec(CStringA *strIn);
	CStringA get_StrEncode(CStringA);
	CStringA get_StrDecode(CStringA);
	bool Encrypt(LPSTR szText);
	bool Decrypt(LPSTR szText);

};
