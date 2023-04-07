/*=============================================================================
   FILE			: Crypto.cpp
   ABSTRACT		: 
   DOCUMENTS	: 
   AUTHOR		: Gaurav Waikar 
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
#include "stdafx.h"
#include "Crypto.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
CHAR g_szCharset[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
						'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
						'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
						'Y', 'Z', '$', '0', '1', '2', '3', '4', 
						'5', '6', '7', '8', '9'};

CCrypt::CCrypt()
{
	this->prtB64code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

/*-------------------------------------------------------------------------------------
	Function		: get_StrEncode
	In Parameters	: CStringA : Contains ActivationKeyname to be Encrypted. Ascii input
	Out Parameters	: CStringA : Encrypted key . Ascii output
	Purpose			: To Encode the given Data
	Author			: Gaurav Waikar  
--------------------------------------------------------------------------------------*/
CStringA CCrypt::get_StrEncode(CStringA csActivationKey)
{
	CStringA strInData;
	CStringA base64String = "";
	
	char* tmpstrInData;
	char* tmpCharsArray;
	char* strOutData;
	
	bool noSpareChars = false;
	int i, j, inDataLen, spareCharsLen, cicli, encodedDataLenght;
	
	strInData.Empty();
	strInData = csActivationKey;

	// BASE64 encoding
	inDataLen = strInData.GetLength();
	if ( inDataLen== 0)
	{
		return base64String;
	}

	cicli = int( inDataLen / 3);
	
	if ((inDataLen % 3) == 0) 
	{
		noSpareChars = true; 
	}
	else 
	{
		noSpareChars = false;
	}
	
	spareCharsLen = inDataLen % 3;

	if (cicli == 0) 
	{
		encodedDataLenght = 4;
	}
	else 
	{
		encodedDataLenght = (4 * int(inDataLen / 3)) + ( (spareCharsLen >0) * 4);
	}
	
	strOutData = new char[encodedDataLenght*2];
	for (i = 0; i < encodedDataLenght * 2; i++) 
	{
		strOutData[i] = 0;
	}

	tmpstrInData = (char*)strInData.GetBuffer(inDataLen);
	
	for (i = 0; i < cicli; i++) 
	{
		tmpCharsArray = base64enc( tmpstrInData + (i * 3), 3);
		for (j = 0; j < 4; j++) 
		{
			strOutData[(i*4) +j] = tmpCharsArray[j];
		}
		
		delete tmpCharsArray;
	}
	if (!noSpareChars) 
	{
		tmpCharsArray = base64enc( tmpstrInData +( cicli * 3), spareCharsLen);
		for ( j = 0; j < 4; j++) 
		{
			strOutData[( cicli * 4) + j] = tmpCharsArray[j];
		}
		delete tmpCharsArray;
	}
	strInData.ReleaseBuffer();
	base64String = strOutData;
	return base64String;
}

/*-------------------------------------------------------------------------------------
	Function		: get_StrDecode
	In Parameters	: CStringA : Contains ActivationKeyname to be Decrypted. Ascii input
	Out Parameters	: CStringA : Decrypted key . Ascii output
	Purpose			: To Decode the given Data
	Author			: Gaurav Waikar  
--------------------------------------------------------------------------------------*/
CStringA CCrypt::get_StrDecode(CStringA csActivationKey)
{
	CStringA strInData;
	CStringA *tmpString;
	CStringA unbase64String = "";
	CStringA unbase64String1 = "";
	
	int i, nblocks;
	strInData.Empty();
	strInData = csActivationKey;
	if (strInData.GetLength() < 4)
	{
		strInData = "";
		return strInData;
	}

	// base64 decoding
	unbase64String = csActivationKey;
	int iFind = unbase64String.Find("====");
    if(iFind != -1)
	{
#pragma warning(disable: 4244)
  		i = unbase64String.Replace((unsigned short)"====",(unsigned short)"");
#pragma warning(default: 4244)
	}
	
	unbase64String.Trim();
	unbase64String.TrimLeft();
	unbase64String.TrimRight();
	nblocks = int(unbase64String.GetLength() / 4);
    
	for (i=0; i<nblocks; i++) 
	{
		tmpString = base64dec(&(unbase64String.Mid( i * 4, 4)));
		unbase64String1 += *tmpString;
		delete tmpString;
	}
	return unbase64String1;
}

/*-------------------------------------------------------------------------------------
	Function		: base64dec
	In Parameters	: char * : pointer to char array, int* : pointer to lenght of the char
	Out Parameters	: char*  : pointer to decoded char array
	Purpose			: decode a base64 block from a array to an array	
	Author			: Gaurav Waikar  
--------------------------------------------------------------------------------------*/
char* CCrypt::base64dec(char *strIn, int *len)
{
	u8 *dataOut = new u8[3];
	u8 tstrIn[4];
	bool error = false;
	
	// copy of strIn in a temp var
	tstrIn[0] = strIn[0]; tstrIn[1] = strIn[1];
	tstrIn[2] = strIn[2]; tstrIn[3] = strIn[3];

	dataOut[0] = dataOut[1] = dataOut[2] = 0;
	if ((tstrIn[0] != '=') && (tstrIn[1] != '=') && (tstrIn[2] != '=') && (tstrIn[3] != '='))
	{
		*len = 3;
		tstrIn[0] = prtB64code.Find(tstrIn[0]); if (tstrIn[0] == 255) {error=true; goto handleError1;}
		tstrIn[1] = prtB64code.Find(tstrIn[1]); if (tstrIn[1] == 255) {error=true; goto handleError1;}
		tstrIn[2] = prtB64code.Find(tstrIn[2]); if (tstrIn[2] == 255) {error=true; goto handleError1;}
		tstrIn[3] = prtB64code.Find(tstrIn[3]); if (tstrIn[3] == 255) {error=true; goto handleError1;}
		dataOut[0] = ((tstrIn[0] & 0x3F) << 2) | ((tstrIn[1] & 0x30) >> 4);
		dataOut[1] = ((tstrIn[1] & 0x0F) << 4) | ((tstrIn[2] & 0x3C) >> 2);
		dataOut[2] = ((tstrIn[2] & 0x03) << 6) | (tstrIn[3] & 0x3F);
	} 
	else if ((tstrIn[3] == '=') && (tstrIn[2] != '=') ) 
	{
		*len = 2;
		tstrIn[0] = prtB64code.Find(tstrIn[0]); if (tstrIn[0] == 255) {error=true; goto handleError1;}
		tstrIn[1] = prtB64code.Find(tstrIn[1]); if (tstrIn[1] == 255) {error=true; goto handleError1;}
		tstrIn[2] = prtB64code.Find(tstrIn[2]); if (tstrIn[2] == 255) {error=true; goto handleError1;}
		dataOut[0] = ((tstrIn[0] & 0x3F) << 2) | ((tstrIn[1] & 0x30) >> 4);
		dataOut[1] = ((tstrIn[1] & 0x0F) << 4) | ((tstrIn[2] & 0x3C) >> 2);
	}
	else if ( (tstrIn[2] == '=') && (tstrIn[3] == '=') )
	{
		*len = 1;
		tstrIn[0] = prtB64code.Find(tstrIn[0]); if (tstrIn[0] == 255) {error=true; goto handleError1;}
		tstrIn[1] = prtB64code.Find(tstrIn[1]); if (tstrIn[1] == 255) {error=true; goto handleError1;}
		dataOut[0] = ((tstrIn[0] & 0x3F) << 2) | ((tstrIn[1] & 0x30) >> 4);
	}
handleError1:
	if (error) 
	{
		tstrIn[0] = '='; tstrIn[1] = '=';
		tstrIn[2] = '='; tstrIn[3] = '=';
		*len = 0;
	}
	return (char*)dataOut;
}

/*-------------------------------------------------------------------------------------
	Function		: base64enc
	In Parameters	: char * : pointer to char array, int* : pointer to lenght of the char
	Out Parameters	: char*  : pointer to encoded char array
	Purpose			: encode a base64 block from an array to an array
	Author			: Gaurav Waikar  
--------------------------------------------------------------------------------------*/
char* CCrypt::base64enc(char *strIn, int len1)
{
	int kk;
	char* b64 = new char[4];
	char tstrIn[3];
	
	// copy of strIn in a temp var
	tstrIn[0] = strIn[0]; 
	tstrIn[1] = strIn[1]; 
	tstrIn[2] = strIn[2];
	
	switch (len1)
	{
	case 3:
		{
			kk = ((tstrIn[0] & 0xFC) >> 2);
			b64[0] = prtB64code[kk];
			
			kk =( ((tstrIn[0] & 0x03) << 4) | ( (tstrIn[1] & 0xF0) >> 4)  );
			b64[1] = prtB64code[kk];
			
			kk =( ((tstrIn[1] & 0x0F) << 2) | ( (tstrIn[2] & 0xC0) >> 6)  );
			b64[2] = prtB64code[kk];
			
			kk = (tstrIn[2] & 0x3F);
			b64[3] = prtB64code[kk];
			break;
		}
	case 2:
		{
			kk = ((tstrIn[0] & 0xFC) >> 2);
			b64[0] = prtB64code[kk];
			
			kk =( ((tstrIn[0] & 0x03) << 4) | ( (tstrIn[1] & 0xF0) >> 4)  );
			b64[1] = prtB64code[kk];
			
			kk =( ((tstrIn[1] & 0x0F) << 2) | ( (tstrIn[2] & 0xC0) >> 6)  );
			b64[2] = prtB64code[kk];
			break;
		}
	case 1:
		{
			kk = ((tstrIn[0] & 0xFC) >> 2);
			b64[0] = prtB64code[kk];
			
			kk =( ((tstrIn[0] & 0x03) << 4) | ( (tstrIn[1] & 0xF0) >> 4)  );
			b64[1] = prtB64code[kk];
			break;
		}
	default:
		{
			b64[0] = '='; b64[1] = '='; b64[2] = '='; b64[3] = '=';
			break;
		}
	}
	
	// adding the termination chars '='
	if (len1 == 2) 
	{
		b64[3] = '=';
	}
	else if (len1 == 1) 
	{
		b64[3] = '=';
		b64[2] = '=';
	}
	return b64;
}

/*-------------------------------------------------------------------------------------
	Function		: base64enc
	In Parameters	: CStringA * : pointer to string to be encoded
	Out Parameters	: CStringA * : pointer to encoded string
	Purpose			: encode a base64 block from a string to a string
	Author			: Gaurav Waikar  
--------------------------------------------------------------------------------------*/
CStringA* CCrypt::base64enc(CStringA *strIn)
{
	u32 len1 = 4;
	u8 b64[4];
	u8 tstrIn[3];
	int kk;
	
	// copy of strIn in a temp var
	tstrIn[0] = strIn->GetAt(0); tstrIn[1] = strIn->GetAt(1); tstrIn[2] = strIn->GetAt(2);
	
	// encoding: getting 6 at time, from left to right
	switch (len1)
	{
	case 3:
		{
			kk = ((tstrIn[0] & 0xFC) >> 2);
			b64[0] = prtB64code[kk];
			
			kk =( ((tstrIn[0] & 0x03) << 4) | ( (tstrIn[1] & 0xF0) >> 4)  );
			b64[1] = prtB64code[kk];
			
			kk =( ((tstrIn[1] & 0x0F) << 2) | ( (tstrIn[2] & 0xC0) >> 6)  );
			b64[2] = prtB64code[kk];
			
			kk = (tstrIn[2] & 0x3F);
			b64[3] = prtB64code[kk];
			break;
		}
	case 2:
		{
			kk = ((tstrIn[0] & 0xFC) >> 2);
			b64[0] = prtB64code[kk];
			
			kk =( ((tstrIn[0] & 0x03) << 4) | ( (tstrIn[1] & 0xF0) >> 4)  );
			b64[1] = prtB64code[kk];
			
			kk =( ((tstrIn[1] & 0x0F) << 2) | ( (tstrIn[2] & 0xC0) >> 6)  );
			b64[2] = prtB64code[kk];
			break;
		}
	case 1:
		{
			kk = ((tstrIn[0] & 0xFC) >> 2);
			b64[0] = prtB64code[kk];
			
			kk =( ((tstrIn[0] & 0x03) << 4) | ( (tstrIn[1] & 0xF0) >> 4)  );
			b64[1] = prtB64code[kk];
			break;
		}
	default:
		{
			b64[0] = '='; 
			b64[1] = '='; 
			b64[2] = '='; 
			b64[3] = '=';
			break;
		}
	}
	// adding termination chars '='
	if (len1 == 2) 
	{
		b64[3] = '=';
	}
	else if (len1 == 1) 
	{
		b64[3] = '=';
		b64[2] = '=';
	}
	return new CStringA((LPCSTR)b64, 4);
}

/*-------------------------------------------------------------------------------------
	Function		: base64dec
	In Parameters	: CStringA * : pointer to string to be decoded
	Out Parameters	: CStringA * : pointer to decoded string
	Purpose			: decode a base64 block from a string to a string
	Author			: Gaurav Waikar  
--------------------------------------------------------------------------------------*/
CStringA* CCrypt::base64dec(CStringA *strIn)
{
	u32 len1 = 0;
	char dataOut[3];
	char tstrIn[4];
	bool error = false;
	ZeroMemory(dataOut, 3);

	// copy of strIn in a temp var
	tstrIn[0] = strIn->GetAt(0); tstrIn[1] = strIn->GetAt(1);
	tstrIn[2] = strIn->GetAt(2); tstrIn[3] = strIn->GetAt(3);
	dataOut[0] = dataOut[1] = dataOut[2] = 0;
	if ((tstrIn[0] != '=') && (tstrIn[1] != '=') && (tstrIn[2] != '=') && (tstrIn[3] != '='))
	{
		len1 = 3;
		tstrIn[0] = prtB64code.Find(tstrIn[0]); if (tstrIn[0] == 255) {error=true; goto handleError2;}
		tstrIn[1] = prtB64code.Find(tstrIn[1]); if (tstrIn[1] == 255) {error=true; goto handleError2;}
		tstrIn[2] = prtB64code.Find(tstrIn[2]); if (tstrIn[2] == 255) {error=true; goto handleError2;}
		tstrIn[3] = prtB64code.Find(tstrIn[3]); if (tstrIn[3] == 255) {error=true; goto handleError2;}
		dataOut[0] = ((tstrIn[0] & 0x3F) << 2) | ((tstrIn[1] & 0x30) >> 4);
		dataOut[1] = ((tstrIn[1] & 0x0F) << 4) | ((tstrIn[2] & 0x3C) >> 2);
		dataOut[2] = ((tstrIn[2] & 0x03) << 6) | (tstrIn[3] & 0x3F);
	} 
	else if ((tstrIn[3] == '=') && (tstrIn[2] != '=') ) 
	{
		len1 = 2;
		tstrIn[0] = prtB64code.Find(tstrIn[0]); if (tstrIn[0] == 255) {error=true; goto handleError2;}
		tstrIn[1] = prtB64code.Find(tstrIn[1]); if (tstrIn[1] == 255) {error=true; goto handleError2;}
		tstrIn[2] = prtB64code.Find(tstrIn[2]); if (tstrIn[2] == 255) {error=true; goto handleError2;}
		dataOut[0] = ((tstrIn[0] & 0x3F) << 2) | ((tstrIn[1] & 0x30) >> 4);
		dataOut[1] = ((tstrIn[1] & 0x0F) << 4) | ((tstrIn[2] & 0x3C) >> 2);
	} 
	else if ((tstrIn[2] == '=') && (tstrIn[3] == '=') ) 
	{
		len1 = 1;
		tstrIn[0] = prtB64code.Find(tstrIn[0]); if (tstrIn[0] == 255) {error=true; goto handleError2;}
		tstrIn[1] = prtB64code.Find(tstrIn[1]); if (tstrIn[1] == 255) {error=true; goto handleError2;}
		dataOut[0] = ((tstrIn[0] & 0x3F) << 2) | ((tstrIn[1] & 0x30) >> 4);
	}

handleError2:
	if (error) 
	{
		tstrIn[0] = '='; tstrIn[1] = '=';
		tstrIn[2] = '='; tstrIn[3] = '=';
		len1 = 0;
	}

	CStringA *csBaseCode = new CStringA( dataOut, len1) ;
	return csBaseCode;
}

 

/*--------------------------------------------------------------------------------------
Function       : getnext
In Parameters  : CHAR chCurrenCHAR
Out Parameters : CHAR
Description    : return the next char, when last char, returns first char
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CHAR getnext(CHAR chCurrenCHAR)
{
	int i = 0;
	CHAR chNexCHAR = 0;

	for(i = 0; i < _countof(g_szCharset); i++)
	{
		if(chCurrenCHAR == g_szCharset[i])
		{
			if((i + 1) >= _countof(g_szCharset))
			{
				chNexCHAR = g_szCharset[0];
			}
			else
			{
				chNexCHAR = g_szCharset[i + 1];
			}

			break;
		}
	}

	return chNexCHAR;
}

/*--------------------------------------------------------------------------------------
Function       : getnext
In Parameters  : CHAR chCurrenCHAR
Out Parameters : CHAR
Description    : return the prev char, when first char, returns last char
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
CHAR getprev(CHAR chCurrenCHAR)
{
	int i = 0;
	CHAR chPrevChar = 0;

	for(i = 0; i < _countof(g_szCharset); i++)
	{
		if(chCurrenCHAR == g_szCharset[i])
		{
			if(0 == i)
			{
				chPrevChar = g_szCharset[_countof(g_szCharset)-1];
			}
			else
			{
				chPrevChar = g_szCharset[i - 1];
			}

			break;
		}
	}

	return chPrevChar;
}

/*--------------------------------------------------------------------------------------
Function       : encrypt
In Parameters  : LPTSTR szText
Out Parameters : bool
Description    : return true if all characters are in charset and encrypted successfully
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CCrypt::Encrypt(LPSTR szText)
{
	bool bSuccess = true;
	/*CHAR chNewChar = 0;
	LPSTR nullchar = szText;
	int i = 0, iTextLen = 0;

	if(NULL == szText)
	{
		return false;
	}

	while(*nullchar++);
	iTextLen = nullchar - szText - 1;

	if(0 >= iTextLen)
	{
		return false;
	}

	for(i = 0; i < iTextLen - 1; i += 2)
	{
		chNewChar = szText[i];
		szText[i] = szText[i+1];
		szText[i+1] = chNewChar;
	}

	for(i = 1; i < iTextLen - 1; i += 2)
	{
		chNewChar = szText[i];
		szText[i] = szText[i+1];
		szText[i+1] = chNewChar;
	}

	for(i = 0; i < iTextLen; i++)
	{
		chNewChar = getnext(szText[i]);
		if(0 == chNewChar)
		{
			bSuccess = false;
			break;
		}

		szText[i] = chNewChar;
	}*/

	return bSuccess;
}

/*--------------------------------------------------------------------------------------
Function       : Decrypt
In Parameters  : LPTSTR szText
Out Parameters : bool
Description    : return true if all characters are in charset and decrypted successfully
Author         : Anand Srivastava
--------------------------------------------------------------------------------------*/
bool CCrypt::Decrypt(LPSTR szText)
{
	bool bSuccess = true;
	CHAR chNewChar = 0;
	LPCSTR nullchar = szText;
	int i = 0, iTextLen = 0;

	if(NULL == szText)
	{
		return false;
	}

	while(*nullchar++);
	iTextLen = int(nullchar - szText - 1);

	if(0 >= iTextLen)
	{
		return false;
	}

	for(i = 0; i < iTextLen; i++)
	{
		chNewChar = getprev(szText[i]);
		if(0 == chNewChar)
		{
			bSuccess = false;
			break;
		}

		szText[i] = chNewChar;
	}

	for(i = 1; i < iTextLen - 1; i += 2)
	{
		chNewChar = szText[i];
		szText[i] = szText[i + 1];
		szText[i + 1] = chNewChar;
	}

	for(i = 0; i < iTextLen - 1; i += 2)
	{
		chNewChar = szText[i];
		szText[i] = szText[i + 1];
		szText[i + 1] = chNewChar;
	}

	return bSuccess;
}
