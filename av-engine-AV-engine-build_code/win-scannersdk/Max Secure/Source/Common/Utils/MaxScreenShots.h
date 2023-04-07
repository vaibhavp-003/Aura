/*======================================================================================
FILE             : MaxScreenShots.h
ABSTRACT         : Contains the implementation of Saving Images in Jpeg Format
DOCUMENTS	     : Refer VSS Documents folder for details
AUTHOR		     : vyankatesh
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created in 2009 as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : 11/17/2009 10:30 AM
NOTES		     : 
VERSION HISTORY  : 
======================================================================================*/

#pragma once
extern "C"
{
	#include "jpeglib.h"
}
class CMaxScreenShots
{
public:
	CMaxScreenShots(void);
	~CMaxScreenShots(void);

	RGBQUAD QuadFromWord(WORD b16);
	HANDLE DDBToDIB( CBitmap& bitmap, DWORD dwCompression, CPalette* pPal );
	BOOL JpegFromDib(HANDLE hDib,int nQuality,TCHAR* csJpeg,TCHAR* pcsMsg);
	BOOL JpegFromDibWrapper(HANDLE hDib,int nQuality,CString szFile,TCHAR *csMsg);
	BOOL SaveCBitmapToJpeg(CWindowDC &dc,CBitmap &ObjBitMap, TCHAR* szFile, CWnd *pWnd);
	BOOL DibToSamps(HANDLE hDib, int nSampsPerRow,jpeg_compress_struct cinfo,JSAMPARRAY jsmpPixels,TCHAR* pcsMsg);	

};
