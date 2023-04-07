/*======================================================================================
FILE             : MaxScreenShots.cpp
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
#include "StdAfx.h"
#include "MaxScreenShots.h"
#pragma warning(disable: 4996)
/*--------------------------------------------------------------------------------------
Function       : CMaxScreenShots
In Parameters  : void, 
Out Parameters : 
Description    : Contructor
Author         : vyankatesh
--------------------------------------------------------------------------------------*/
CMaxScreenShots::CMaxScreenShots(void)
{
}

/*--------------------------------------------------------------------------------------
Function       : ~CMaxScreenShots
In Parameters  : void, 
Out Parameters : 
Description    : Destrcutor
Author         : vyankatesh
--------------------------------------------------------------------------------------*/
CMaxScreenShots::~CMaxScreenShots(void)
{
}

/*-------------------------------------------------------------------------------------
Function Name    : SaveCBitmapToJpeg
Parameters       : dc		 ->handle to device context
				   ObjBitMap ->CBitmap object
				   szFile    ->name of jpeg file to save
				   pWnd      ->win handle
Return Value     : BOOL
Purpose          : to take snapshot of window and save in Jpeg file
Author           : vyankatesh
--------------------------------------------------------------------------------------*/
BOOL CMaxScreenShots::SaveCBitmapToJpeg(CWindowDC &dc, CBitmap & ObjBitMap, TCHAR *szFile, CWnd *pWnd)
{
	try
	{
		CPalette	pal;
		BOOL		bRet = FALSE;
		TCHAR		szMsg[MAX_PATH] = {0};

		if(dc.GetDeviceCaps(RASTERCAPS)& RC_PALETTE)
		{
			UINT nSize = sizeof(LOGPALETTE) + (sizeof(PALETTEENTRY)* 256);
			LOGPALETTE *pLP = (LOGPALETTE *)new BYTE[nSize];
			pLP->palVersion = 0x300;
			pLP->palNumEntries = GetSystemPaletteEntries(dc, 0, 255, pLP->palPalEntry);
			pal.CreatePalette(pLP);
			delete[] pLP;
		}
		HANDLE hDIB = DDBToDIB(ObjBitMap, BI_RGB, &pal);
		if(hDIB == NULL)
		{
			bRet = FALSE;
		}

		if(JpegFromDib(hDIB, 90, szFile, szMsg))
		{
			bRet = TRUE;
		}
		else
		{
			bRet = FALSE;
		}

		GlobalFree(hDIB);
		return bRet;
	}
	catch(...)
	{
	}
	return FALSE;
}

/*-------------------------------------------------------------------------------------
Function Name    : DDBToDIB
Parameters       : CBitmap& bitmap, DWORD dwCompression, CPalette* pPal
Return Value     : BOOL
Purpose          : to convert DDB To DIB
Author           : vyankatesh
--------------------------------------------------------------------------------------*/
HANDLE CMaxScreenShots::DDBToDIB(CBitmap& bitmap, DWORD dwCompression, CPalette* pPal)
{
	try
	{
		BITMAP			bm;
		BITMAPINFOHEADER	bi;
		LPBITMAPINFOHEADER 	lpbi;
		DWORD			dwLen;
		HANDLE			hDIB;
		HANDLE			handle;
		HDC 			hDC;
		HPALETTE		hPal;

		ASSERT(bitmap.GetSafeHandle());
		if(dwCompression == BI_BITFIELDS)
		{
			return NULL;
		}

		hPal = (HPALETTE)pPal->GetSafeHandle();
		if(hPal == NULL)
		{
			hPal = (HPALETTE)GetStockObject(DEFAULT_PALETTE);
		}

		bitmap.GetObject(sizeof(bm), (LPTSTR)&bm);

		bi.biSize			 = sizeof(BITMAPINFOHEADER);
		bi.biWidth			 = bm.bmWidth;
		bi.biHeight 		 = bm.bmHeight;
		bi.biPlanes 		 = 1;
		bi.biBitCount		 = bm.bmPlanes * bm.bmBitsPixel;
		bi.biCompression	 = dwCompression;
		bi.biSizeImage		 = 0;
		bi.biXPelsPerMeter	 = 0;
		bi.biYPelsPerMeter	 = 0;
		bi.biClrUsed		 = 0;
		bi.biClrImportant	 = 0;

		int nColors = (1 << bi.biBitCount);
		if(nColors > 256)
		{
			nColors = 0;
		}

		dwLen  = bi.biSize + nColors * sizeof(RGBQUAD);
		hDC = ::GetDC(NULL);
		hPal = SelectPalette(hDC, hPal, FALSE);
		RealizePalette(hDC);

		hDIB = GlobalAlloc(GMEM_FIXED, dwLen);
		if(!hDIB)
		{
			SelectPalette(hDC, hPal, FALSE);
			::ReleaseDC(NULL, hDC);
			return NULL;
		}

		lpbi = (LPBITMAPINFOHEADER)hDIB;
		*lpbi = bi;

		GetDIBits(hDC, (HBITMAP)bitmap.GetSafeHandle(), 0L, (DWORD)bi.biHeight,
			(LPBYTE)NULL, (LPBITMAPINFO)lpbi, (DWORD)DIB_RGB_COLORS);

		bi = *lpbi;
		if(bi.biSizeImage == 0)
		{
			bi.biSizeImage = ((((bi.biWidth * bi.biBitCount) + 31)& ~31)/ 8)* bi.biHeight;
			if(dwCompression != BI_RGB)
			{
				bi.biSizeImage = (bi.biSizeImage * 3)/ 2;
			}
		}
		dwLen += bi.biSizeImage;
		if(handle = GlobalReAlloc(hDIB, dwLen, GMEM_MOVEABLE))
		{
			hDIB = handle;
		}
		else
		{
			GlobalFree(hDIB);
			SelectPalette(hDC, hPal, FALSE);
			::ReleaseDC(NULL, hDC);
			return NULL;
		}
		lpbi = (LPBITMAPINFOHEADER)hDIB;
		BOOL bGotBits = GetDIBits(hDC, (HBITMAP)bitmap.GetSafeHandle(), 0L,
			(DWORD)bi.biHeight, (LPBYTE)lpbi+ (bi.biSize + nColors * sizeof(RGBQUAD)),
			(LPBITMAPINFO)lpbi, (DWORD)DIB_RGB_COLORS);

		if(!bGotBits)
		{
			GlobalFree(hDIB);
			SelectPalette(hDC, hPal, FALSE);
			::ReleaseDC(NULL, hDC);
			return NULL;
		}
		SelectPalette(hDC, hPal, FALSE);
		::ReleaseDC(NULL, hDC);
		return hDIB;
	}
	catch(...)
	{
	}
	return 0;
}

/*-------------------------------------------------------------------------------------
Function		: JpegFromDib()
In Parameters	: hDib,     - Handle to DIB
				  nQuality  - JPEG quality (0-100)
				  csJpeg    - Pathname to jpeg file
				  pcsMsg    - Error msg to return
Out Parameters	: BOOL
Purpose			: to write jpeg files form Dib
Author			: vyankatesh
--------------------------------------------------------------------------------------*/
BOOL CMaxScreenShots::JpegFromDib(HANDLE hDib, int nQuality, TCHAR *csJpeg, TCHAR *pcsMsg)
{
	__try
	{
		if(nQuality < 0 || nQuality > 100 || hDib == NULL || pcsMsg == NULL || csJpeg == _T(""))
		{
			if(pcsMsg != NULL)
			{
				_tcscpy(pcsMsg, _T("Invalid input data"));
			}

			return FALSE;
		}
		_tcscpy(pcsMsg, _T(""));

		LPBITMAPINFOHEADER lpbi = (LPBITMAPINFOHEADER)hDib;
		byte *buf2 = 0;

		struct jpeg_compress_struct cinfo;
		struct jpeg_error_mgr       jerr;

		FILE*      pOutFile;
		int        nSampsPerRow;
		JSAMPARRAY jsmpArray;

		cinfo.err = jpeg_std_error(&jerr);
		jpeg_create_compress(&cinfo);

		if(0 != _tfopen_s(&pOutFile, static_cast<LPCTSTR>(csJpeg), _T("wb")))
		{
			_tcscpy(pcsMsg, L"Cannot open ");
			_tcscat(pcsMsg, csJpeg);
			jpeg_destroy_compress(&cinfo);
			return FALSE;
		}
		jpeg_stdio_dest(&cinfo, pOutFile);
		cinfo.image_width      = lpbi->biWidth;
		cinfo.image_height     = lpbi->biHeight;
		cinfo.input_components = 3;
		cinfo.in_color_space   = JCS_RGB; 

		jpeg_set_defaults(&cinfo);
		jpeg_set_quality(&cinfo, nQuality, TRUE);
		jpeg_start_compress(&cinfo, TRUE);
		nSampsPerRow = cinfo.image_width * cinfo.input_components;
		jsmpArray = (*cinfo.mem->alloc_sarray)((j_common_ptr)&cinfo, JPOOL_IMAGE, nSampsPerRow, cinfo.image_height);

		if(DibToSamps(hDib, nSampsPerRow, cinfo, jsmpArray, pcsMsg))
		{
			(void)jpeg_write_scanlines(&cinfo, jsmpArray, cinfo.image_height);
		}

		jpeg_finish_compress(&cinfo);

		if(pOutFile)
		{
			fclose(pOutFile);
		}

		jpeg_destroy_compress(&cinfo);

		if(_tcslen(pcsMsg) > 0)
		{
			return FALSE;
		}
		else
		{
			return TRUE;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
	}
	return FALSE;
}
/*-------------------------------------------------------------------------------------
Function		: DibToSamps()
In Parameters	: hDib, 			- Handle to DIB
				  nSampsPerRow, - JPEG quality (0-100)
				  cinfo, 		- Pathname to jpeg file
				  jsmpPixels)  - array of RGB values
				  pcsMsg		- Error msg to return
Out Parameters	: BOOL
Purpose			: This function fills a jsmpArray with the RGB values for the CBitmap.
Author			: vyankatesh
--------------------------------------------------------------------------------------*/
BOOL CMaxScreenShots::DibToSamps(HANDLE hDib, int nSampsPerRow, jpeg_compress_struct cinfo,
								 JSAMPARRAY jsmpPixels, TCHAR *pcsMsg)
{
	if(hDib == NULL || nSampsPerRow <= 0 || pcsMsg == NULL)
	{
		if(pcsMsg != NULL)
		{
			_tcscpy(pcsMsg, _T("Invalid input data"));
		}
		return FALSE;
	}

	int r = 0, p = 0, q = 0, b = 0, n = 0,
		nUnused = 0, nBytesWide = 0, nUsed = 0, nLastBits = 0, nLastNibs = 0, nCTEntries = 0,
		nRow = 0, nByte = 0, nPixel = 0;
	BYTE bytCTEnt = 0;
	LPBITMAPINFOHEADER pbBmHdr = (LPBITMAPINFOHEADER)hDib;

	switch (pbBmHdr->biBitCount)
	{
	case 1:
		nCTEntries = 2;
		break;
	case 4:
		nCTEntries = 16;
		break;
	case 8:
		nCTEntries = 256;
		break;
	case 16:
	case 24:
	case 32:
		nCTEntries = 0;
		break;
	default:
		_tcscpy(pcsMsg, L"Invalid bitmap bit count");
		return FALSE;
	}

#pragma warning(disable: 4311)
	DWORD     dwCTab = reinterpret_cast<DWORD>(pbBmHdr) + pbBmHdr->biSize;
#pragma warning(default: 4311)

#pragma warning(disable: 4312)
	LPRGBQUAD pCTab = reinterpret_cast<LPRGBQUAD>(dwCTab);
#pragma warning(default: 4312)

	LPSTR     lpBits = (LPSTR)pbBmHdr + (WORD)pbBmHdr->biSize +(WORD)(nCTEntries * sizeof(RGBQUAD));
	LPBYTE   lpPixels = (LPBYTE) lpBits;
	RGBQUAD* pRgbQs   = (RGBQUAD*)lpBits;
	WORD*    wPixels  = (WORD*)  lpBits;

	switch (pbBmHdr->biBitCount)
	{
	case 1:
		nUsed      = (pbBmHdr->biWidth + 7)/ 8;
		nUnused    = (((nUsed + 3)/ 4)* 4) - nUsed;
		nBytesWide = nUsed + nUnused;
		nLastBits  = 8 - ((nUsed * 8) - pbBmHdr->biWidth);
		for (r = 0; r < pbBmHdr->biHeight; r++)
		{
			for (p = 0, q = 0; p < nUsed; p++)
			{
				nRow = (pbBmHdr->biHeight-r-1)* nBytesWide;
				nByte =  nRow + p;
				int nBUsed = (p <(nUsed+1))? 8 : nLastBits;
				for(b = 0; b < nBUsed;b++)
				{
					bytCTEnt = lpPixels[nByte] << b;
					bytCTEnt = bytCTEnt >> 7;

					jsmpPixels[r][q+0] = pCTab[bytCTEnt].rgbRed;
					jsmpPixels[r][q+1] = pCTab[bytCTEnt].rgbGreen;
					jsmpPixels[r][q+2] = pCTab[bytCTEnt].rgbBlue;
					q += 3;
				}
			}
		}
		break;
	case 4:
		nUsed      = (pbBmHdr->biWidth + 1)/ 2;
		nUnused    = (((nUsed + 3)/ 4)* 4) - nUsed;
		nBytesWide = nUsed + nUnused;
		nLastNibs  = 2 - ((nUsed * 2) - pbBmHdr->biWidth);

		for (r = 0; r < pbBmHdr->biHeight;r++)
		{
			for (p = 0, q = 0; p < nUsed;p++)
			{
				nRow = (pbBmHdr->biHeight-r-1)* nBytesWide;
				nByte = nRow + p;
				int nNibbles = p;
				for(n = 0; n < nNibbles;n++)
				{
					bytCTEnt = lpPixels[nByte] << (n*4);
					bytCTEnt = bytCTEnt >> (4-(n*4));
					jsmpPixels[r][q+0] = pCTab[bytCTEnt].rgbRed;
					jsmpPixels[r][q+1] = pCTab[bytCTEnt].rgbGreen;
					jsmpPixels[r][q+2] = pCTab[bytCTEnt].rgbBlue;
					q += 3;
				}
			}
		}
		break;
	default:
	case 8:
		nUnused = (((pbBmHdr->biWidth + 3)/ 4)* 4) - pbBmHdr->biWidth;

		for (r = 0;r < pbBmHdr->biHeight; r++)
		{
			for (p = 0, q = 0; p < pbBmHdr->biWidth; p++, q+= 3)
			{
				nRow   = (pbBmHdr->biHeight-r-1)* (pbBmHdr->biWidth + nUnused);
				nPixel =  nRow + p;
				jsmpPixels[r][q+0] = pCTab[lpPixels[nPixel]].rgbRed;
				jsmpPixels[r][q+1] = pCTab[lpPixels[nPixel]].rgbGreen;
				jsmpPixels[r][q+2] = pCTab[lpPixels[nPixel]].rgbBlue;
			}
		}
		break;

	case 16:
		for (r = 0;r < pbBmHdr->biHeight; r++)
		{
			for (p = 0, q = 0; p < pbBmHdr->biWidth; p++, q+= 3)
			{
				nRow    = (pbBmHdr->biHeight-r-1)* pbBmHdr->biWidth;
				nPixel  = nRow + p;
				RGBQUAD quad = QuadFromWord(wPixels[nPixel]);
				jsmpPixels[r][q+0] = quad.rgbRed;
				jsmpPixels[r][q+1] = quad.rgbGreen;
				jsmpPixels[r][q+2] = quad.rgbBlue;
			}
		}
		break;

	case 24:
		nBytesWide =  (pbBmHdr->biWidth*3);
		nUnused    =  (((nBytesWide + 3)/ 4)* 4) - nBytesWide;
		nBytesWide += nUnused;

		for (r = 0;r < pbBmHdr->biHeight;r++)
		{
			for (p = 0, q = 0;p < (nBytesWide-nUnused); p+= 3, q+= 3)
			{
				nRow = (pbBmHdr->biHeight-r-1)* nBytesWide;
				nPixel  = nRow + p;
				jsmpPixels[r][q+0] = lpPixels[nPixel+2]; //Red
				jsmpPixels[r][q+1] = lpPixels[nPixel+1]; //Green
				jsmpPixels[r][q+2] = lpPixels[nPixel+0]; //Blue
			}
		}
		break;

	case 32:
		for (r = 0; r < pbBmHdr->biHeight; r++)
		{
			for (p = 0, q = 0; p < pbBmHdr->biWidth; p++, q+= 3)
			{
				nRow    = (pbBmHdr->biHeight-r-1)* pbBmHdr->biWidth;
				nPixel  = nRow + p;
				jsmpPixels[r][q+0] = pRgbQs[nPixel].rgbRed;
				jsmpPixels[r][q+1] = pRgbQs[nPixel].rgbGreen;
				jsmpPixels[r][q+2] = pRgbQs[nPixel].rgbBlue;
			}
		}
		break;
	}   //end switch

	return TRUE;
}

/*--------------------------------------------------------------------------------------
Function       : QuadFromWord
In Parameters  : WORD b16, 
Out Parameters : RGBQUAD 
Description    : F\Get Quad from WORD
Author         : vyankatesh
--------------------------------------------------------------------------------------*/
RGBQUAD CMaxScreenShots::QuadFromWord(WORD b16)
{
	BYTE bytVals[] =
	{
		0,  16, 24, 32,  40, 48, 56, 64,
		72, 80, 88, 96, 104, 112, 120, 128,
		136, 144, 152, 160, 168, 176, 184, 192,
		200, 208, 216, 224, 232, 240, 248, 255
	};

	WORD wR = b16;
	WORD wG = b16;
	WORD wB = b16;

	wR <<= 1; wR >>= 11;
	wG <<= 6; wG >>= 11;
	wB <<= 11; wB >>= 11;

	RGBQUAD rgb;

	rgb.rgbReserved = 0;
	rgb.rgbBlue     = bytVals[wB];
	rgb.rgbGreen    = bytVals[wG];
	rgb.rgbRed      = bytVals[wR];

	return rgb;
}
