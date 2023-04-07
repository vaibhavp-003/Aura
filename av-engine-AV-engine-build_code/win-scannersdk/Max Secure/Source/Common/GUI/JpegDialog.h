/*=============================================================================
   FILE			: JpegDialog.h
   ABSTRACT		: 
   DOCUMENTS	: Refer The ---- document
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
CREATION DATE   : 2/24/06
   NOTES		: Common GUI JPEG Handling class
VERSION HISTORY	:
===========================================================================*/

#pragma once

class CJpegDialog : public CDialog
{
public:
	CJpegDialog(){};
	CJpegDialog(UINT nTemplateID, CWnd* pParent = NULL);	// standard constructor
	virtual ~CJpegDialog();

	BOOL Load(LPCTSTR szFileName);
	BOOL Load(LPCTSTR szResourceName, LPCTSTR szResourceType);
	BOOL Load(HGLOBAL hGlobal, DWORD dwSize);
	BOOL Load(HMODULE m_hResHandle, LPCTSTR szResourceName, LPCTSTR szResourceType);
	
	inline SIZE GetPictureSize()
	{
		return m_PictureSize;
	}

	BOOL Draw();
	DWORD LoadJPEG(int jpgDPI_96, int jpgDPI_120, int jpgDPI_98120);
	void UnLoad();

	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg LRESULT OnNcHitTest(CPoint point);

protected:
	DECLARE_MESSAGE_MAP()
private:
	BOOL PrepareDC(int nWidth, int nHeight);

	RECT		m_PaintRect;
	HDC			m_hMemDC;
	SIZE		m_PictureSize;
	UINT		m_nDataSize;
	HBITMAP		m_hBitmap;
	HBITMAP		m_hOldBitmap;
	IPicture	*m_pPicture;
	COLORREF	m_clrBackground;
	BOOL		m_bIsInitialized;

};