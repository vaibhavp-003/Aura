/*=============================================================================
   FILE		           : MemDC.h
   ABSTRACT		       : This class implements a memory Device Context
   DOCUMENTS	       : Refer The Live Update Design.doc, Live Update Requirement Document.doc
   AUTHOR		       :
   COMPANY		       : Aura 
   COPYRIGHT NOTICE    :
						(C) Aura
						 Created as an unpublished copyright work.  All rights reserved.
						 This document and the information it contains is confidential and
						 proprietary to Aura.  Hence, it may not be 
						 used, copied, reproduced, transmitted, or stored in any form or by any 
						 means, electronic, recording, photocopying, mechanical or otherwise, 
						 without the prior written permission of Aura.	
   CREATION DATE      : 7/10/07
   NOTES		      : Header file for class implementing a memory Device Context
   VERSION HISTORY    : 
=============================================================================*/

#ifndef MEMDC_H
#define MEMDC_H

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning(disable: 6011)
#endif

class CMemDCEx : public CDC
{
public:
    // constructor sets up the memory DC
    CMemDCEx(CDC* pDC) : CDC()
    {
        ASSERT(pDC != NULL);

        m_pDC = pDC;
        m_pOldBitmap = NULL;
        m_bMemDC = !pDC->IsPrinting();
              
        if (m_bMemDC)    // Create a Memory DC
        {
            pDC->GetClipBox(&m_rect);
            CreateCompatibleDC(pDC);
            m_bitmap.CreateCompatibleBitmap(pDC, m_rect.Width(), m_rect.Height());
            m_pOldBitmap = SelectObject(&m_bitmap);
            SetWindowOrg(m_rect.left, m_rect.top);
        }
        else        // Make a copy of the relevent parts of the current DC for printing
        {
            m_bPrinting = pDC->m_bPrinting;
            m_hDC       = pDC->m_hDC;
            m_hAttribDC = pDC->m_hAttribDC;
        }
    }
    
    // Destructor copies the contents of the mem DC to the original DC
    ~CMemDCEx()
    {
        if (m_bMemDC) 
        {    
            // Copy the offscreen bitmap onto the screen.
            m_pDC->BitBlt(m_rect.left, m_rect.top, m_rect.Width(), m_rect.Height(),
                          this, m_rect.left, m_rect.top, SRCCOPY);

            //Swap back the original bitmap.
            SelectObject(m_pOldBitmap);
        } else {
            // All we need to do is replace the DC with an illegal value,
            // this keeps us from accidently deleting the handles associated with
            // the CDC that was passed to the constructor.
            m_hDC = m_hAttribDC = NULL;
        }
    }

    // Allow usage as a pointer
    CMemDCEx* operator->() {return this;}
        
    // Allow usage as a pointer
    operator CMemDCEx*() {return this;}

private:
    CBitmap  m_bitmap;      // Offscreen bitmap
    CBitmap* m_pOldBitmap;  // bitmap originally found in CMemDCEx
    CDC*     m_pDC;         // Saves CDC passed in constructor
    CRect    m_rect;        // Rectangle of drawing area.
    BOOL     m_bMemDC;      // TRUE if CDC really is a Memory DC.
};

#ifndef INCLUDE_VSTS_WARNINGS
#pragma warning (default:6011)
#endif
#endif //MEMDC_H