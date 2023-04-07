/*=============================================================================
FILE		           : TransparentStatic.cpp
ABSTRACT		       : To Make The Label Transprent.
DOCUMENTS	       : Refer The GUI Design.doc, GUI Requirement Document.doc
AUTHOR		       : 
COMPANY		       : Aura
COPYRIGHT NOTICE    :
(C)Aura:
Created as an unpublished copyright work.  All rights reserved.
This document and the information it contains is confidential and
proprietary to Aura.  Hence, it may not be 
used, copied, reproduced, transmitted, or stored in any form or by any 
means, electronic, recording, photocopying, mechanical or otherwise, 
without the prior written permission of Aura
CREATION DATE      : 2/24/06
NOTES		      : Header file for Class To Make The Label Transprent.
VERSION HISTORY    : 

=============================================================================*/
#ifndef CTRANSPARENTSTATIC_H
#define CTRANSPARENTSTATIC_H

#pragma once

class CTransparentStatic : public CStatic
{
	DECLARE_DYNAMIC( CTransparentStatic )
public:
	CTransparentStatic( void );
	virtual		~CTransparentStatic( void );
protected:
	DECLARE_MESSAGE_MAP()
	afx_msg void	OnPaint( void );
};
#endif //  CTRANSPARENTSTATIC_H

