/*======================================================================================
FILE             : Singleinstance.h
ABSTRACT         : 
DOCUMENTS        : 
AUTHOR           : Darshan Singh Virdi
COMPANY          : Aura 
COPYRIGHT(NOTICE): (C) Aura
                   Created as an unpublished copyright work.  All rights reserved.
                   This document and the information it contains is confidential and
                   proprietary to Aura.  Hence, it may not be
                   used, copied, reproduced, transmitted, or stored in any form or by any
                   means, electronic, recording, photocopying, mechanical or otherwise,
                   without the prior written permission of Aura.
CREATION DATE   : 24-Feb-2006
NOTES           : Defines the class behaviors for the application
VERSION HISTORY : 
======================================================================================*/
#pragma once

class CSingleInstance
{
public :

	// Constructor/Destructor
	CSingleInstance();
	virtual ~CSingleInstance ();

	// Creates the instance handler
	BOOL Create(CString& csGUID);
	// Callback when the instance is woken up by another
	virtual void WakeUp(LPCTSTR aCommandLine)const;

	BOOL SingleInstancePerSession(LPCTSTR szUniqueGUID);

private :
	// The implementation handler, "pimple"
	class CSingleInstanceImpl* mImplementor;
};
