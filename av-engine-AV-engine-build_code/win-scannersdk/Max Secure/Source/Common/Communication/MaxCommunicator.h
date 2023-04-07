/*======================================================================================
FILE             : MaxCommunicator.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Darshit Kasliwal
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
CREATION DATE    : 5/14/2009
NOTES		     : CMaxCommunicator is implemeted as a Named pipe client.This class
				   is used by all the client applications that need to communicate with
				    the Named pipe servers decalred in MaxPipes.h
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include "MaxConstant.h"
class CMaxCommunicator
{
public:
	// Constructor
	CMaxCommunicator(const TCHAR* tchPipeName, bool bRetryConnection = false);
	// Destructor
	~CMaxCommunicator();
	// Member Functions
	bool SendData(LPVOID lpMaxData, DWORD dwSize);
	bool ReadData(LPVOID lpMaxData, DWORD dwSize);
	void Close();
private:
	// To connect to a given named pipe
	bool Connect(void);
	// Handle to the Named Pipe
	HANDLE m_hPipe;
	// Pipe Name
	TCHAR m_tchPipe[MAX_PATH];
	bool m_bRetryConnection;
};