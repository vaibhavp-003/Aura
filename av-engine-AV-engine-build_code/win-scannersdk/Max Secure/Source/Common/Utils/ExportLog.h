/*=============================================================================
   FILE			: ExportLog.h
   ABSTRACT		: 
   DOCUMENTS	: CommonSystem DesignDoc.doc
   AUTHOR		: Sandip Sanap
   COMPANY		: Aura 
COPYRIGHT NOTICE:
				(C) Aura
				Created as an unpublished copyright work.  All rights reserved.
				This document and the information it contains is confidential and
				proprietary to Aura.  Hence, it may not be 
				used, copied, reproduced, transmitted, or stored in any form or by any 
				means, electronic, recording, photocopying, mechanical or otherwise, 
				with out the prior written permission of Aura
CREATION DATE   : 20/09/2006
   NOTES		:
VERSION HISTORY	:24 Aug 2007, Avinash B : Unicode Supported
============================================================================*/
#pragma once
#include "Registry.h"
#include "shlwapi.h"

class CExportLog
{
public:
	CExportLog(void); //Constructor
	~CExportLog(void); //Destructor

	void AddHijackLogEntry();
	void AddSystemLogEntry(bool bSd = false);
	//functions add by sandip to merge sd and rc
	bool OpenLogFile(CString csFileName);
	bool CloseLogFile();
	void WriteLog(CString csWriteStr);
	void WriteScanStatus(int,CString);
	CString GetLine(void);
	void WriteLine(void);
private:
	static CStdioFile m_objExportFile;

};//CExportLog Class Ends

