/*=============================================================================
   FILE			: FileRW.cpp
   ABSTRACT		: Implementation of the CFileRW class.
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
VERSION HISTORY	: 21 Aug 2007, Avinash B
				  Unicode Supported
============================================================================*/
#pragma once

class CExportFileOperations
{
public:
	bool OpenLogFile(CString csFileName);
	void WriteLog(CString csWriteStr);
	void WriteLog(CStdioFile& pTempLog, CString csFilePath);
	void WriteScanStatus(int,CString);
	void WriteLine(void);
	bool CloseLogFile();
	CString GetLine(void);
	void WriteScanLog(HANDLE hFileHandle,CString csFilePath);

private:
	void WriteToFile(HANDLE fileHandle, CString csDataToWrite);
	CStdioFile m_objExportFile;
};
