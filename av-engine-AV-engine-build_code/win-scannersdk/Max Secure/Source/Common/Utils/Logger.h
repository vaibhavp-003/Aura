
/*======================================================================================
FILE             : Logger.h
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
CREATION DATE    : 9/04/2009 12:04:49 PM
NOTES		     : Declares the Singleton Logger class
VERSION HISTORY  : 
======================================================================================*/
#pragma once
#include <string>

const TCHAR LINE_SEPARATOR[] = _T("\r\n");

interface ILogger{
	virtual void OnReceiveLogCallback(LPCTSTR szLogMsg) = 0;
};

class CLogger
{
public:
  void Initialize(LPCTSTR szLogFileName,bool bShowDetails = true,ILogger *pILogger = NULL,bool bShowConsole = true);
  void AddLog(LPCTSTR szSource,LPCTSTR szDestination,LPCTSTR szFormatString, ...);
  void AddLog1(LPCTSTR szFormatString, ...);
  void CloseLog();
  void LogCallback(LPCTSTR szFormatString);

  ~CLogger(void);
  CLogger();
private:
  bool m_bFirstLine;
  TCHAR m_szLogFileName[MAX_PATH];
  ILogger *m_pILogger;
  FILE *m_pFile;
  bool m_bShowDetails;
  bool m_bShowConsole;
};
extern CLogger g_objLogApp;