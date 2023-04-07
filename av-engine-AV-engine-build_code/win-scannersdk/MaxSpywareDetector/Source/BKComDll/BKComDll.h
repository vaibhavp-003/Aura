/**
	\file BKComDll.h
	\brief Header File of Backend functional class
* FILE				 : BKComDll.h
*
* AUTHOR		     : Core Development Team
* COMPANY		     : Aura 
*
* COPYRIGHT(NOTICE):
*				  (C) Aura
*				  Created in 2022 as an unpublished copyright work.  All rights reserved.
*				  This document and the information it contains is confidential and
*				  proprietary to Aura.  Hence, it may not be
*				  used, copied, reproduced, transmitted, or stored in any form or by any
*				  means, electronic, recording, photocopying, mechanical or otherwise,
*				  without the prior written permission of Aura.
*
* NOTES		     : Class to communicate with UI to backend functionality in c++
 */

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'pch.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols
#include "PipeCom.h"
#include "MaxCommunicator.h"
#include "MaxProcessReg.h"
#include "MaxCommunicatorServer.h"
#include "MaxExceptionFilter.h"
#include "ScanProcess.h"
#include "ThreatInfo.h"
#include "RegistrationStatus.h"
#include "FullScanReport.h"
#include "USBScan.h"

// CBKComDllApp
// See BKComDll.cpp for the implementation of this class
//

 /** \class CBKComDllApp
	 \brief A Functional Class of Backend to communicate with UI.
  */
class CBKComDllApp : public CWinApp
{
public:
	CBKComDllApp();

// Overrides
public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();

	DECLARE_MESSAGE_MAP()

public:
	/** \var CPipeCom m_objPipeCom
	  *	 \brief Object of PipeCom class to perform interprocess communication
	  */
	CPipeCom m_objPipeCom;

	/** \var CScanProcess m_objScanProcess
	  *	 \brief Object of ScanProcess class to perform scanning
	  */
	CScanProcess m_objScanProcess;

	/** \var CThreatInfo m_objThreatInfo
	  *	 \brief Object of ThreatInfo class to perform scanning
	  */
	CThreatInfo m_objThreatInfo;

	/** \var CFullScanReport m_objFullScanReport
	  *	 \brief Object of FullScanReport class to get reports
	  */
	CFullScanReport m_objFullScanReport;

	/** \var CUSBScan m_objUSBScan
	  *	 \brief Object of CUSBScan class to perform usb/custom right click scanning
	  */
	CUSBScan m_objUSBScan;

	/** \var SENDTDSSMESSAGETOULTRAUI m_pSendMsgUltraUI
	  *	 \brief Callback function pointer of UI class to show scan status
	  */
	SENDTDSSMESSAGETOULTRAUI m_pSendMsgUltraUI;

	/** \var SENDDETECTIONTOULTRAUI m_pSendDetectionToUltraUI
	  *	 \brief Callback function pointer of UI class to show detection status
	  */
	SENDDETECTIONTOULTRAUI m_pSendDetectionToUltraUI;

	/** \var static bool m_bUISrvRunning
	  *	 \brief Is communication service running or not
	  */
	static bool m_bUISrvRunning;

	/** \var static bool m_bScannerRunning
	  *	 \brief Is scanner running or not
	  */
	static bool m_bScannerRunning;

	/** \var CString m_csScannerID
	  *	 \brief Scanner unique ID
	  */
	CString m_csScannerID;

	/** \var CString m_csGUID
	  *	 \brief UI unique ID
	  */
	CString m_csGUID;

	/** \var bool m_bAutoQuarantine
	  *	 \brief Auto quarantine is ON/OFF
	  */
	bool m_bAutoQuarantine;

	/** \var bool m_bRegWDThreadRunning
	  *	 \brief Is UI is register with service thread status
	  */
	bool m_bRegWDThreadRunning;

	/** \var ENUM_SCAN_CONDITION eScanStartedBy
	  *	 \brief Scan launch type(by user or scheduler)
	  */
	ENUM_SCAN_CONDITION eScanStartedBy;

	/** \var static int	 m_iControlFlag
	  *	 \brief For registration status
	  */
	static int	 m_iControlFlag;

	/** \var CMaxCommunicatorServer* m_pObjMaxCommunicatorServer
	  *	 \brief Pointer of CMaxCommunicatorServer class to create communication server
	  */
	CMaxCommunicatorServer* m_pObjMaxCommunicatorServer;

	/** \var CMaxCommunicator m_objWDMaxCommunicator
	  *	 \brief Object of CMaxCommunicator class to create communication client
	  */
	CMaxCommunicator m_objWDMaxCommunicator;

	/** \var CMaxProcessReg m_obgRegProcess
	  *	 \brief Object of CMaxProcessReg class use to register our processes with service
	  */
	CMaxProcessReg m_obgRegProcess;

	/** \var MAX_WD_DATA m_sMaxWDData
	  *	 \brief Object of MAX_WD_DATA structure to communicate with service
	  */
	MAX_WD_DATA m_sMaxWDData;

	/** \var UScanStatusData m_objScanStatusData
	  *	 \brief Object of UScanStatusData structure for scan current status
	  */
	UScanStatusData m_objScanStatusData;

	/** \var HANDLE m_hAppStopEvent
	  *	 \brief Handle to check App stop event
	  */
	HANDLE m_hAppStopEvent;

	/** \var CWinThread* m_pWinThread
	  *	 \brief Thread pointer of WDConnectionThread 
	  */
	CWinThread* m_pWinThread;

	/** \var CString m_csCommand
	  *	 \brief Command line parameters
	  */
	CString m_csCommand;
	
	/** \fn  WDConnectionThread(LPVOID lParam)
	  *	 \brief This function communicate with service
	  *	 \param LPVOID lParam : Thread options
	  *  \return UINT
	  */
	static UINT WDConnectionThread(LPVOID lParam);

	
	/** \fn  CallCloseWPFUI()
	  *	 \brief This function closed all the handles opened for UI
	  *  \return bool : (TRUE : SUCCESS, FALSE : FAILURE)
	  */
	bool CallCloseWPFUI();

	/** \fn  ShutdownScannersAndCloseUI()
	  *	 \brief Shutdown event from message
	  *  \return void
	  */
	void ShutdownScannersAndCloseUI();

	/** \fn PrepareValueForDispaly(MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR* strValue, int iSizeOfBuffer)
	  *	 \brief This function prepare reg key to display on UI
	  *	 \param MAX_PIPE_DATA_REG& sMaxPipeDataReg : Reference to MAX_PIPE_DATA_REG @see MAX_PIPE_DATA_REG
	  *  \param WCHAR* strValue : Reference to registry name
	  *  \param int iSizeOfBuffer : Buffer size
	  *  \return void
	  */
	void PrepareValueForDispaly(MAX_PIPE_DATA_REG& sMaxPipeDataReg, WCHAR* strValue, int iSizeOfBuffer);

	/** \fn GetThreatInfo(ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId)
	  *	 \brief This function prepare spyware name to display on UI
	  *	 \param ULONG ulSpyName : Spyware name id
	  *  \param CString& csSpyName : Reference to spyware name
	  *  \param BYTE& bThreatIndex : Threat index
	  *  \param CString& csHelpInfo : Information of threat
	  *  \param CString csKeyValue : Original spyware(threat) name
	  *  \param int iTypeId : Type of scanned object
	  *  \return bool : (true : SUCCESS, false : FAILURE)
	  */
	bool GetThreatInfo(ULONG ulSpyName, CString& csSpyName, BYTE& bThreatIndex, CString& csHelpInfo, CString csKeyValue, int iTypeId);

	/** \fn GetRegisrationStatus()
	  *	 \brief This function return registration status
	  *  \return REGISTRATION_STATUS : Registered or not
	  */
	REGISTRATION_STATUS GetRegisrationStatus();

	/** \fn IsSDReadyForFullScan(bool bFullScan)
	  *	 \brief This function check if scanner is ready to launch
	  *	 \param bool bFullScan : Full scan or not
	  *  \return bool : (true : SUCCESS, false : FAILURE)
	  */
	bool IsSDReadyForFullScan(bool bFullScan);

	/** \fn LaunchOtherProcess()
		  *	 \brief This function launch other processes
		  *  \return bool : (true : SUCCESS, false : FAILURE)
		  */
	bool LaunchOtherProcess();

	/** \fn CheckPrequisites()
	  *	 \brief This function check if product patch or database path is set
	  *  \return bool : (true : SUCCESS, false : FAILURE)
	 */
	bool CheckPrequisites();

	/** \fn AddExcludeEntriesDB()
	  *	 \brief This function update exclude entries
	  *  \return bool : (true : SUCCESS, false : FAILURE)
	 */
	bool AddExcludeEntriesDB();

};
extern CBKComDllApp theApp;
