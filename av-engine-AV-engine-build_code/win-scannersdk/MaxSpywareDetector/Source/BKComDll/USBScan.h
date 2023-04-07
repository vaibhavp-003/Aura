/**
	\file USBScan.h
	\brief Header File of USBScan class
* FILE				 : CUSBScan.h
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
* NOTES		     : Class to communicate with UI to start scanning
 */
#pragma once
#include "MaxCommunicatorServer.h"
#include "MaxDSrvWrapper.h"

/** \class CUSBScan
	 \brief A Functional Class of USB and right click scanning.
  */
class CUSBScan
{
public:
	CUSBScan();
	~CUSBScan();

	bool			m_bFullScan;
	bool			m_bCustomScan;
	bool			m_bQuickScan;
	bool			m_bScheduleScan;
	bool			m_bDeepScan;
	bool			m_bStartedScanner;
	bool			m_bRestartRequired;
	TCHAR			m_szDrivesToScan[MAX_PATH];

	UScanStartInfo m_objScanStartInfo;

	CString m_csGUID;
	CString m_csScannerID;
	
	static CMaxDSrvWrapper* m_pMaxDSrvWrapper;


	/** \fn LaunchScan
	  *	 \brief This function launch usb and right click custom scan
	  *  \return bool : (true : SUCCESS, false : FAILURE)
	  */
	bool LaunchScan();

	/** \fn CloseUI
	  *	 \brief This function clean up all the handles
	  *  \return bool : (true : SUCCESS, false : FAILURE)
	  */
	bool CloseUI();

	/** \fn StopScan
	  *	 \brief This function stop scanning process
	  *  \return bool : (true : SUCCESS, false : FAILURE)
	  */
	bool StopScan();

	/** \fn OnScanDataReceivedCallBack
	  *	 \brief This function received data from scanner
	  *  \param LPVOID lParam : Communication data
	  *  \return void
	  */
	static void OnScanDataReceivedCallBack(LPVOID lpParam);

	bool StartScan(CString csDrive, bool bSignatureScan, bool bVirusScan, bool bRootkitScan, bool bKeyLoggerScan, bool bHeuristicScan, bool bDBScan, bool bCustomScan, bool bDeepScan, bool bAutoQuarantine);

	void QuarantineData(DWORD dwQuarantineDataLength, DWORD* ptrQuarantineData, DWORD dwTotalCount, DWORD* ptrQuarantinedData);
	void ShutdownStatus(bool bShutdown);

private:
	BOOL			m_bStop;
	bool			m_bStopScan;
	DWORD			m_dwThreatCount;
	bool			m_bShutdown;

	ScanCurrentStatus m_eProcessStatus;
	DWORD m_dwTotalFilesScanned;
	
	CWinThread* m_pThreadScanner;
	CWinThread* m_pThreadQuarantine;

	void StopControls();
	


};

