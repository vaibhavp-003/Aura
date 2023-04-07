/*======================================================================================
FILE             : SDSAConstants.h
ABSTRACT         :
DOCUMENTS	     :
AUTHOR		     :
COMPANY		     : Aura 
COPYRIGHT(NOTICE):
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be
				  used, copied, reproduced, transmitted, or stored in any form or by any
				  means, electronic, recording, photocopying, mechanical or otherwise,
				  without the prior written permission of Aura.

CREATION DATE    : 2/24/06
NOTES		     : Declaring SD contants
VERSION HISTORY  :
======================================================================================*/
#pragma once
#include "SDConstants.h"


#define PRODUCT_REG			_T("SOFTWARE\\UltraAV")
#define PRODUCTNAME			_T("UltraAV")

	#define DRWATSON_KEY		_T("SOFTWARE\\Microsoft\\DrWatson")	
	#define AEDEBUG_KEY			_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug")

		
	const HKEY ACTIVEPROTECTIONKEY	=	HKEY_CURRENT_USER;
	#ifdef WIN64
		#define PRODUCTKEY				 _T("NewProductDetailsx64")
		#define VIRUSKEY					 _T("VirusDetailsx64")
		#define SDUPDATEKEY				 _T("SDUpdateDetailsX64")
		#define SDFIRSTPRIORITYKEY				 _T("FirstPriorityPatchDetailsX64")

	#else
		
		#define PRODUCTKEY				 _T("NewProductDetails")
		#define SDUPDATEKEY				 _T("SDUpdateDetails")
		#define VIRUSKEY					 _T("VirusDetails")
		#define FIREWALLKEY					 _T("FirewallDetails")
		#define SDFIRSTPRIORITYKEY			_T("FirstPriorityPatchDetails")


	#endif
	#define DOWNLOADTHREADDETAILS  _T("DownLoadThreadCountDetails")
	#define EVALUATION_PERIOD		_T("30")
	#define EVALUATION_PERIOD_INT	30
	#define VERSION					_T("25")



#define  ACTMON_TRAY_NAME  _T("AuTray.exe")
#define SRV_OPT_EXE		_T("AuSrvOpt.exe")  
#define ACT_MON_TRAY_EXE		_T("AuTray.exe")  
#define LIVEUPDATE_EXE			_T("AULIVEUPDATE.EXE")

#define REFER_FRIEND_URL	_T("/referfriend.asp")


#define RED					159
#define GREEN				182
#define BLUE				250

#define TABINFORMATIONLABLE		RGB(45, 75, 145)
#define BANNER_TEXT_COLOR		RGB(140, 8, 3)
#define BTN_TEXT_COLOR			RGB(17, 31, 118)
#define TABBACKGROUND			RGB(131, 161, 243)
#define TAB_TEXT_COLOR			RGB(39, 74, 155)

const UINT ID_BUTTON_EXCLUDE				= 10000;
const UINT ID_BUTTON_COOKIE					= 10001;
const UINT ID_BUTTON_SYSSETTING				= 10002;
const UINT ID_BUTTON_REGFIX					= 10003;
const UINT ID_BUTTON_INETFIX				= 10004;
const UINT ID_BUTTON_VIEWPROC				= 10005;
const UINT ID_BUTTON_STARTUP				= 10006;
const UINT ID_BUTTON_PRODINFO				= 10007;
const UINT ID_BUTTON_QUICKSCAN				= 10008;
const UINT ID_BUTTON_CUSTOMSCAN				= 10009;
const UINT ID_BUTTON_FULLSCAN				= 10010;
const UINT ID_BUTTON_SCHEDULAR				= 10011;
const UINT ID_BUTTON_SCANREPORT				= 10012;
const UINT ID_BUTTON_CUSTOM_SETTING 		= 10013;
const UINT ID_BUTTON_ADVANCED_SETTING 		= 10014;
const UINT ID_BUTTON_PROXY_SETTING 			= 10015;
const UINT ID_BUTTON_SCANBYNAME_SETTING 	= 10016;
const UINT ID_BUTTON_FW_OVERVIEW		= 10017;
const UINT ID_BUTTON_APPRULES			= 10018;
const UINT ID_BUTTON_COMMON_TAB			= 10019;
const UINT ID_BUTTON_EMAIL_SCAN			= 10020;
const UINT ID_BUTTON_PARCONTROL			= 10021;
const UINT ID_BUTTON_NETWORK_BLOCK      = 10022;
const UINT ID_BUTTON_WEBFILTER			= 10023;
const UINT ID_BUTTON_FW_USBMANAGER 			= 10024;
const UINT ID_BUTTON_SCANGRAPH			= 10025;
const UINT ID_BUTTON_MOIBLESCAN 			= 10026;

const int BUTTON_WIDTH	= 80;
const int BUTTON_HEIGHT = 80;
const int BUTTON_WIDTH_BIG	= 104;

const CPoint BTN_LOCATION(0, 0);
const CPoint BTN_LOCATION_1(82, 0);
const CPoint BTN_LOCATION_2(2*82, 0);

#define SUBJECT							_T("Export log from Scanning")




#define ACTIVATION_URL_PATH		_T("/registernew.aspx?")
#define PURCHASE_URL			_T("/purchase.htm")







#define  IMG_FILE_NAME			 _T("/BuyNow.jpg")
#define  IMG_FILE_NAME_2K		 _T("/BuyNow_2kdpi.jpg")
#define  IMG_FILE_NAME_98		 _T("/BuyNow_98dpi.jpg")
#define  MAIN_UI_IMG_FILE_NAME  _T("/MainUI-small.gif")

const int  QUARANTINE_CLICK_COUNT	=	-1;
const int TIMER_SCAN_STATUS					= 100;
const int TIMER_MANAGE_INFO_DLG				= 101;
const int TIMER_SCAN_FINISHED_HANDLER		= 102;
const int TIMER_SPL_SCAN_FINISHED_HANDLER	= 103;
const int TIMER_ROOTKIT_SCAN_FINISHED_HANDLER		= 104;
const int TIMER_KEYLOGGER_SCAN_FINISHED_HANDLER		= 105;
const int TIMER_EP_SIGNATURE_SCAN_FINISHED_HANDLER	= 106;
const int TIMER_ADVANCED_SCAN_FINISHED_HANDLER		= 107;
const int TIMER_PAUSE_HANDLER						= 108;
const int TIMER_SHOW_SLIDING_CHILD					= 109;

#define REG_KP_NOMORERESTARTS			_T("__NoMoreRestarts")
#define REG_KP_KEEPALIVECOUNTER			_T("__KeepAliveCounter")
#define REG_KP_RESTARTCOUNTER			_T("__RestartCounter")
#define REG_KP_SDMAINSERVICESTATUS		_T("__SDMainServiceStatus")
#define REG_KP_KEEPALIVEINTERVAL		_T("__KeepAliveInterval")

#define REG_WD_SHUTDOWN					_T("WDShutdown")

#define REG_EXCEP_ERROR_REPORT			_T("SendErrorReport")
#define REG_SHOWFWUI                    _T("ShowFWUI")
const int APPLY_FOR_ALL_YES = 10;
const int APPLY_FOR_ALL_NO = 11;
