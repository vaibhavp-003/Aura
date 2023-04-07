/*======================================================================================
FILE             : Constants.h
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
NOTES		     : Declaring Global Constants
VERSION HISTORY  :
======================================================================================*/
#pragma once
#include <afxtempl.h>

#define MAX_KEY_NAME			255
#define MAX_BUFFER				1024
#define MAX_VALUE_NAME			16383
#define MAX_FILE_PATH			MAX_PATH 
#define MAX_EVENTLOG_BUFFER     524287
#define EN						0       
#define JP						1       
#define	CH						2       	
#define GE						3       	
#define SP						4       

#define EVALUATION_PERIOD		_T("30")

#define SECTION_NAME			_T("Strings")                     

#define PROXYSETTINGS_INI	    _T("\\Proxysettings.ini");

 
#define APP_FOLDER_KEY			_T("AppFolder")
#define VOUCHER_NUMBER			_T("VoucherNo")
#define REGISTRATION_NUMBER		_T("RegistrationNo")
#define PURCHASEURL				_T("PurchaseURL")
#define VENDORNAME				_T("VendorName")

#define OS_VERSION_REG			_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
#define SYSTEM_INFO_REG			_T("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0")
#define AUTH_KEY				_T("AuthenticationRequired")
#define SMTP_SERVER_NAME_KEY		_T("SMTPServer")
#define USER_NAME_KEY				_T("UserName")
#define SMTP_PORT_NO				_T("SMTPPortNo")

#define  RUN_REG_PATH			_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") 
#define  RUNSVC_REG_PATH		_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices")
#define  KEYBORD_REG_PATH	  _T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E96B-E325-11CE-BFC1-08002BE10318}")

#ifdef WIN64
	#define  RUN_REG_PATH_X86			_T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run") 
	#define  RUNSVC_REG_PATH_X86		_T("SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices")
#endif

#define W95  _T("Windows 95" )
#define W98  _T("Windows 98" )
#define WME  _T("Windows ME" )
#define WNT4  _T("Windows NT 4.0" )
#define W2K _T("Windows 2000" )
#define WXP  _T("Windows XP" )
#define WNE  _T("Windows .Net" )
#define HED  _T(" Home Edition" )
#define PED  _T(" Professional Edition" )
#define DCS  _T(" DataCenter Server") 
#define ADS  _T(" Advanced Server" )
#define ENS  _T(" Enterprise Server" )
#define WES  _T(" Web Server" )
#define SER  _T(" Server")
#define WXP64  _T("Windows XP 64 bit")
#define WVISTA  _T("Windows Vista")
#define WWIN7  _T("Windows 7")
#define WWIN8  _T("Windows 8")
#define WWIN10  _T("Windows 10")
#define X64  _T(" 64 bit")

#define CONST_WINDOWS_DIR				 _T("%windir%")
#define CONST_SYSTEM_DRIVE			 _T("%systemdrive%")
#define CONST_SYSTEM_ROOT				 _T("%systemroot%")
#define CONST_PROGRAM_FILES_DIR		 _T("%programfiles%")
#define CONST_PROGRAM_FILES_COMMON_DIR _T("%commonprogramfiles%")
#define CONST_PROFILE_DIR				 _T("%userprofile%")
#define CONST_RESOURCE_DIR			 _T("%resourcedir%")
#define CONST_USER_APPDATA_DIR		 _T("%userappdata%")
#define CONST_LOCAL_APPDATA_DIR		 _T("%localappdata%")
#define CONST_WEB_DIR					 _T("%webdir%")
#define CONST_TEMP_DIR				 _T("%temp%")
#define CONST_PROGRAM_FILES_X86_DIR	 _T("%programfiles(x86)%")
#define CONST_SYSTEM_WOW64_DIR         _T("%syswow64%")
#define CONST_PROGRAM_FILES_COMMON_X86  _T("%commonprogramfiles(x86)%")
#define CONST_PROGRAM_W6432			  _T("%programw6432%")
#define CONST_COMMON_W6432			  _T("%commonprogramw6432%")
#define OSVER_PATH_WIN98				 _T("Software\\Microsoft\\Windows\\CurrentVersion")
#define CONST_PROFILE_DIR_2			 _T("%profile%")
#define CONST_LOCAL_APPDATA_DIR_2		 _T("%local_appdata%")
#define CONST_ALL_USER_PROFILE		_T("%allusersprofile%")


#define DDS_DLIL_HARDDRIVES 1     
#define DDS_DLIL_CDROMS     2     
#define DDS_DLIL_REMOVABLES 4         
#define DDS_DLIL_NETDRIVES  8      
#define DDS_DLIL_RAMDRIVES  16    

#define DDS_DLIL_ALL_REMOVABLE ( DDS_DLIL_CDROMS | DDS_DLIL_REMOVABLES )

#define DDS_DLIL_ALL_LOCAL_DRIVES ( DDS_DLIL_HARDDRIVES | DDS_DLIL_CDROMS | \
                                    DDS_DLIL_REMOVABLES | DDS_DLIL_RAMDRIVES )

#define DDS_DLIL_ALL_DRIVES_NO_CDROM ( DDS_DLIL_HARDDRIVES |  \
                              DDS_DLIL_REMOVABLES | DDS_DLIL_NETDRIVES | \
                              DDS_DLIL_RAMDRIVES )

#define DDS_DLIL_ALL_DRIVES ( DDS_DLIL_HARDDRIVES | DDS_DLIL_CDROMS | \
                              DDS_DLIL_REMOVABLES | DDS_DLIL_NETDRIVES | \
                              DDS_DLIL_RAMDRIVES )

#define  PROFILELIST_PATH  _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
#define  PROFILELIST_PATH_98  _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProfileList")

#define DPI2KREG_KEY	_T("system\\CurrentControlSet\\Hardware Profiles\\Current\\Software\\Fonts")
#define DPI98REG_KEY	_T("Display\\Settings")
#define  WINLOGON_REG_KEY		 _T("software\\microsoft\\windows nt\\currentversion\\winlogon")    
#define  NOTIFY_MAIN_KEY		 _T("software\\microsoft\\windows nt\\currentversion\\winlogon\\notify")    
#define  SSODL_PATH			 _T("software\\microsoft\\windows\\currentversion\\shellserviceobjectdelayload")    
#define  REG_NOTIFY_ENTRY		 _T("software\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\")
#define  SVCHOST_MAIN_KEY		 _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost")
#define  BOOT_EXECUTE_REG_KEY	 _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager")    

#define  WINDOWS_INSTALLER_2_PATH  _T("SOFTWARE\\CLASSES\\CLSID\\{000C101D-0000-0000-C000-000000000046}\\DllVersion")
#define REG_SHELL_FOLDER	_T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders")
#define HIVE_LIST			_T("SYSTEM\\CurrentControlSet\\Control\\hivelist")
#define BACK_SLASH			_T("\\")
#define  SOFTWARE				 _T("Software")
#define  BLANKSTRING			 _T("")
#define  INPROCSERVER32		 _T("InprocServer32")
#define	  OPEN				_T("open")   
#define  MICROSOFT_SANS_SERIFF_FONT  _T("Microsoft Sans Serif")

#define DLLEXPORT __declspec(dllexport)
#define DLLIMPORT __declspec(dllimport)

#define SYSTEM32			_T("System32")
#define DOCUMENT_SETTINGS	_T("Documents and Settings")
#define USER				_T("USER")
#define LOGFOLDER				_T("Log")
#define SETTINGFOLDER			_T("Setting")
#define IS_SUBSCRIPTION_EXPIRED		 -1
#define IS_REGISTERED_COPY			 -1
#define IS_EVALUATION_EXPIRED		 0
#define IS_RENEW_SUBSCRIPTION		 15
#define SUBCRIPTION_PERIOD			_T("365")


#define SMTP_ATTACHMENT					_T("Export.zip")
#define SMTP_HOST						_T("smtp.mailgun.org")
#define SMTP_ADDRESS					_T("")
#define SMTP_TO							_T("")
#define SMTP_AUTHENTICATION				_T("1")
#define SMTP_AUTH_USER					_T("")
#define SMTP_AUTH_PWD					_T("")
#define NAME							_T("Export Log")
#define DEFAULT_SUBJECT					_T("Export Log")  
#define EXPORT_INI						_T("Export.ini")
#define EXPORT_FILES					_T("Export")
#define FILE_COUNT						_T("FileCount")
#define SMTP_DLL						_T("smtpdll.dll")
#define SEND_REPORT_EXE					_T("sendreport.exe")
#define PRODUCT_DETAILS					_T("Productdetails")
#define PRODUCT_NAME					_T("ProductName")
#define REG_INFO_FILE					_T("RegInfo.txt")


#define TITLE_COLOR						RGB(255 , 255 , 255)
#define BACKGROUND						RGB( 159 , 182 , 250 )	
#define WHITE							RGB( 255 , 255 , 255 )
#define BLUEBACKGROUND					RGB(85, 127, 237)
#define BANNER_TEXT_COLOR				RGB(140, 8, 3)
#define BLACK							RGB( 0, 0, 0)

#define REGSVR32_EXE_NAME				_T("regsvr32.exe")

#define EXE_EXTENTION					_T(".exe")
#define DLL_EXTENTION					_T(".dll")
#define LANGUAGE						_T("Language")  
#define SETTING_FOLDER					_T("setting\\")
#define CURRENT_SETTINGS_INI			_T("CurrentSettings.ini")             
#define ANTI_SPAM_SETTING_INI			_T("AntiSpamSetting.ini")
#define DBFULLPATHPHRASE				_T("Phrase.DB")
#define DBFULLPATHSENDER				_T("Sender.DB")
#define DBFULLPATHMYMAILADDRESS			_T("MyEmailId.DB")
#define DBFULLPATHURLS					_T("PhishingDomain.DB")
#define CURRENT_LANGUAGE				_T("CurrentLanguage")
#define FWDATA_FOLDER					_T("FWData\\")

#define SCAN_LOG_FILE					_T("Log\\ScanLog.txt")

#define SETTING_VAL_INI		_T("Settings")
#define COLOR_VAL_INI		_T("colorcode")

enum INTERNET_OPTIMIZER_SETTINGS
{
	IO_TCP_WINDOW_SIZE,
	IO_DEFAULT_TTL,
	IO_BLACK_HOLE_DETECT,
	IO_SACK_OPTS,
	IO_MAX_DUP_ACKS,
	IO_HTTP_PATCH,
	IO_DNS_ERROR_CACHING,
	IO_HOST_RESOLUTION,
	IO_MTU_SIZE,
	IO_INDEX_DAT
};

const int TOTAL_SCAN_OPTION				= 22;
const int MAX_NO_OF_SCANNER				= TOTAL_SCAN_OPTION;

typedef struct
{
	int		m_iWormTypeID[MAX_NO_OF_SCANNER];
	LPVOID	*treeList;
	LPVOID	*statusList;
}MAX_PC_OPTIMIZATION, *LPMAX_PC_OPTIMIZATION;

enum RC_SCAN_OPTION
{
	ENUM_SO_STARTUP,
	ENUM_SO_STARTMENU,
	ENUM_SO_SHAREDDLL,
	ENUM_SO_FONT,
	ENUM_SO_APPINFO,
	ENUM_SO_SND_APPEVNT,
	ENUM_SO_CU_USER_INFO,
	ENUM_SO_FILE_EXT,
	ENUM_SO_SHARED_FOLDER,
	ENUM_SO_HELP_FILE,
	ENUM_SO_MRU,
	ENUM_SO_EMPTY_REG_KEYS,
	ENUM_SO_COM,
	ENUM_SO_DEEPSCAN,
	ENUM_SO_SHORTCUTS,
	ENUM_SO_COOKIE,
	ENUM_SO_ADDRESSURL,
	ENUM_SO_RECYCLE_BIN,
	ENUM_SO_CLIPBOARD,
	ENUM_SO_WINAPPLOG,
	ENUM_SO_TEMP_FILES,
	ENUM_SO_INTERNET_TEMP_FILES 
};

const int		SO_STARTUP_THREAT_LEVEL			= 0;
const CString	SO_STARTUP_IGNOREDB				= _T("IgnoreData\\RC0.DB");
const CString	SO_STARTUP_DISPLAY				= _T("Startup Program");
const int		STATUS_START_STARTUP_SCAN		= ENUM_SO_STARTUP;
const int		STATUS_FINISH_STARTUP_SCAN		= TOTAL_SCAN_OPTION;

const int		SO_STARTMENUITEM_THREAT_LEVEL	= 2;
const CString	SO_STARTMENUITEM_IGNOREDB		= _T("IgnoreData\\RC1.DB");
const CString	SO_STARTMENUITEM_DISPLAY		= _T("Start Menu Item");
const int		STATUS_START_STARTMENU_SCAN		= ENUM_SO_STARTMENU;
const int		STATUS_FINISH_STARTMENU_SCAN	= TOTAL_SCAN_OPTION + STATUS_START_STARTMENU_SCAN;

const int		SO_SHAREDDLL_THREAT_LEVEL		= 0;
const CString	SO_SHAREDDLL_IGNOREDB			= _T("IgnoreData\\RC2.DB");
const CString	SO_SHAREDDLL_DISPLAY			= _T("Shared DLL");
const int		STATUS_START_SHAREDDLL_SCAN		= ENUM_SO_SHAREDDLL;
const int		STATUS_FINISH_SHAREDDLL_SCAN	= TOTAL_SCAN_OPTION + STATUS_START_SHAREDDLL_SCAN;

const int		SO_FONT_THREAT_LEVEL			= 0;
const CString	SO_FONT_IGNOREDB				= _T("IgnoreData\\RC3.DB");
const CString	SO_FONT_DISPLAY					= _T("Font");
const int		STATUS_START_FONT_SCAN			= ENUM_SO_FONT;
const int		STATUS_FINISH_FONT_SCAN			= TOTAL_SCAN_OPTION + STATUS_START_FONT_SCAN;

const int		SO_APPLICATIONINFO_THREAT_LEVEL	= 2;
const CString	SO_APPLICATIONINFO_IGNOREDB		= _T("IgnoreData\\RC4.DB");
const CString	SO_APPLICATIONINFO_DISPLAY		= _T("Application Info");
const int		STATUS_START_APPINFO_SCAN		= ENUM_SO_APPINFO;
const int		STATUS_FINISH_APPINFO_SCAN		= TOTAL_SCAN_OPTION + STATUS_START_APPINFO_SCAN;

const int		SO_SOUNDAPPEVENT_THREAT_LEVEL	= 2;
const CString	SO_SOUNDAPPEVENT_IGNOREDB		= _T("IgnoreData\\RC5.DB");
const CString	SO_SOUNDAPPEVENT_DISPLAY		= _T("Sound & App Events");
const int		STATUS_START_SOUNDAPP_SCAN		= ENUM_SO_SND_APPEVNT;
const int		STATUS_FINISH_SOUNDAPP_SCAN		= TOTAL_SCAN_OPTION + STATUS_START_SOUNDAPP_SCAN;

const int		SO_CURRENTUSER_THREAT_LEVEL		= 2;
const CString	SO_CURRENTUSER_IGNOREDB			= _T("IgnoreData\\RC6.DB");
const CString	SO_CURRENTUSER_DISPLAY			= _T("Logged On User");
const int		STATUS_START_CURRUSER_SCAN		= ENUM_SO_CU_USER_INFO;
const int		STATUS_FINISH_CURRUSER_SCAN		= TOTAL_SCAN_OPTION + STATUS_START_CURRUSER_SCAN;

const int		SO_FILE_EXTENSION_THREAT_LEVEL	= 0;
const CString	SO_FILE_EXTENSION_IGNOREDB		= _T("IgnoreData\\RC7.DB");
const CString	SO_FILE_EXTENSION_DISPLAY		= _T("File Extension");
const int		STATUS_START_FILE_EXT_SCAN		= ENUM_SO_FILE_EXT;
const int		STATUS_FINISH_FILE_EXT_SCAN		= TOTAL_SCAN_OPTION + STATUS_START_FILE_EXT_SCAN;

const int		SO_SHAREDFOLDER_THREAT_LEVEL	= 0;
const CString	SO_SHAREDFOLDER_IGNOREDB		= _T("IgnoreData\\RC8.DB");
const CString	SO_SHAREDFOLDER_DISPLAY			= _T("Shared Folder");
const int		STATUS_START_SHARED_FLDR_SCAN	= ENUM_SO_SHARED_FOLDER;
const int		STATUS_FINISH_SHARED_FLDR_SCAN	= TOTAL_SCAN_OPTION + STATUS_START_SHARED_FLDR_SCAN;

const int		SO_HELPFILE_THREAT_LEVEL		= 0;
const CString	SO_HELPFILE_IGNOREDB			= _T("IgnoreData\\RC9.DB");
const CString	SO_HELPFILE_DISPLAY				= _T("Help File");
const int		STATUS_START_HELPFILE_SCAN		= ENUM_SO_HELP_FILE;
const int		STATUS_FINISH_HELPFILE_SCAN		= TOTAL_SCAN_OPTION + STATUS_START_HELPFILE_SCAN;

const int		SO_MRU_THREAT_LEVEL				= 2;
const CString	SO_MRU_IGNOREDB					= _T("IgnoreData\\RC10.DB");
const CString	SO_MRU_DISPLAY					= _T("MRU Entries");
const int		STATUS_START_MRU_SCAN			= ENUM_SO_MRU;
const int		STATUS_FINISH_MRU_SCAN			= TOTAL_SCAN_OPTION + STATUS_START_MRU_SCAN;

const int		SO_EMPTY_REG_KEY_THREAT_LEVEL		= 2;
const CString	SO_EMPTY_REG_KEY_IGNOREDB			= _T("IgnoreData\\RC11.DB");
const CString	SO_EMPTY_REG_KEY_DISPLAY			= _T("Empty Registry Key");
const int		STATUS_START_EMPTY_REG_KEY_SCAN		= ENUM_SO_EMPTY_REG_KEYS;
const int		STATUS_FINISH_EMPTY_REG_KEY_SCAN	= TOTAL_SCAN_OPTION + STATUS_START_EMPTY_REG_KEY_SCAN;

const int		SO_COM_THREAT_LEVEL				= 0;
const CString	SO_COM_IGNOREDB					= _T("IgnoreData\\RC12.DB");
const CString	SO_COM_DISPLAY					= _T("COM/ActiveX");
const int		STATUS_START_COM_SCAN			= ENUM_SO_COM;
const int		STATUS_FINISH_COM_SCAN			= TOTAL_SCAN_OPTION + STATUS_START_COM_SCAN;

const int		SO_DEEPSCAN_THREAT_LEVEL		= 0;
const CString	SO_DEEPSCAN_IGNOREDB			= _T("IgnoreData\\RC13.DB");
const CString	SO_DEEPSCAN_DISPLAY				= _T("Deep Scan");
const int		STATUS_START_DEEP_SCAN			= ENUM_SO_DEEPSCAN;
const int		STATUS_FINISH_DEEP_SCAN			= TOTAL_SCAN_OPTION + STATUS_START_DEEP_SCAN;

const int		SO_SHORTCUT_THREAT_LEVEL		= 2;
const CString	SO_SHORTCUT_IGNOREDB			= _T("IgnoreData\\RC14.DB");
const CString	SO_SHORTCUT_DISPLAY				= _T("Windows/MSDOS Shortcut");
const int		STATUS_START_SHORTCUT_SCAN		= ENUM_SO_SHORTCUTS;
const int		STATUS_FINISH_SHORTCUT_SCAN		= TOTAL_SCAN_OPTION + STATUS_START_SHORTCUT_SCAN;

const int		SO_TEMP_FILE_THREAT_LEVEL		= 2;
const CString	SO_TEMP_FILE_IGNOREDB			= _T("IgnoreData\\RC15.DB");
const CString	SO_TEMP_FILE_DISPLAY			= _T("Temporary File");
const int		STATUS_START_TEMP_FILE_SCAN		= ENUM_SO_TEMP_FILES;
const int		STATUS_FINISH_TEMP_FILE_SCAN	= TOTAL_SCAN_OPTION + STATUS_START_TEMP_FILE_SCAN;

const int		SO_INET_TEMP_FILE_THREAT_LEVEL	= 2;
const CString	SO_INET_TEMP_FILE_IGNOREDB		= _T("IgnoreData\\RC16.DB");
const CString	SO_INET_TEMP_FILE_DISPLAY		= _T("Temporary Internet File");
const int		STATUS_START_INET_TEMP_FILE_SCAN= ENUM_SO_INTERNET_TEMP_FILES;
const int		STATUS_FINISH_INET_TEMP_FILE_SCAN= TOTAL_SCAN_OPTION + STATUS_START_INET_TEMP_FILE_SCAN;

const int		SO_COOKIE_THREAT_LEVEL	= 2;
const CString	SO_COOKIE_IGNOREDB	= _T("IgnoreData\\RC17.DB");
const CString	SO_COOKIE_DISPLAY		= _T("Cookie");
const int		STATUS_START_COOKIE_SCAN = ENUM_SO_COOKIE;
const int		STATUS_FINISH_COOKIE_SCAN= TOTAL_SCAN_OPTION + STATUS_START_COOKIE_SCAN;

const int		SO_ADDRESSURL_THREAT_LEVEL	= 2;
const CString	SO_ADDRESSURL_IGNOREDB	= _T("IgnoreData\\RC18.DB");
const CString	SO_ADDRESSURL_DISPLAY		= _T("URL History");
const int		STATUS_START_ADDRESSURL_SCAN = ENUM_SO_ADDRESSURL;
const int		STATUS_FINISH_ADDRESSURL_SCAN= TOTAL_SCAN_OPTION + STATUS_START_ADDRESSURL_SCAN;
#define			REGKEY_IE_ADDRESSBAR_URLS			_T("Software\\Microsoft\\Internet Explorer\\TypedURLs")

const int		SO_RECYCLE_BIN_THREAT_LEVEL	= 2;
const CString	SO_RECYCLE_BIN_DISPLAY		= _T("Recycle Bin File");
const int		STATUS_START_RECYCLE_BIN_SCAN= ENUM_SO_RECYCLE_BIN;
const int		STATUS_FINISH_RECYCLE_BIN_SCAN= TOTAL_SCAN_OPTION + STATUS_START_RECYCLE_BIN_SCAN;


const int		SO_CLIPBOARD_THREAT_LEVEL	= 2;
const CString	SO_CLIPBOARD_DISPLAY		= _T("Clipboard");
const int		STATUS_START_CLIPBOARD_SCAN = ENUM_SO_CLIPBOARD;
const int		STATUS_FINISH_CLIPBOARD_SCAN= TOTAL_SCAN_OPTION + STATUS_START_CLIPBOARD_SCAN;

const int		SO_WINAPPLOG_THREAT_LEVEL	= 2;
const CString	SO_WINAPPLOG_DISPLAY		= _T("Windows Application Log");
const int		STATUS_START_WINAPPLOG_SCAN = ENUM_SO_WINAPPLOG;
const int		STATUS_FINISH_WINAPPLOG_SCAN= TOTAL_SCAN_OPTION + STATUS_START_WINAPPLOG_SCAN;

const int COLUMN_SECTION		= 0;
const int COLUMN_OPTIONTYPE		= 1;
const int COLUMN_THREAT			= 2;
const int COLUMN_VALUENAME		= 3;
const int COLUMN_INVALIDVALUE	= 4;
const int COLUMN_TYPE_CT		= 5;	 
const int COLUMN_IS_CHILD		= 6;	 
const int COLUMN_IS_ADMINENTRY	= 7;	 
const int COLUMN_THREAT_ICON    = 8;	     
const int MIN_COLUMN_WIDTH		= 50;

const int COLUMN_RECOVER_SECTION	 = 0;	 
const int COLUMN_RECOVER_TYPE		 = 1;	 
const int COLUMN_RECOVER_KEY		 = 2;	 
const int COLUMN_RECOVER_VALUE		 = 3;	
const int COLUMN_RECOVER_DATA		 = 4;	
const int COLUMN_RECOVER_FILENAME	 = 5;	    
const int COLUMN_RECOVER_REGDATATYPE = 6;        

#define	COUNT_COLOR						RGB(0,0,0)
#define ID_PROGRESS_TIMER				9999
#define ID_TREE_ONSIZE_TIMER			1000
#define NEW_RECOVER_DB_FILE_NAME	_T("NewRecoverDB.db")

enum RESTART_DELETE_TYPE
{
	RD_INVALID = 0,
	RD_FILE_DELETE,
	RD_FILE_BACKUP,
	RD_PROCESS,
	RD_FOLDER,
	RD_KEY,
	RD_VALUE,
	RD_DATA,
	RD_FILE_RENAME,
	RD_FILE_REPLACE,
	RD_NATIVE_BACKUP
};

#define RENAME_FILE_SEPARATOR		_T(">\\??\\")
#define MAXMANAGER_INI				_T("setting\\AuManager.ini")

#define LOGGING_LEVEL	L"LoggingLevel"
const int LOG_ERROR		= 0;	                
const int LOG_WARNING	= 1;	                
const int LOG_DEBUG		= 2;	                                     

#define AUTO_UPDATE_DELAY L"AUTOUPDATEDELAY"
#define MEMORY_SCAN_DELAY L"MemoryScanDelay"

typedef enum __TagProductType
{
	ENUM_ULTRAAV = 0,
	ENUM_FIREWALL,
	INVALID_ID
}ENUM_PRODUCT_TYPE;

#define FIREWALL_REG_KEY		_T("SOFTWARE\\AuAppFirewall")
#define ULTRAAV_REG_KEY			_T("SOFTWARE\\UltraAV")

const LPCTSTR FW_FIREWALL_UNINSTALL		= _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UnInstall\\AuAppFirewall");

#define TRACKER_KEY							_T("\\Track")

#define TRACKER_DELAY_START					_T("DelayedStart")
#define TRACKER_QUERY						_T("Querry")
#define TRACKER_UNISTALL_URL				_T("UnistallUrl")
#define TRACKER_SUPPORT_URL					_T("SupportURL")
#define TRACKER_HOMEPAGE_URL				_T("HomePageURL")
#define TRACKER_BUYNOW_URL					_T("BuyNowURL")
#define TRACKER_INSTALL_DATE				_T("InstallDate")
#define TRACKER_WELCOME_PAGE				_T("WelcomePage")
#define TRACKER_MACHINE_GUID				_T("MachineGuid")
#define TRACKER_OS							_T("Os")
#define TRACKER_LAST_SCAN_CHECKED			_T("LastScanChecked")
#define TRACKER_QUERY_DATE					_T("QuerryDate")
#define TRACKER_SETUP_NAME					_T("SetupName")
#define TRACKER_USER						_T("User")
#define TRACKER_LAST_BI_SENT				_T("LastBISent")

#define TRACKER_QUICKSCAN_COUNT				_T("BtnQuickScanCick")
#define TRACKER_FULLSCAN_COUNT				_T("BtnFullScanCick")
#define TRACKER_CUSTOMSCAN_COUNT			_T("BtnCustomScanCick")
#define TRACKER_ITEMS_CLEANED_COUNT			_T("ItemsCleaned")
#define TRACKER_ITEMS_QUARANTINED_COUNT		_T("ItemsQuarantined")
#define TRACKER_ITEMS_TO_CLEAN_COUNT		_T("ItemsToClean")
#define TRACKER_ITEMS_TO_QUARANTINE_COUNT	_T("ItemsToQuarantine")
#define TRACKER_LICENSE_DATE				_T("LicenseDate")
#define TRACKER_LIVEUPDATE_LAUNCHED			_T("LiveUpdateLaunched")
#define TRACKER_BUY_NOW_CLICK				_T("BuyNowClicked")
#define TRACKER_REGISTER_NOW_CLICK			_T("RegisterNowClicked")
#define TRACKER_RENEW_NOW_CLICK				_T("RenewNowClicked")
#define TRACKER_MAINUI_LAUNCHED				_T("MainUILaunched")
#define TRACKER_CLEAN_CLICKED				_T("CleanButtonClicked")

#define UNTRACTED		_T("100") 
#define WIN_2000		_T("101")
#define WINXP_32BIT		_T("102")
#define WINXP_64BIT		_T("103") 
#define WIN_VISTA_32BIT	_T("104") 
#define WIN_VISTA_64BIT	_T("105") 
#define WIN7_32BIT		_T("106")
#define WIN7_64BIT		_T("107")
#define WIN8_32BIT		_T("108")
#define WIN8_64BIT		_T("109") 




typedef enum _RegistryType
{
	ENUM_KEY,
	ENUM_VALUE,
	ENUM_DATA
}REG_TYPE;


#define ADWCLEANER_GOOGLE_PREF_FILE_PATH     _T("\\Google\\Chrome\\User Data\\Default\\Web Data")
#define ADWCLEANER_MOZILLA_PREF_FILE_PATH    _T("\\Mozilla\\Firefox\\Profiles")
#define ADWCLEANER_REG_HKLM_PATH             _T("HKLM\\SOFTWARE")
#define ADWCLEANER_REG_HKCU_PATH             _T("HKCU\\SOFTWARE")
#define ADWCLEANER_PROG_FILE_DIR             _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
#define ADWCLEANER_BROWSER_DB_FILE_PATH      _T("adwConfigFile.DB")
#define ADWCLEANER_FOLDER_DB_FILE_PATH       _T("adwFolderFiles.DB")
#define ADWCLEANER_REG_VALUE_DB_FILE_PATH    _T("adwRegValue.DB")
#define ADWCLEANER_REG_KEY_DB_FILE_PATH      _T("adwRegKey.DB")

const int ACTIVATION_TIME_PERIOD = 48;
typedef struct ActivationTimer
{	
private:
	time_t	LocalActTime;
	time_t	ServerActTime;
	time_t	CurrentLocalTime;			
	time_t	TimeElapsed;	
public:
	ActivationTimer():LocalActTime(0),ServerActTime(0),CurrentLocalTime(0),TimeElapsed(ACTIVATION_TIME_PERIOD)
	{		
	}
	void setActivationTime(const CTime& actTime,const CTime& servTime)
	{
		LocalActTime	=   CurrentLocalTime	=	actTime.GetTime();
		ServerActTime	=	servTime.GetTime();		
	}		
	int GetHoursLeft(const CTime& localTime)
	{	
		int iTempTime = 0;
		int iHours			= ACTIVATION_TIME_PERIOD;
		time_t ctTmSpan		= localTime.GetTime() - CurrentLocalTime;
		double dHours		=  (double)ctTmSpan/(3600.00);      

		if((int)dHours < 0 || (int)dHours > 48)
		{
			return 0;
		}
		
		if(TimeElapsed <= 0)
			iHours = 0;
		else
		iHours = (int)(TimeElapsed - (int)dHours);

		return	 iHours;


	}
	void SetCurrSrvTime(const CTime& LocalTime,const CTime& SrvTime)
	{
		int iTempTime = 0;
		CurrentLocalTime = LocalTime.GetTime();
		double dHours = (SrvTime.GetTime() - ServerActTime)/(3600.00);
		
		iTempTime = (int)dHours;
		TimeElapsed = ACTIVATION_TIME_PERIOD - ((int)dHours);
	}

} ACTIVTIMER, *LPACTIVERTIMER;