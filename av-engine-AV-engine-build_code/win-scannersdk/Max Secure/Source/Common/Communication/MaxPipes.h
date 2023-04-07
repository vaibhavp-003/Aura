/*======================================================================================
FILE             : MaxPipes.h
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
CREATION DATE    : 5/14/2009.
NOTES		     : Names of all the Pipe servers used in SD for communication
VERSION HISTORY  : 
======================================================================================*/

#pragma once
// UI[Client] and Watch Dog Service[Server] 
static const TCHAR* _NAMED_PIPE_UI_TO_SERVICE			= _T("\\\\.\\pipe\\{60A8B8B0-15C8-4a30-85F9-143FDE8B833F}");

// Watch Dog Service[Client] and Scanner[Server]
static const TCHAR* _NAMED_PIPE_SERVICE_TO_SCANNER		= _T("\\\\.\\pipe\\{F7D29DB0-ACBB-4d20-BC1F-812977F55227}");

// Watch Dog Service[Client] and Registry Scanner[Server]
static const TCHAR* _NAMED_PIPE_SERVICE_TO_REGSCANNER	= _T("\\\\.\\pipe\\{44BF3A34-3B87-4da1-AFC0-115B0F2E51BD}");

// Scanner[Client] to UI[Server]
static const TCHAR* _NAMED_PIPE_SCANNER_TO_UI			= _T("\\\\.\\pipe\\{1977D291-8866-4eeb-83B1-324E14AEF851}");

// Reg Scanner[Client] to UI[Server]
static const TCHAR* _NAMED_PIPE_REGSCANNER_TO_UI		= _T("\\\\.\\pipe\\{84067136-44A9-473c-AD04-359E3788B1F5}");

// Option Tab[Client] to Scanner[Server]
static const TCHAR* _NAMED_PIPE_OPTIONTTAB_TO_SCANNER	= _T("\\\\.\\pipe\\{CB67BF50-4EEA-403b-8D4D-1C4E960A8EE0}");

static const TCHAR* _NAMED_PIPE_UI_TO_RECOVER_SCANNER	= _T("\\\\.\\pipe\\{A85C92F4-FDA8-49c5-B46F-BEBDAEE9B90C}");

// Active Monitor : Tray[Client] to Active Monitor Service[Server]
static const TCHAR* _NAMED_PIPE_TRAY_TO_ACTMON			= _T("\\\\.\\pipe\\{CDD89B3C-9224-4cb2-9FAB-94F196A9E52D}");

// Active Monitor : Active Monitor Service[Client] to Tray[Server]
static const TCHAR* _NAMED_PIPE_ACTMON_TO_TRAY			= _T("\\\\.\\pipe\\{D715ADD1-4D5D-49e5-AE19-74D231B16473}");

// Active Monitor : Active Monitor Service[Client] to ServerTray[Server]
static const TCHAR* _NAMED_PIPE_ACTMON_TO_SERVERTRAY	= _T("\\\\.\\pipe\\{3CF609AF-9645-4b2a-A7CC-79DE66C38E81}");

// FS Monitor: Client to FS Monitor Service[Server]
static const TCHAR* _NAMED_PIPE_UI_TO_FSMONSERVICE		= _T("\\\\.\\pipe\\{1D894697-6FBE-4339-85B1-B6FC6BC30B41}");

// Wsc Monitor: Client to Wsc Monitor Service[Server]
static const TCHAR* _NAMED_PIPE_UI_TO_WSCREGSERVICE		= _T("\\\\.\\pipe\\{E9AC8072-3BC3-4aa8-974B-3F8D7C963854}");

// Firewall: Tray to Firewall Service[Server]
static const TCHAR* _NAMED_PIPE_TRAY_TO_FIREWALLSERVICE		= _T("\\\\.\\pipe\\{76B4E6ED-4754-4486-9220-5E81B691B4BA}");


// AuScanner : UI[Client] to AuScanner[Server] for Actions
static const TCHAR* _NAMED_ACTION_PIPE_UI_TO_SCANNER	= _T("\\\\.\\pipe\\{1B62E344-5393-4e4f-8F48-0DD9BA9CDEBC}");

// Watch Dog Service[Server] all Monitored Apps (Client) 
static const TCHAR* _NAMED_PIPE_WATCHDOG_PROCESSES			= _T("\\\\.\\pipe\\{76DD52B3-D836-4a47-AA83-550F15D65BF7}");

// HeuristicScan AuScanner[Serve] to AuWatchDog[Client]
static const TCHAR* _NAMED_PIPE_HEURISTICSCAN_TO_SCANNER  = _T("\\\\.\\pipe\\{33B3775B-7E2E-421a-B907-E1BD044328C7}");

// Watch Dog Service[SDNotify/WinLogon] to Monitor AuWatchDogService
static const TCHAR* _NAMED_PIPE_SDNOTIFY_WATCHDOG		  = _T("\\\\.\\pipe\\{7CB49BB9-1E7E-4fe1-A9A7-35BB5A311CF5}");

static const TCHAR* _NAMED_PIPE_SERVICE_TO_MAXSCANNER		  = _T("\\\\.\\pipe\\{BC044819-2D72-4627-B2FF-EE7FCDE80F27}");

static const TCHAR* _NAMED_PIPE_PLUGIN_TO_SCANNER		= _T("\\\\.\\pipe\\{342E27F0-1787-44b6-9628-F37E7EFE58FA}");

static const TCHAR* _NAMED_PIPE_SCANNER_TO_PLUGIN		= _T("\\\\.\\pipe\\{513067DA-8BD5-49ee-937A-A56336686BA9}");

//MaxDBCache user(scanner, actmon etc.) to DBServer
static const TCHAR* _NAMED_PIPE_DBCLIENT_TO_DBSERVER		= _T("\\\\.\\pipe\\{44DAC4D7-A83D-4ae9-88F8-D7E625711579}");

//AuUnpacker32 user(scanner, actmon etc.) to AuUnpacker32
static const TCHAR* _NAMED_PIPE_SCANNER_TO_UNPACKER		= _T("\\\\.\\pipe\\{A5E6D167-A2A4-4197-9E89-56A734E76A05}");