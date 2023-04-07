/*======================================================================================
FILE             : Constants.h
ABSTRACT         : Collection of all the stuctures and constant values require for Repaire routine
DOCUMENTS	     : 
AUTHOR		     : Tushar Kadam + Virus Team
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
CREATION DATE    : June 2010
NOTES		     : Collection of all the stuctures and constant values require for Repaire routine
VERSION HISTORY  : 
======================================================================================*/

#define REPAIR_WMA_FILES	_T("FD")
#define REPAIR_TTF_FILES	_T("FC")
#define REPAIR_HELP_FILES	_T("FB")
#define REPAIR_LNK_FILES	_T("FA")
#define REPAIR_IFRAME_TAG	_T("1A")
#define REPAIR_OBJECT_TAG	_T("1B")
#define REPAIR_SCRIPT_TAG	_T("1C")
#define REPAIR_EICAR_TAG	_T("26")
#define REPAIR_PNG_TAG		_T("27")

#define IFRAME_START_TAG	"<IFRAME"
#define IFRAME_END_TAG		"</IFRAME>"
#define OBJECT_START_TAG	"<HTML>\r\n<object"
#define OBJECT_END_TAG		"</object>"
#define SCRIPT_START_TAG	"<script"
#define SCRIPT_END_TAG		"</script>"
#define EICAR_START_TAG		"X5O!P"
#define EICAR_END_TAG		"$H+H*"

const int SCRIPT_BUFF_SIZE  = 0x10000;

const int REPAIR_IFRAME 	= 0x1A;
const int REPAIR_OBJECT 	= 0x1B;
const int REPAIR_SCRIPT 	= 0x1C;
const int REPAIR_EICAR	 	= 0x26;
const int REPAIR_PNG	 	= 0x27;

const int START_TAG_LENGTH		= 15;
const int END_TAG_LENGTH		= 9;
const int OBJECT_REPAIR_OFFSET	= 7;

const int SAVIOR_DECRYPTION			= 8; 
const int ADSON_1703_DECRYPTION		= 0xA;
const int MAGIC_1590_DECRYPTION		= 0xB;
const int AGENT_CX_DECRYPTION		= 0xC;
const int QUDOS_DECRYPTION			= 0xD;
const int ADSON_1559_DECRYPTION		= 0xE;
const int OROCH_DECRYPTION			= 0xF;
const int DECRYPTION_SADON_900		= 0x10;
const int DECRYPTION_BARTEL			= 0x11;
const int DECRYPTION_ARTELAD_2173	= 0x12;
const int DECRYPTION_LAMEWIN		= 0x13;
const int DECRYPTION_KILLIS			= 0x14;
const int DECRYPTION_RAINSONG		= 0x15;
const int DECRYPTION_ALISAR			= 0x16;
const int DECRYPTION_ROSEC			= 0x17;
const int DECRYPTION_TUPAC			= 0x18;
const int DECRYPTION_CABANAS		= 0x19;
const int DECRYPTION_TANK			= 0x1A;
const int DECRYPTION_EVAR			= 0x1B;
const int DECRYPTION_DICTATOR		= 0x1C;
const int DECRYPTION_ADSON_1734		= 0x1D;
const int DECRYPTION_RAMDILE		= 0x1E;
const int DECRYPTION_IH6			= 0x1F;
const int DECRYPTION_YAZ_A			= 0x20;
const int DECRYPTION_ESTATIC		= 0x21;
const int DECRYPTION_GODOG			= 0x22;
const int DECRYPTION_SMALL_2602		= 0x23;
const int DECRYPTION_DELF_DJ		= 0x24;
const int DECRYPTION_POSITON_4668	= 0x25;
const int DECRYPTION_XOR			= 0x26;
const int DECRYPTION_MOCKODER_1120	= 0x27;
const int DECRYPT_PATCHED_MD		= 0x28;
const int DECRYPTION_PARVO			= 0x29;
const int DECRYPTION_PRIEST			= 0x2A;
const int DECRYPTION_WORD_XOR		= 0x2B;
const int DECRYPTION_MATRIX_3597	= 0x2C;
const int DECRYPTION_PIONEER_BG		= 0x2D;
const int DECRYPTION_LAMER_ER		= 0x2E;
const int DECRYPTION_LAMER_EL		= 0x2F;
const int DECRYPTION_NEG			= 0x30;
const int DECRYPTION_KINO			= 0x31;
const int DECRYPTION_ZOMBIE			= 0x32;
const int DECRYPTION_CABRES			= 0x33;
const int DECRYPTION_ILMX			= 0x34;
const int DECRYPTION_FABI			= 0x35;
const int DECRYPTION_CRYTEX1290		= 0x36;
const int DECRYPTION_LAMERHB		= 0x37;

// CopyData Decryptions:
const int DECRYPTION_DORIFEL		= 13;

// Added by Rupali on 1 Mar 2011. Added Virus Velost by Neeraj.
const int VELOST_BUFF_SIZE			= 0x236;
const int VELOST31_AEP				= 0x249;
const int VELOST41_AEP				= 0x244;
// End

// Added by Rupali on 2 Mar 2011. Added special repair for virus Redemption by Adnan.
const int REDEMPTION_BUFF_SIZE		= 0x1FFFF;
// End

const int GET_VALUE						= 1;
const int SPECIAL_REPAIR_IMPORTER_A		= 2;
const int SPECIAL_REPAIR_RENAMED_FILE	= 3;
const int SPECIAL_REPAIR_HLLC_EXT		= 4;
const int SPECIAL_REPAIR_WARRAY			= 5;
const int SPECIAL_REPAIR_APATHY			= 6;
const int SPECIAL_REPAIR_SALITY			= 7;
const int SPECIAL_REPAIR_ALMAN_A		= 8;
const int SPECIAL_REPAIR_VELOST			= 9;
const int SPECIAL_REPAIR_REDEMPTION		= 10;
const int SPECIAL_REPAIR_STREAM			= 11;
const int CHECK_AEP_SECTION				= 12;
const int SPECIAL_REPAIR_TINIT_A		= 13;
const int SPECIAL_REPAIR_RENAMER		= 14;
const int SPECIAL_REPAIR_OTWYCAL_G		= 15;
const int SPECIAL_REPAIR_NEMSI_B		= 16;
const int SPECIAL_REPAIR_ASSILL			= 17;
const int SPECIAL_REPAIR_WINEMMEM		= 18;
const int SPECIAL_REPAIR_SABUREX		= 19;
const int SPECIAL_REPAIR_9X_CIH			= 20;
const int SPECIAL_REPAIR_CHITON_B		= 21;
const int SPECIAL_REPAIR_MUCE_B			= 22;
const int SPECIAL_REPAIR_PADIC			= 23;
const int SPECIAL_REPAIR_EMAR           = 24;
const int SPECIAL_REPAIR_MIAM			= 25;
const int SPECIAL_REPAIR_KIRO			= 26;
const int SPECIAL_REPAIR_KLEZ			= 27;
const int GET_SEC_PRD					= 28;
const int INTERCHANGE_SECTION_HEADERS	= 29;
const int SPECIAL_REPAIR_TRIONC			= 30;
const int SPECIAL_REPAIR_DOCPACK		= 31;
const int SPECIAL_REPAIR_STRING_TO_DECIMAL	=32;
const int SPECIAL_REPAIR_PIONEERBT		=33;
const int SPECIAL_REPAIR_RECYL		=34;
const int SPECIAL_REPAIR_SHIPUP		=35;
const int SPECIAL_REPAIR_RANSOM		=36;
const int SPECIAL_REPAIR_LAMEREL	=37;
const int SPECIAL_REPAIR_PIONEERDLL =38;
const int SPECIAL_REPAIR_MULTI_PREPENDER =39;
const int SPECIAL_REPAIR_LAMER_CQ =40;


const int DECRYPT_BUFF_SIZE				= 1024;

const int NEMSI_BUFF_SIZE				= 0x500;