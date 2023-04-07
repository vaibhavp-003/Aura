#pragma once

#define NEGATIVE_JUMP(X) (X & 0x80000000)

typedef struct	_tagINSTRUCTION_SET
{
	DWORD	dwInstLen ;
	char	szOpcode[MAX_PATH] ;
	char	szPnuemonics[MAX_PATH] ;
}Instruction_Set_Struct;

const int MAX_INSTRUCTIONS				= 0x500;
const int MAX_VALID_SECTIONS			= 70;

const int REPAIR_FAILED					= 0;
const int REPAIR_SUCCESS				= 1;
const int VIRUS_NOT_FOUND				= 0;
const int VIRUS_FILE_REPAIR				= 1;
const int VIRUS_FILE_DELETE				= 2;

const int SECTION_NAME_OFFSET			= 0x00;
const int SECTION_VIRTUAL_SIZE			= 0x08;
const int SECTION_SIZE_OF_RAW_DATA		= 0x10;
const int SECTION_NO_OF_RELOCATIONS		= 0x20;
const int SECTION_NO_OF_LINE_NUMBERS	= 0x22;									

// Virus cleaning status constants
const DWORD	REAPIR_STATUS_FAILURE	= 0x60;
const DWORD	REAPIR_STATUS_SUCCESS	= 0x70;
const DWORD	REAPIR_STATUS_CORRUPT	= 0x80;
const DWORD	REAPIR_STATUS_TIMEOUT	= 0x90;

// Virus scanning actions constants
const DWORD	SCAN_ACTION_CLEAN		= 0x0000;
const DWORD	SCAN_ACTION_REPAIR		= 0x0001;
const DWORD	SCAN_ACTION_DELETE		= 0x0002;
const DWORD	SCAN_ACTION_TIMEOUT		= 0x0003;

const WORD MAX_SCAN_TIME = 1000	* 60	* 1; // 1 Minute

#pragma pack(1)
typedef struct _tag_REV_ID_BREAK_UP
{
	BYTE byIndex;
	BYTE byRevNo;
}REV_ID_TEST;
#pragma pack()

typedef struct _tag_REV_ID_TYPE
{
	union
	{
		REV_ID_TEST ID;
		WORD wRevID;
	}u;
}REV_ID_TYPE;

/*
const REV_ID_TYPE GR0_REV_ID = {0x0, 0};
const REV_ID_TYPE GR1_REV_ID = {0x1, 0x14};		// increased for patch 2.30 	 	 				
const REV_ID_TYPE GR2_REV_ID = {0x2, 5};		
const REV_ID_TYPE GR3_REV_ID = {0x3, 5};		
const REV_ID_TYPE GR4_REV_ID = {0x4, 0x10};		// increased for patch 2.30  	 	 		
const REV_ID_TYPE GR5_REV_ID = {0x5, 0x11};		// increased for patch 2.30 	 	 						 	 		 	 	
const REV_ID_TYPE GR6_REV_ID = {0x6, 1};
const REV_ID_TYPE GR7_REV_ID = {0x7, 0x17};		// increased for patch 2.30 				 	 	
const REV_ID_TYPE GR8_REV_ID = {0x8, 8};		 
const REV_ID_TYPE GR9_REV_ID = {0x9, 7};  		 
const REV_ID_TYPE GRA_REV_ID = {0xA, 3};	 	 
const REV_ID_TYPE GRB_REV_ID = {0xB, 0x11};		 	 	
const REV_ID_TYPE GRC_REV_ID = {0xC, 6}; 	 	
const REV_ID_TYPE GRD_REV_ID = {0xD, 6};				
const REV_ID_TYPE GRE_REV_ID = {0xE, 0x15}; 						 	 		 	 	
const REV_ID_TYPE GRF_REV_ID = {0xF, 1};
*/
//Tushar Kadam ==> Changes done by Tushar to Handle Local DB For Poly Viruses
const REV_ID_TYPE GR0_REV_ID = {0x0, 0x0}; //Default
const REV_ID_TYPE GR1_REV_ID = {0x1, 0x6}; //Rarely changing viruses //Changed in Virus Patch Version : 1.0.2.94
const REV_ID_TYPE GR2_REV_ID = {0x2, 0x2}; //Changed in Virus Patch Version : 1.0.2.79
const REV_ID_TYPE GR3_REV_ID = {0x3, 0x1};		
const REV_ID_TYPE GR4_REV_ID = {0x4, 0xF}; //Changed in Virus Patch Version : 1.0.3.09	
const REV_ID_TYPE GR5_REV_ID = {0x5, 0x7}; //Changed in Virus Patch Version : 1.0.2.90	
const REV_ID_TYPE GR6_REV_ID = {0x6, 0x1};
const REV_ID_TYPE GR7_REV_ID = {0x7, 0x4}; //Changed in Virus Patch Version : 1.0.2.84	
const REV_ID_TYPE GR8_REV_ID = {0x8, 0x3}; //Changed in Virus Patch Version : 1.0.2.84		 
const REV_ID_TYPE GR9_REV_ID = {0x9, 0x3};  //Changed in Virus Patch Version : 1.0.2.88		 
const REV_ID_TYPE GRA_REV_ID = {0xA, 0x1};	 	 
const REV_ID_TYPE GRB_REV_ID = {0xB, 0x3};	//Changed in Virus Patch Version : 1.0.2.72	 	 	
const REV_ID_TYPE GRC_REV_ID = {0xC, 0x1}; 	 	
const REV_ID_TYPE GRD_REV_ID = {0xD, 0x1};				
const REV_ID_TYPE GRE_REV_ID = {0xE, 0xF}; //Changed in Virus Patch Version : 1.0.2.90					 	 		 	 	
const REV_ID_TYPE GRF_REV_ID = {0xF, 0x0}; //Not Used

/*===================================================================================================
VERSION HISTORY
24 Jun 2016 : 1.0.2.68 : GRE_REV_ID : 2 : Added New Viruses in Semipoly Trojan By Santosh
05 Oct 2016 : 1.0.2.69 : GRE_REV_ID : 3 : Added New Viruses in Semipoly Trojan By Santosh
						 GR4_REV_ID : 2 : Added New Viruses in Semipoly Virus By Santosh
01 Dec 2016 : 1.0.2.70 : GRE_REV_ID : 4 : Added New Viruses in Semipoly Trojan By  + Alisha
						 GRB_REV_ID : 2 : Added New Viruses in Sality By Santosh + Alisha
						 GR4_REV_ID : 3 : Added New Viruses in Semipoly Virus By Santosh + Alisha
04 Jan 2017 : 1.0.2.72 : GRE_REV_ID : 5 : Added New Viruses in Semipoly Trojan By Santosh
						 GRB_REV_ID : 3 : Added New Viruses in Sality By Santosh + Alisha
						 GR7_REV_ID : 2 : Added New Viruses in Trojan By Alisha
						 GR5_REV_ID : 2 : Added New Viruses in Non Repairable Trojan By Alisha
09 Feb 2017 : 1.0.2.73 : GRE_REV_ID : 6 : Added New Viruses in Semipoly Trojan By Santosh +Tushar
						 GR4_REV_ID : 4 : Added New Viruses in Semipoly Virus By Santosh 
29 Mar 2017 : 1.0.2.74 : GR9_REV_ID : 2 : Added New Heuristic By Tushar(Add new class CPolyHeuristics)
						 GR7_REV_ID : 3 : Trojan
						 GRE_REV_ID : 7 : Semipoly Trojan
						 GR4_REV_ID : 4 : Semipoly Virus
						 GR5_REV_ID : 3 : Non Repairable Trojan
29 Mar 2017 : 1.0.2.76 : GR4_REV_ID : 6 : Changes in Virus.Pioneer.CZ
15 May 2017 : 1.0.2.77 : GR4_REV_ID : 7 : Changes for RansomCry by Alisha
26 May 2017 : 1.0.2.78 : GR4_REV_ID : 8 : Semipoly Virus
						 GR5_REV_ID : 4 : Non-Repairable Virus
						 GRE_REV_ID : 8 : Semipoly Trojan
27 Jul 2017 : 1.0.2.79 : GRE_REV_ID : 9 : Semipoly Trojan
						 GR4_REV_ID : 9 : Semipoly Virus, Trojan_Ransom
						 GR5_REV_ID : 5 : Non-Repairable Virus
						 GR8_REV_ID : 2 : Expiro
						 GR2_REV_ID : 2 : Rainsong
23 Jan 2018 : 1.0.2.84 : GR1_REV_ID : 2 : 
						 GR4_REV_ID : A : 
						 GR5_REV_ID : 6 : 
						 GR7_REV_ID : 4 : 
						 GR8_REV_ID : 3 : 
						 GRE_REV_ID : A : 
08 Feb 2018 : 1.0.2.85 : GR1_REV_ID : 3 : 
						 GR4_REV_ID : B : 
						 GRE_REV_ID : B : 
28 Feb 2018 : 1.0.2.86 : GRE_REV_ID : C : 
04 Apr 2018 : 1.0.2.87 : GRE_REV_ID : D : Semipoly Trojan
						 GR4_REV_ID : C : Semipoly Virus
						 GR1_REV_ID : 4 : Poly Base
26 Apr 2018 : 1.0.2.88 : GR9_REV_ID : 3 : Nimnul Virus
						 GRE_REV_ID : E : Semipoly Trojan + Crab Ransomware
13 Jun 2018 : 1.0.2.90 : GR1_REV_ID : 5 : 
						 GR4_REV_ID : D : 
						 GR5_REV_ID : 7 : 
						 GRE_REV_ID : F : 
26 Jul 2018 : 1.0.2.94   GR1_REV_ID : 6 : Semipoly Virus
18 Feb 2019 : 1.0.3.09 : GR4_REV_ID : E : Semi poly Virus By Sneha Kurade (CPolyTrojanAgentRC4)
22 Sep 2021 : 1.0.3.41 : GR4_REV_ID : F : Semi poly Virus By JayPrakash (CPolyVirusShodiA)
===================================================================================================*/
// Rarely changing viruses
const WORD AFGAN_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD ALCAUL_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD ALMA_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD AOC_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD BLUWIN_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD CALM_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD CENSOR_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD CHAMP_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD CRUNK_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD DEADCODE_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD DELIKON_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD DETNAT_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD DEVIR_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD DOSER_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD DUDRA_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD DUNDUN_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD EVOL_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD HEZHI_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD INVICTUS_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD JUNKCOMP_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD KANBAN_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD KENSTON_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD KILLFILE_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD KORU_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD LAMT_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD LAZYMIN_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD LEVI_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD MERINOS_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD MINIT_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD MOGUL_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD PAIRABLE_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD OPORTO_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD PARTRIOT_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD PAYBACK_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD POLIP_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD SATIR_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD SFCER_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD SWADUK_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD TDSS_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD THORIN_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD VB_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD ZAPROM_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD ZMORPH_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD ZPERM_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD FOSFORO_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD SMASH_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD JOLLA_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD FONO_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD SPIKER_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD DION_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD POLYK_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD DIEHARD_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD HATRED_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD VULCAS_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD ZERO_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD LUNA_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD ZPERMORPH_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD GODOG_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD XTAIL_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD INDUC_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD FIASKO_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD RUBASHKA_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD AGENTCE_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD HPS_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD XORER_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD IMPLINKER_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD KARACHUN_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD CHOP_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD BYTESV_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD DUGERT_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD EAK_REV_ID			= GR1_REV_ID.u.wRevID;
const WORD POSON4367_REV_ID     = GR1_REV_ID.u.wRevID;
const WORD MEGINA_REV_ID	    = GR1_REV_ID.u.wRevID;
const WORD NATHAN_REV_ID	    = GR1_REV_ID.u.wRevID;
const WORD MAMIANUNEIF_REV_ID	= GR1_REV_ID.u.wRevID;
const WORD LMIRWJ_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD AGENTFT_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD POLYGODOGA_REV_ID	= GR1_REV_ID.u.wRevID;
const WORD POLYVBGN_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD POLYYAKA_REV_ID		= GR1_REV_ID.u.wRevID;
const WORD POLYBITMINER_REV_ID	= GR1_REV_ID.u.wRevID;
const WORD POLYBLOOREDE_REV_ID	= GR1_REV_ID.u.wRevID;
const WORD POLAUTORUNVX_REV_ID	= GR1_REV_ID.u.wRevID;
const WORD POLYZUSY22271_REV_ID	= GR1_REV_ID.u.wRevID;
const WORD POLYBANKERBANBRA_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYZBOTWTEN_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYDOWNLOADERH_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYSWISYNFOHA_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYDELFX_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYGENKD30602080_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYSWISYNBNER_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYAGENTES_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYVBHN_REV_ID = GR1_REV_ID.u.wRevID;
const WORD POLYSGENERICKDZ_REV_ID = GR1_REV_ID.u.wRevID;


// Patched call viruses
const WORD CRAZYPRIER_REV_ID	= GR2_REV_ID.u.wRevID;
const WORD HIV_REV_ID			= GR2_REV_ID.u.wRevID;
const WORD SUPERTHREAT_REV_ID	= GR2_REV_ID.u.wRevID;
const WORD BASKET_REV_ID		= GR2_REV_ID.u.wRevID;
const WORD GREMO_REV_ID			= GR2_REV_ID.u.wRevID;
const WORD BABYLONIA_REV_ID		= GR2_REV_ID.u.wRevID;
const WORD BOLZANO_REV_ID		= GR2_REV_ID.u.wRevID;
const WORD ETAP_REV_ID			= GR2_REV_ID.u.wRevID;
const WORD RAINSONG_REV_ID		= GR2_REV_ID.u.wRevID;

// Emulator viruses
const WORD PADDI_REV_ID			= GR3_REV_ID.u.wRevID;
const WORD TVIDO_REV_ID			= GR3_REV_ID.u.wRevID;
const WORD DRILLER_REV_ID		= GR3_REV_ID.u.wRevID;
const WORD ANDRAS_REV_ID		= GR3_REV_ID.u.wRevID;
const WORD ARIS_REV_ID			= GR3_REV_ID.u.wRevID;
const WORD KRIZ_REV_ID			= GR3_REV_ID.u.wRevID;
const WORD HALEN_REV_ID			= GR3_REV_ID.u.wRevID;
const WORD MODRIN_REV_ID		= GR3_REV_ID.u.wRevID;
const WORD VAMPIRO_REV_ID		= GR3_REV_ID.u.wRevID;

//Semipoly viruses
const WORD DEEMO_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD LAMER_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD MKAR_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD TYHOS_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD IPAMOR_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD SPIT_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD NESHTA_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD PIONEER_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD INITX_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD WIDE_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD GYPET_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD MARBURG_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD INTA_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD BLUBACK_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD UNDERTAKER_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD MIMIX_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD PADANIA_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD HIGHWAYB_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD FUJACK_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD CAW_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD GINRA_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD DZAN_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD ASSILL_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD DOWNLOADERTOLSTYA_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD ALIMIK_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD NUMROCK_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD MIAM_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD YOUNGA_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD SEMISOFT_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD GLORIA_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD VBITL_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD GAMETHIEFLMIROA_REV_ID = GR4_REV_ID.u.wRevID;
const WORD POLYKURGAN_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD TABECI_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD DROPPERDAPATOAZUE_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD KUTO_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD JETHRO_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD SPINEX_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD MEMORIAL_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD VIKING_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD LAMEREL_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD RANSOM_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD PATCHEDQR_REV_ID     = GR4_REV_ID.u.wRevID;
//const WORD FEARSO_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD PATCHEDQW_REV_ID     = GR4_REV_ID.u.wRevID;
const WORD TENGA_REV_ID			= GR4_REV_ID.u.wRevID;
const WORD RECONYC_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD MEWSPY_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD POLYINF_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD POLYAGENT_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD POLYDETROIE_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYINFECTORGEN_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYILAMERFG_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYIHOROPED_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYIHOROPEI_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYIZUSY256811_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYBITMINERMADAM_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYHEURGEN_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYAGENTRC4_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYQWIFFA_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYKESPY_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYXORALA_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYZEZAL_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYSHOHDI_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD POLYIPAMORC_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD VIKINGEO_REV_ID		= GR4_REV_ID.u.wRevID;
const WORD POLYSHODIA_REV_ID	= GR4_REV_ID.u.wRevID;
const WORD TROJNPATCHEDRW_REV_ID = GR4_REV_ID.u.wRevID;

// Non repairable viruses
const WORD NONREPAIRABLE_REV_ID = GR5_REV_ID.u.wRevID;
const WORD PACKERS_REV_ID		= GR6_REV_ID.u.wRevID;
const WORD TROJANS_REV_ID		= GR7_REV_ID.u.wRevID;
const WORD SEMIPOLYTROJANS_REV_ID = GRE_REV_ID.u.wRevID;

// Less changing viruses
const WORD ELKERN_REV_ID		= GR8_REV_ID.u.wRevID;
const WORD EXPIRO_REV_ID		= GR8_REV_ID.u.wRevID;
const WORD CHITON_REV_ID		= GR8_REV_ID.u.wRevID;
const WORD MABEZAT_REV_ID		= GR9_REV_ID.u.wRevID;
const WORD NIMNUL_REV_ID		= GR9_REV_ID.u.wRevID;
const WORD PARITE_REV_ID		= GR9_REV_ID.u.wRevID;
const WORD SILCER_REV_ID		= GR9_REV_ID.u.wRevID;
const WORD EXPIRO64_REV_ID		= GR9_REV_ID.u.wRevID;
const WORD POLYTROJANS64_REV_ID	= GR9_REV_ID.u.wRevID;
const WORD HEURISTIC_REV_ID		= GR9_REV_ID.u.wRevID;
const WORD POLYFUNLOVE_REV_ID   = GR9_REV_ID.u.wRevID;

// Frequently changing viruses
const WORD CTX_REV_ID			= GRA_REV_ID.u.wRevID;
const WORD ALMAN_REV_ID			= GRA_REV_ID.u.wRevID;
const WORD SALITY_REV_ID		= GRB_REV_ID.u.wRevID;
const WORD TROJANPATCHED_REV_ID	= GRB_REV_ID.u.wRevID;
const WORD VIRUT_REV_ID			= GRC_REV_ID.u.wRevID;
const WORD XPAJ_REV_ID			= GRD_REV_ID.u.wRevID;
const WORD XPAJA_REV_ID			= GRC_REV_ID.u.wRevID;
const WORD FLYSTDIO_REV_ID		= GRA_REV_ID.u.wRevID;

