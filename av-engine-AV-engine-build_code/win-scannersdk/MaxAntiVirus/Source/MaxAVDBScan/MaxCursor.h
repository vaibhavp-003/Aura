/*======================================================================================
FILE				: MaxCursor.h
ABSTRACT			: Scanner for File Type : .CUR Files
DOCUMENTS			: 
AUTHOR				: Tushar Kadam
COMPANY				: Aura 
COPYRIGHT NOTICE	: (C) Aura
					Created as an unpublished copyright work.  All rights reserved.
					This document and the information it contains is confidential and
					proprietary to Aura.  Hence, it may not be 
					used, copied, reproduced, transmitted, or stored in any form or by any 
					means, electronic, recording, photocopying, mechanical or otherwise, 
					without the prior written permission of Aura
CREATION DATE		: 22-Apr-2010
NOTES				: This class module keeps the information of virus names identifiers of signature loaded in memory.
VERSION HISTORY		: 
				Version: 1.0.1.1
				Date:22-Apr-2010
				Description :Check in code changed by Tushar
=====================================================================================*/
#pragma once
#include "pch.h"
#include "MaxPEFile.h"


typedef struct ANI_HEADER_STRUCT
{
	DWORD ChunkId;      /* Subchunk ID (always "anih") */
	DWORD Size;         /* Length of subchunk minus 8 */
	DWORD HeaderSize;   /* Size of the subchunk data in bytes */
	DWORD NumFrames;    /* Number of icon or cursor frames */
	DWORD NumSteps;     /* Number of steps in the animation */
	DWORD Width;        /* Width of frame in pixels */
	DWORD Height;       /* Height of frame in pixels */
	DWORD BitCount;     /* Number of bits in the frame pixels */
	DWORD NumPlanes;    /* Number of color planes in the frame data */
	DWORD DisplayRate;  /* Default frame display rate */
	DWORD Flags;        /* File attributes flags */
} ANI_HEADER;

typedef struct LIST_INFO_STRUCT
{
	DWORD            ListId;     /* "LIST" */
	DWORD            ListSize;   /* Length of LIST chunk minus 8 */
	// BYTE*            Frames;   /* Array of cursor, icon, or bitmap data */
} LIST_INFO;

typedef struct LIST_FRAME_STRUCT
{
	DWORD            ListId;     /* "LIST" */
	DWORD            ListSize;   /* Length of LIST chunk minus 8 */
	DWORD            ListType;   /* "fram" */
	//ICON             Frames[];   /* Array of cursor, icon, or bitmap data */
} LIST_FRAME;

typedef struct ICON_STRUCT
{
	DWORD ChunkId;      /* Subchunk ID (always "icon") */
	DWORD Size;         /* Length of subchunk minus 8 */
	// BYTE  Data[];       /* Icon, cursor, or raw bitmap data */ 
} ICON;


typedef struct RATE_STRUCT
{
	DWORD ChunkId;      /* Subchunk ID (always "rate") */
	DWORD Size;         /* Total length of subchunk in bytes */
	//DWORD Rates[];      /* Array of JIF rate values */
} RATE;

typedef struct SEQUENCE_STRUCT
{
	DWORD ChunkId;      /* Subchunk ID (always "seq ") */
	DWORD Size;         /* Length of subchunk minus 8 */
	// DWORD Indices[];    /* Array of sequence values */
} SEQUENCE;

typedef struct RIFF_ANI_FILE_STRUCT
{
	DWORD                  FileId;     /* File ID (always "RIFF") */
	DWORD                  Size;       /* Length of file minus 8 in bytes */
	DWORD                  FormID;     /* Format ID (always "ACON") */
	//LIST_INFO              ListInfoChunk;    /* File and content information */
	//DISPLAY                DisplaySubchunk;  /* Display object */
	//ANI_HEADER             AniHeader;        /* Header information */
	//RATE                   RateSubchunk;     /* Frame rate data */
	//SEQUENCE               SequenceSubchunk; /* Frame sequence data */
	//LIST_FRAME             ListFrame;        /* LIST Frame chunk */
} RIFF_ANI_FILE;

typedef struct ANI_CHUNK_STRUCT
{
	DWORD ChunkID;
	DWORD ChunkSize;
	DWORD SubChunk;
}ANI_CHUNK;

class CMaxCursor
{	
   	DWORD   m_dwReadOffset;
	DWORD   m_dwReadBuffOffset;

	DWORD	NormalizeBuffer(LPBYTE byBuffer, DWORD cbBuffer);
	bool	CheckExploit(LPBYTE byBuffer, DWORD dwNoOfBytes);

public:

	CMaxCursor();
	~CMaxCursor();

	bool	IsValidICONFile(CMaxPEFile *pMaxPEFile);
	bool	GetICONBuffer(LPBYTE byBuffer, DWORD cbBuffer, DWORD& cbBufSize, int iIndex, CMaxPEFile *pMaxPEFile);		

	bool	IsValidANIFile(CMaxPEFile *pMaxPEFile);
	bool	IsExploitANI(CMaxPEFile *pMaxPEFile);
	bool	GetANIBuffer(LPBYTE byBuffer, DWORD& cbBufSize, CMaxPEFile *pMaxPEFile);
};
