/*======================================================================================
FILE             : Packers.h
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
	CREATION DATE    : 12/19/2009 4:56:49 PM
	NOTES		     : Header file for Decoding LZMA
	VERSION HISTORY  : 
	======================================================================================*/
#pragma once

#define CProb UInt16
#define LZMA_RESULT_OK 0
#define LZMA_RESULT_DATA_ERROR 1
#define LZMA_BASE_SIZE 1846
#define LZMA_LIT_SIZE 768
#define LZMA_PROPERTIES_SIZE 5
#define LzmaGetNumProbs(lzmaProps) (LZMA_BASE_SIZE + (LZMA_LIT_SIZE << ((lzmaProps)->lc + (lzmaProps)->lp)))
#define kLzmaInBufferSize 64   /* don't change it. it must be larger than kRequiredInBufferSize */
#define kLzmaNeedInitId (-2)
#define LzmaDecoderInit(vs) { (vs)->RemainLen = kLzmaNeedInitId; (vs)->BufferSize = 0; }
#define LZMA_STREAM_END 2
#define LZMA_RESULT_OK 0
#define LZMA_RESULT_DATA_ERROR 1


typedef struct _CLzmaProperties
{
  int lc;
  int lp;
  int pb;
  UInt32 DictionarySize;
}CLzmaProperties;

typedef struct _CLzmaDecoderState
{
  CLzmaProperties Properties;
  CProb *Probs;
  unsigned char *Dictionary;

  unsigned char Buffer[kLzmaInBufferSize];
  int BufferSize;

  UInt32 Range;
  UInt32 Code;
  UInt32 DictionaryPos;
  UInt32 GlobalPos;
  UInt32 DistanceLimit;
  UInt32 Reps[4];
  int State;
  int RemainLen;  /* -2: decoder needs internal initialization
                     -1: stream was finished, 
                      0: ok
                    > 0: need to write RemainLen bytes as match Reps[0],
                  */
  unsigned char TempDictionary[4];  /* it's required when DictionarySize = 0 */
} CLzmaDecoderState;


int LzmaDecode(CLzmaDecoderState *vs,
    const unsigned char *inStream, SizeT inSize,  SizeT *inSizeProcessed,
    unsigned char *outStream, SizeT outSize, SizeT *outSizeProcessed,
    int finishDecoding);

typedef struct MAX_LZMA_tag MAX_LZMA;

struct stream_state {
	uint32_t avail_in;
	unsigned char *next_in;
	uint32_t avail_out;
	unsigned char *next_out;
};

struct lzmastate {
	char *p0;
	uint32_t p1, p2;
};

int LzmaInit(MAX_LZMA **, uint64_t);
void LzmaShutdown(MAX_LZMA **);
int MaxLzmaDecode(MAX_LZMA **, struct stream_state*);
int LzmaInitUPX(MAX_LZMA **, uint32_t);

uint32_t Lzma_UPack_ESI_00(struct lzmastate *, char *, char *, uint32_t);
uint32_t Lzma_UPack_ESI_50(struct lzmastate *, uint32_t, uint32_t, char **, char *, uint32_t *, char *, uint32_t);
uint32_t Lzma_UPack_ESI_54(struct lzmastate *, uint32_t, uint32_t *, char **, uint32_t *, char *, uint32_t);
int LzmaDecodeProperties(CLzmaProperties *propsRes, const unsigned char *propsData, int size);
