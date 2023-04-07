
/*======================================================================================
FILE             : Lzma_Iface.c
ABSTRACT         :
DOCUMENTS	     : 
AUTHOR		     : Siddharam Pujari
COMPANY		     : Aura 
COPYRIGHT(NOTICE): 
				  (C) Aura
				  Created as an unpublished copyright work.  All rights reserved.
				  This document and the information it contains is confidential and
				  proprietary to Aura.  Hence, it may not be 
				  used, copied, reproduced, transmitted, or stored in any form or by any 
				  means, electronic, recording, photocopying, mechanical or otherwise, 
				  without the prior written permission of Aura.	
				  
	CREATION DATE    : 12/19/2009 4:13:54 PM
	NOTES		     : Defines the class behaviors for the application
	VERSION HISTORY  : 
	======================================================================================*/
#include "Packers.h"

#define Z_PREFIX

struct MAX_LZMA_tag 
{
	CLzmaDecoderState state;
	unsigned char *next_in;
	SizeT avail_in;
	unsigned char *next_out;
	SizeT avail_out;
	int initted;
	uint64_t usize;
};

/*--------------------------------------------------------------------------------------
Function       : LzmaInit
In Parameters  : MAX_LZMA **Lp, uint64_t size_override, 
Out Parameters : int 
Description    : Initialize the LZMA
Author & Date  :
--------------------------------------------------------------------------------------*/
int LzmaInit(MAX_LZMA **Lp, uint64_t size_override)
{
	MAX_LZMA *L = *Lp;

	if(!L) 
	{
		*Lp = L = MaxCalloc(sizeof(*L), 1);
		if(!L)
		{
			return -114;
		}
	}

	L->initted = 0;
	if(size_override) L->usize=size_override;

	if (!L->next_in || L->avail_in < LZMA_PROPERTIES_SIZE + 8) return LZMA_RESULT_OK;
	if (LzmaDecodeProperties(&L->state.Properties, L->next_in, LZMA_PROPERTIES_SIZE) != LZMA_RESULT_OK)
		return LZMA_RESULT_DATA_ERROR;

	L->next_in += LZMA_PROPERTIES_SIZE;
	L->avail_in -= LZMA_PROPERTIES_SIZE;

	if (!L->usize)
	{
		L->usize=(uint64_t)ReadInt32(L->next_in) + ((uint64_t)ReadInt32(L->next_in+4)<<32);
		L->next_in += 8;
		L->avail_in -= 8;
	}

	if (!(L->state.Probs = (CProb *)MaxMalloc(LzmaGetNumProbs(&L->state.Properties) * sizeof(CProb))))
		return LZMA_RESULT_DATA_ERROR;

	if (!(L->state.Dictionary = (unsigned char *)MaxMalloc(L->state.Properties.DictionarySize))) 
	{
		free(L->state.Probs);
		return LZMA_RESULT_DATA_ERROR;
	}

	L->initted = 1;

	LzmaDecoderInit(&L->state);
	return LZMA_RESULT_OK;
}

/*--------------------------------------------------------------------------------------
Function       : LzmaShutdown
In Parameters  : MAX_LZMA **Lp, 
Out Parameters : void 
Description    : Shuts Down LZMA
Author & Date  :
--------------------------------------------------------------------------------------*/
void LzmaShutdown(MAX_LZMA **Lp)
{
	MAX_LZMA *L;

	if(!Lp) return;
	L = *Lp;
	if(L->initted) 
	{
		if(L->state.Probs) free(L->state.Probs);
		if(L->state.Dictionary) free(L->state.Dictionary);
	}
	free(L);
	*Lp = NULL;
	return;
}

/*--------------------------------------------------------------------------------------
Function       : MaxLzmaDecode
In Parameters  : MAX_LZMA **Lp, struct stream_state* state, 
Out Parameters : int 
Description    : Decode the LZMA
Author & Date  :
--------------------------------------------------------------------------------------*/
int MaxLzmaDecode(MAX_LZMA **Lp, struct stream_state* state)
{
	int res;
	SizeT processed_in, processed_out;
	MAX_LZMA* L = *Lp;

	if(L) {
		L->avail_in = state->avail_in;
		L->next_in = state->next_in;
		L->avail_out = state->avail_out;
		L->next_out = state->next_out;
	}

	if (!L || !L->initted) 
	{
		if(LzmaInit(Lp, 0) != LZMA_RESULT_OK)
			return LZMA_RESULT_DATA_ERROR;
		L = *Lp;
	}


	res = LzmaDecode(&L->state, L->next_in, L->avail_in, &processed_in, L->next_out, L->avail_out, &processed_out, (L->avail_in==0));

	L->next_in += processed_in;
	L->avail_in -= processed_in;
	L->next_out += processed_out;
	L->avail_out -= processed_out;

	state->avail_in = L->avail_in;
	state->next_in = L->next_in;
	state->avail_out = L->avail_out;
	state->next_out = L->next_out;

	return res;
}

/*--------------------------------------------------------------------------------------
Function       : LzmaInitUPX
In Parameters  : MAX_LZMA **Lp, uint32_t dictsz, 
Out Parameters : int 
Description    : Intializes the LZMA for UPX
Author & Date  :
--------------------------------------------------------------------------------------*/
int LzmaInitUPX(MAX_LZMA **Lp, uint32_t dictsz)
{
	MAX_LZMA *L = *Lp;

	if(!L)
	{
		*Lp = L = MaxCalloc(sizeof(*L), 1);
		if(!L)
		{
			return LZMA_RESULT_DATA_ERROR;
		}
	}

	L->state.Properties.pb = 2; 
	L->state.Properties.lp = 0; 
	L->state.Properties.lc = 3; 

	L->state.Properties.DictionarySize = dictsz;

	if (!(L->state.Probs = (CProb *)MaxMalloc(LzmaGetNumProbs(&L->state.Properties) * sizeof(CProb))))
		return LZMA_RESULT_DATA_ERROR;

	if (!(L->state.Dictionary = (unsigned char *)MaxMalloc(L->state.Properties.DictionarySize))) {
		free(L->state.Probs);
		return LZMA_RESULT_DATA_ERROR;
	}

	L->initted = 1;

	LzmaDecoderInit(&L->state);
	return LZMA_RESULT_OK;
}
