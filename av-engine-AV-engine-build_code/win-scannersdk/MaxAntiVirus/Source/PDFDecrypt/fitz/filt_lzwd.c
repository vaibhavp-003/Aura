#include "fitz.h"
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 

/* TODO: error checking */

enum
{
	MIN_BITS = 9,
	MAX_BITS = 12,
	NUM_CODES = (1 << MAX_BITS),
	LZW_CLEAR = 256,
	LZW_EOD = 257,
	LZW_FIRST = 258,
	MAX_LENGTH = 4097
};

typedef struct lzw_code_s lzw_code;

struct lzw_code_s
{
	int prev;			/* prev code (in string) */
	unsigned short length;		/* string len, including this token */
	unsigned char value;		/* data value */
	unsigned char first_char;	/* first token of string */
};

typedef struct fz_lzwd_s fz_lzwd;

struct fz_lzwd_s
{
	fz_stream *chain;
	int eod;

	int early_change;

	int code_bits;			/* num bits/code */
	int code;			/* current code */
	int old_code;			/* previously recognized code */
	int next_code;			/* next free entry */

	lzw_code table[NUM_CODES];

	unsigned char bp[MAX_LENGTH];
	unsigned char *rp, *wp;
};

static int
read_lzwd(fz_stream *stm, unsigned char *buf, int len)
{
	fz_lzwd *lzw = stm->state;
	lzw_code *table = lzw->table;
	unsigned char *p = buf;
	unsigned char *ep = buf + len;
	unsigned char *s;
	int codelen;

	int code_bits = lzw->code_bits;
	int code = lzw->code;
	int old_code = lzw->old_code;
	int next_code = lzw->next_code;

	while (lzw->rp < lzw->wp && p < ep)
		*p++ = *lzw->rp++;

	while (p < ep)
	{
		if (lzw->eod)
			return 0;

		code = fz_read_bits(lzw->chain, code_bits);

		if (fz_is_eof_bits(lzw->chain))
		{
			lzw->eod = 1;
			break;
		}

		if (code == LZW_EOD)
		{
			lzw->eod = 1;
			break;
		}

		if (code == LZW_CLEAR)
		{
			code_bits = MIN_BITS;
			next_code = LZW_FIRST;
			old_code = -1;
			continue;
		}

		/* if stream starts without a clear code, old_code is undefined... */
		if (old_code == -1)
		{
			old_code = code;
		}
		else if(next_code >= _countof(lzw->table))
		{
			return -1; // data error, saves array overwrite
		}
		else
		{
			/* add new entry to the code table */
			table[next_code].prev = old_code;
			table[next_code].first_char = table[old_code].first_char;
			table[next_code].length = table[old_code].length + 1;
			if (code < next_code)
				table[next_code].value = table[code].first_char;
			else if (code == next_code)
				table[next_code].value = table[next_code].first_char;
			else
				fz_warn("out of range code encountered in lzw decode");

			next_code ++;

			if (next_code > (1 << code_bits) - lzw->early_change - 1)
			{
				code_bits ++;
				if (code_bits > MAX_BITS)
					code_bits = MAX_BITS;	/* FIXME */
			}

			old_code = code;
		}

		/* code maps to a string, copy to output (in reverse...) */
		if (code > 255)
		{
			codelen = table[code].length;
			lzw->rp = lzw->bp;
			lzw->wp = lzw->bp + codelen;

			assert(codelen < MAX_LENGTH);

			s = lzw->wp;
			do {
				*(--s) = table[code].value;
				code = table[code].prev;
			} while (code >= 0 && s > lzw->bp);
		}

		/* ... or just a single character */
		else
		{
			lzw->bp[0] = code;
			lzw->rp = lzw->bp;
			lzw->wp = lzw->bp + 1;
		}

		/* copy to output */
		while (lzw->rp < lzw->wp && p < ep)
			*p++ = *lzw->rp++;
	}

	lzw->code_bits = code_bits;
	lzw->code = code;
	lzw->old_code = old_code;
	lzw->next_code = next_code;

	return p - buf;
}

static void
close_lzwd(fz_stream *stm)
{
	fz_lzwd *lzw = stm->state;
	fz_close(lzw->chain);
	fz_free(lzw);
}

fz_stream *
fz_open_lzwd(fz_stream *chain, fz_obj *params)
{
	fz_lzwd *lzw;
	fz_obj *obj;
	int i;

	lzw = fz_malloc(sizeof(fz_lzwd));
	lzw->chain = chain;
	lzw->eod = 0;
	lzw->early_change = 1;

	obj = fz_dict_gets(params, "EarlyChange");
	if (obj)
		lzw->early_change = !!fz_to_int(obj);

	for (i = 0; i < 256; i++)
	{
		lzw->table[i].value = i;
		lzw->table[i].first_char = i;
		lzw->table[i].length = 1;
		lzw->table[i].prev = -1;
	}

	for (i = 256; i < NUM_CODES; i++)
	{
		lzw->table[i].value = 0;
		lzw->table[i].first_char = 0;
		lzw->table[i].length = 0;
		lzw->table[i].prev = -1;
	}

	lzw->code_bits = MIN_BITS;
	lzw->code = -1;
	lzw->next_code = LZW_FIRST;
	lzw->old_code = -1;
	lzw->rp = lzw->bp;
	lzw->wp = lzw->bp;

	return fz_new_stream(lzw, read_lzwd, close_lzwd);
}

#define BITS 12 // 비트수를 정한다 12, 13 
#define HASHING_SHIFT BITS-8 
#define MAX_VALUE (1 << BITS)-1 
#define MAX_CODE MAX_VALUE-1 

#if (BITS == 14)
#define TABLE_SIZE 18041 // string table의 수는 2**bits보다 큼
#endif 
#if (BITS == 13)
#define TABLE_SIZE 9029 
#endif 
#if (BITS <= 12)
#define TABLE_SIZE 4097 
#endif 

// 전역 변수/상수 선언부
int * code_value; // code value 배열
unsigned int * prefix_code; // 이 배열은 prefix codes를 가리킨다
char * append_character; // 이 배열은 appended chars를 가리킨다
char decode_stack[5120]; // 이 배열은 decoded string을 가리킨다 

//** 이것은 string table로부터 간단하게 decode하는 루틴이다. 
//** 버퍼는 expansion 프로그램과 역으로 출력가능하다. 
char * decode_string(char * buffer, unsigned int code) 
{ 
	int i=0; 

	while(code > 255) 
	{ 
		*buffer++ = append_character[code]; 
		code=prefix_code[code]; 
		if(i++ >= 4094) return NULL;
	} 
	*buffer = code; 
	return (char *)buffer; 
} 

//** 다음의 두 routines는 variable length code의 출력에 쓰인다. 
unsigned int input_code(FILE * input) 
{
	static int input_bit_count = 0; 
	static unsigned long input_bit_buffer = 0L; 
	unsigned long return_value;

	while(input_bit_count <= 24) 
	{ 
		input_bit_buffer |= (unsigned long)getc(input) << (24-input_bit_count);
		input_bit_count += 8; 
	} 
	return_value = input_bit_buffer >> (32-BITS); 
	input_bit_buffer <<= BITS;
	input_bit_count -= BITS;
	return return_value;
} 

//** 이것은 expansion routine이다. 이것은 LZW형식의 파일을 요구한고 이것을 output화일로 확장한다. 
void expand(FILE * input, FILE * output) 
{
	unsigned int next_code = 256; // 이것은 다음 정의될 code 
	int counter = 0; // 카운터는 조정자로 쓰인다.
	unsigned int old_code;
	int character;
	unsigned int new_code; 
	char * string;

	old_code = input_code(input); /* 처음 code를 읽는다.*/ 
	character = old_code; 
	putc(old_code, output); /* output 파일에 처음 code를 보낸다.*/ 

	//** 이것은 main expansion loop이다. LZW화일로부터 데이터의 마지막 code까지 본 다음 읽어 들인다. 
	while((new_code = input_code(input)) != (MAX_VALUE)) 
	{ 
		if(++counter == 1000) /* 1000 characters 마다 *를 찍는다. */ 
		{ 
			counter = 0; 
		} 

		//** 마찬가지로 우리는 새로운 코드를 decode해야한다. 
		if(new_code >= next_code) 
		{ 
			*decode_stack = character; 
			string = (char *)decode_string(decode_stack+1, old_code); 
		}
		else string = (char *)decode_string(decode_stack,new_code); 

		if(string == 0) break;
		//** 이제 우리는 역으로 decoded string을 출력한다. 
		character = *string; 
		while(string >= decode_stack) 
			putc(*string--, output); 

		//** 마지막으로, 가능하다면 새로운 코드를 string table에 더한다. 
		if(next_code <= MAX_CODE) 
		{ 
			prefix_code[next_code] = old_code; 
			append_character[next_code] = character; 
			next_code++;
		} 
		old_code = new_code; 
	} 
} 

int fz_my_LZW_Decrypt(char *dst, long *dstLen, char *src, long srcLen)
{
	char szTempPath[512];
	char szInputFile[512]; 
	char szOutputFile[512];
	FILE * lzw_file;
	FILE * out_file;

	//** 세 개의 버퍼는 압축을 위하여 쓰인다. 
	code_value = (int *)malloc(TABLE_SIZE*sizeof(unsigned int)); 
	prefix_code = (unsigned int *)malloc(TABLE_SIZE*sizeof(unsigned int));
	append_character = (char *)malloc(TABLE_SIZE*sizeof(char)); 

	memset(code_value, 0x0, TABLE_SIZE*sizeof(unsigned int));
	memset(prefix_code, 0x0, TABLE_SIZE*sizeof(unsigned int));
	memset(append_character, 0x0, TABLE_SIZE*sizeof(char));

	_getcwd(szTempPath, 512);
	if(szTempPath[strlen(szTempPath)-1] == '\\') szTempPath[strlen(szTempPath)-1] = 0;

	strcpy(szInputFile, szTempPath);
	strcat(szInputFile, "\\tempEncrypt.lzw");
	
	strcpy(szOutputFile, szTempPath);
	strcat(szOutputFile, "\\tempDecrypt.txt");

	lzw_file = fopen(szInputFile, "w+b");
	if(!lzw_file) return 0;
	fwrite(src, 1, srcLen, lzw_file);
	fclose(lzw_file);

	lzw_file = fopen(szInputFile, "rb");
	out_file = fopen(szOutputFile, "w+b");
	if(!lzw_file || !out_file) return 0;

	//** 파일을 확장한다.(복원)
	expand(lzw_file, out_file);

	fclose(lzw_file);
	fclose(out_file);

	out_file = fopen(szInputFile, "rb");
	if(!out_file) return 0;
	fseek(out_file, 0, SEEK_END);
	*dstLen = ftell(out_file);
	fseek(out_file, 0, SEEK_SET);
	fread(dst, 1, *dstLen, out_file);
	fclose(out_file);

	free(code_value); 
	free(prefix_code); 
	free(append_character); 

	return 1;
}