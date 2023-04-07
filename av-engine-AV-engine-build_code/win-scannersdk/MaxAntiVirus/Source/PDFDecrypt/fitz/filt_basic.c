#include "fitz.h"

/* Pretend we have a filter that just copies data forever */

fz_stream *
fz_open_copy(fz_stream *chain)
{
	return fz_keep_stream(chain);
}

/* Null filter copies a specified amount of data */

struct null_filter
{
	fz_stream *chain;
	int remain;
};

static int
read_null(fz_stream *stm, unsigned char *buf, int len)
{
	struct null_filter *state = stm->state;
	int amount = MIN(len, state->remain);
	int n = fz_read(state->chain, buf, amount);
	if (n < 0)
		return fz_rethrow(n, "read error in null filter");
	state->remain -= n;
	return n;
}

static void
close_null(fz_stream *stm)
{
	struct null_filter *state = stm->state;
	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_open_null(fz_stream *chain, int len)
{
	struct null_filter *state;

	state = fz_malloc(sizeof(struct null_filter));
	state->chain = chain;
	state->remain = len;

	return fz_new_stream(state, read_null, close_null);
}

/* ASCII Hex Decode */

typedef struct fz_ahxd_s fz_ahxd;

struct fz_ahxd_s
{
	fz_stream *chain;
	int eod;
};

static inline int iswhite(int a)
{
	switch (a) {
	case '\n': case '\r': case '\t': case ' ':
	case '\0': case '\f': case '\b': case 0177:
		return 1;
	}
	return 0;
}

static inline int ishex(int a)
{
	return (a >= 'A' && a <= 'F') ||
		(a >= 'a' && a <= 'f') ||
		(a >= '0' && a <= '9');
}

static inline int unhex(int a)
{
	if (a >= 'A' && a <= 'F') return a - 'A' + 0xA;
	if (a >= 'a' && a <= 'f') return a - 'a' + 0xA;
	if (a >= '0' && a <= '9') return a - '0';
	return 0;
}

static int
read_ahxd(fz_stream *stm, unsigned char *buf, int len)
{
	fz_ahxd *state = stm->state;
	unsigned char *p = buf;
	unsigned char *ep = buf + len;
	int a, b, c, odd;

	odd = 0;

	while (p < ep)
	{
		if (state->eod)
			return p - buf;

		c = fz_read_byte(state->chain);
		if (c < 0)
			return p - buf;

		if (ishex(c))
		{
			if (!odd)
			{
				a = unhex(c);
				odd = 1;
			}
			else
			{
				b = unhex(c);
				*p++ = (a << 4) | b;
				odd = 0;
			}
		}
		else if (c == '>')
		{
			if (odd)
				*p++ = (a << 4);
			state->eod = 1;
		}
		else if (!iswhite(c))
		{
			return fz_throw("bad data in ahxd: '%c'", c);
		}
	}

	return p - buf;
}

static void
close_ahxd(fz_stream *stm)
{
	fz_ahxd *state = stm->state;
	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_open_ahxd(fz_stream *chain)
{
	fz_ahxd *state;

	state = fz_malloc(sizeof(fz_ahxd));
	state->chain = chain;
	state->eod = 0;

	return fz_new_stream(state, read_ahxd, close_ahxd);
}

/* ASCII 85 Decode */

typedef struct fz_a85d_s fz_a85d;

struct fz_a85d_s
{
	fz_stream *chain;
	unsigned char bp[4];
	unsigned char *rp, *wp;
	int eod;
};

static int
read_a85d(fz_stream *stm, unsigned char *buf, int len)
{
	fz_a85d *state = stm->state;
	unsigned char *p = buf;
	unsigned char *ep = buf + len;
	int count = 0;
	int word = 0;
	int c;

	while (state->rp < state->wp && p < ep)
		*p++ = *state->rp++;

	while (p < ep)
	{
		if (state->eod)
			return p - buf;

		c = fz_read_byte(state->chain);
		if (c < 0)
			return p - buf;

		if (c >= '!' && c <= 'u')
		{
			if (count == 4)
			{
				word = word * 85 + (c - '!');

				state->bp[0] = (word >> 24) & 0xff;
				state->bp[1] = (word >> 16) & 0xff;
				state->bp[2] = (word >> 8) & 0xff;
				state->bp[3] = (word) & 0xff;
				state->rp = state->bp;
				state->wp = state->bp + 4;

				word = 0;
				count = 0;
			}
			else
			{
				word = word * 85 + (c - '!');
				count ++;
			}
		}

		else if (c == 'z' && count == 0)
		{
			state->bp[0] = 0;
			state->bp[1] = 0;
			state->bp[2] = 0;
			state->bp[3] = 0;
			state->rp = state->bp;
			state->wp = state->bp + 4;
		}

		else if (c == '~')
		{
			c = fz_read_byte(state->chain);
			if (c != '>')
				fz_warn("bad eod marker in a85d");

			switch (count) {
			case 0:
				break;
			case 1:
				return fz_throw("partial final byte in a85d");
			case 2:
				word = word * (85 * 85 * 85) + 0xffffff;
				state->bp[0] = word >> 24;
				state->rp = state->bp;
				state->wp = state->bp + 1;
				break;
			case 3:
				word = word * (85 * 85) + 0xffff;
				state->bp[0] = word >> 24;
				state->bp[1] = word >> 16;
				state->rp = state->bp;
				state->wp = state->bp + 2;
				break;
			case 4:
				word = word * 85 + 0xff;
				state->bp[0] = word >> 24;
				state->bp[1] = word >> 16;
				state->bp[2] = word >> 8;
				state->rp = state->bp;
				state->wp = state->bp + 3;
				break;
			}
			state->eod = 1;
		}

		else if (!iswhite(c))
		{
			return fz_throw("bad data in a85d: '%c'", c);
		}

		while (state->rp < state->wp && p < ep)
			*p++ = *state->rp++;
	}

	return p - buf;
}

static void
close_a85d(fz_stream *stm)
{
	fz_a85d *state = stm->state;
	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_open_a85d(fz_stream *chain)
{
	fz_a85d *state;

	state = fz_malloc(sizeof(fz_a85d));
	state->chain = chain;
	state->rp = state->bp;
	state->wp = state->bp;
	state->eod = 0;

	return fz_new_stream(state, read_a85d, close_a85d);
}

/* Run Length Decode */

typedef struct fz_rld_s fz_rld;

struct fz_rld_s
{
	fz_stream *chain;
	int run, n, c;
};

static int
read_rld(fz_stream *stm, unsigned char *buf, int len)
{
	fz_rld *state = stm->state;
	unsigned char *p = buf;
	unsigned char *ep = buf + len;

	while (p < ep)
	{
		if (state->run == 128)
			return p - buf;

		if (state->n == 0)
		{
			state->run = fz_read_byte(state->chain);
			if (state->run < 0)
				state->run = 128;
			if (state->run < 128)
				state->n = state->run + 1;
			if (state->run > 128)
			{
				state->n = 257 - state->run;
				state->c = fz_read_byte(state->chain);
				if (state->c < 0)
					return fz_throw("premature end of data in run length decode");
			}
		}

		if (state->run < 128)
		{
			while (p < ep && state->n)
			{
				int c = fz_read_byte(state->chain);
				if (c < 0)
					return fz_throw("premature end of data in run length decode");
				*p++ = c;
				state->n--;
			}
		}

		if (state->run > 128)
		{
			while (p < ep && state->n)
			{
				*p++ = state->c;
				state->n--;
			}
		}
	}

	return p - buf;
}

static void
close_rld(fz_stream *stm)
{
	fz_rld *state = stm->state;
	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_open_rld(fz_stream *chain)
{
	fz_rld *state;

	state = fz_malloc(sizeof(fz_rld));
	state->chain = chain;
	state->run = 0;
	state->n = 0;
	state->c = 0;

	return fz_new_stream(state, read_rld, close_rld);
}

/* RC4 Filter */

typedef struct fz_arc4c_s fz_arc4c;

struct fz_arc4c_s
{
	fz_stream *chain;
	fz_arc4 arc4;
};

static int
read_arc4(fz_stream *stm, unsigned char *buf, int len)
{
	fz_arc4c *state = stm->state;
	int n;

	n = fz_read(state->chain, buf, len);
	if (n < 0)
		return fz_rethrow(n, "read error in arc4 filter");

	fz_arc4_encrypt(&state->arc4, buf, buf, n);

	return n;
}

static void
close_arc4(fz_stream *stm)
{
	fz_arc4c *state = stm->state;
	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_open_arc4(fz_stream *chain, unsigned char *key, unsigned keylen)
{
	fz_arc4c *state;

	state = fz_malloc(sizeof(fz_arc4c));
	state->chain = chain;
	fz_arc4_init(&state->arc4, key, keylen);

	return fz_new_stream(state, read_arc4, close_arc4);
}

/* AES Filter */

typedef struct fz_aesd_s fz_aesd;

struct fz_aesd_s
{
	fz_stream *chain;
	fz_aes aes;
	unsigned char iv[16];
	int ivcount;
	unsigned char bp[16];
	unsigned char *rp, *wp;
};

static int
read_aesd(fz_stream *stm, unsigned char *buf, int len)
{
	fz_aesd *state = stm->state;
	unsigned char *p = buf;
	unsigned char *ep = buf + len;

	while (state->ivcount < 16)
	{
		int c = fz_read_byte(state->chain);
		if (c < 0)
			return fz_throw("premature end in aes filter");
		state->iv[state->ivcount++] = c;
	}

	while (state->rp < state->wp && p < ep)
		*p++ = *state->rp++;

	while (p < ep)
	{
		int n = fz_read(state->chain, state->bp, 16);
		if (n < 0)
			return fz_rethrow(n, "read error in aes filter");
		else if (n == 0)
			return p - buf;
		else if (n < 16)
			return fz_throw("partial block in aes filter");

		aes_crypt_cbc(&state->aes, AES_DECRYPT, 16, state->iv, state->bp, state->bp);
		state->rp = state->bp;
		state->wp = state->bp + 16;

		/* strip padding at end of file */
		if (fz_is_eof(state->chain))
		{
			int pad = state->bp[15];
			if (pad < 1 || pad > 16)
				return fz_throw("aes padding out of range: %d", pad);
			state->wp -= pad;
		}

		while (state->rp < state->wp && p < ep)
			*p++ = *state->rp++;
	}

	return p - buf;
}

static void
close_aesd(fz_stream *stm)
{
	fz_aesd *state = stm->state;
	fz_close(state->chain);
	fz_free(state);
}

fz_stream *
fz_open_aesd(fz_stream *chain, unsigned char *key, unsigned keylen)
{
	fz_aesd *state;

	state = fz_malloc(sizeof(fz_aesd));
	state->chain = chain;
	aes_setkey_dec(&state->aes, key, keylen * 8);
	state->ivcount = 0;
	state->rp = state->bp;
	state->wp = state->bp;

	return fz_new_stream(state, read_aesd, close_aesd);
}

/////////////////// ASCIIHex Decode ///////////////////////////////////////
int fz_my_ASCIIHex_Decrypt(char *dst, long *dstLen, char *src, long srcLen)
{
	int i, j;
	int nReturn = 1;
	char szSearch[3];
	char *stopstring = NULL;

	j = 0;
	for(i=0; i<srcLen; i++)
	{
		if(src[i+0] == '>') break;
		if(src[i+1] == '>') 
		{
			nReturn = 0;
			break;
		}
		if(src[i+0] == ' ') continue;

		szSearch[0] = src[i+0];
		szSearch[1] = src[i+1];
		szSearch[2] = 0;

		dst[j] = (char)strtoul(szSearch, &stopstring, 16);

		i += 2;
		j ++;
	}
	dst[j] = 0;
	*dstLen = j;

	return nReturn;
}

////////////////////// ASCII85 Decode //////////////////////////////////
static unsigned long pow85[] = 
{
	85*85*85*85, 85*85*85, 85*85, 85, 1
};

void wput(unsigned long tuple, int bytes)
{
	switch (bytes) 
	{
	case 4:
		putchar(tuple >> 24);
		putchar(tuple >> 16);
		putchar(tuple >>  8);
		putchar(tuple);
		break;
	case 3:
		putchar(tuple >> 24);
		putchar(tuple >> 16);
		putchar(tuple >>  8);
		break;
	case 2:
		putchar(tuple >> 24);
		putchar(tuple >> 16);
		break;
	case 1:
		putchar(tuple >> 24);
		break;
	}
}

void decode85(FILE *fp, const char *file) 
{
	unsigned long tuple = 0;
	int c, count = 0;

	for(;;)
		switch(c = getc(fp)) 
		{
		default:
			if(c < '!' || c > 'u') 
			{
				//fprintf(stderr, "%s: bad character in ascii85 region: %#o\n", file, c);
				exit(1);
			}
			tuple += (c - '!') * pow85[count++];
			if(count == 5) 
			{
				wput(tuple, 4);
				count = 0;
				tuple = 0;
			}
			break;
		case 'z':
			if(count != 0) 
			{
				//fprintf(stderr, "%s: z inside ascii85 5-tuple\n", file);
				exit(1);
			}
			putchar(0);
			putchar(0);
			putchar(0);
			putchar(0);
			break;
		case '~':
			if(getc(fp) == '>') 
			{
				if(count > 0) 
				{
					count--;
					tuple += pow85[count];
					wput(tuple, count);
				}
				c = getc(fp);
				return;
			}
			//fprintf(stderr, "%s: ~ without > in ascii85 section\n", file);
			exit(1);
		case '\n': case '\r': case '\t': case ' ':
		case '\0': case '\f': case '\b': case 0177:
			break;
		case EOF:
			//fprintf(stderr, "%s: EOF inside ascii85 section\n", file);
			exit(1);
		}
}

void decode(FILE *fp, const char *file, int preserve) 
{
	int c;
	while((c = getc(fp)) != EOF)
		if(c == '<')
			if((c = getc(fp)) == '~') decode85(fp, file);
			else 
			{
				if(preserve) putchar('<');
				if(c == EOF) break;
				if(preserve) putchar(c);
			}
		else if(preserve) putchar(c);
}

int fz_my_ASCII85_Decrypt(char *dst, long *dstLen, char *src, long srcLen)
{
	int preserve = 0;
	char szTempPath[512];
	char szInputFile[512]; 
	FILE * asc85_file;

	_getcwd(szTempPath, 512);
	if(szTempPath[strlen(szTempPath)-1] == '\\') szTempPath[strlen(szTempPath)-1] = 0;

	strcpy(szInputFile, szTempPath);
	strcat(szInputFile, "\\tempEncrypt.a85");

	asc85_file = fopen(szInputFile, "w+b");
	if(!asc85_file) return 0;
	fwrite(src, 1, srcLen, asc85_file);
	fclose(asc85_file);

	asc85_file = fopen(szInputFile, "rb");
	if(!asc85_file) return 0;

	decode(asc85_file, szInputFile, preserve);
	fclose(asc85_file);

	asc85_file = fopen(szInputFile, "rb");
	if(!asc85_file) return 0;
	fseek(asc85_file, 0, SEEK_END);
	*dstLen = ftell(asc85_file);
	fseek(asc85_file, 0, SEEK_SET);
	fread(dst, 1, *dstLen, asc85_file);
	fclose(asc85_file);

	return 1;
}

////////////// RunLength Decode ///////////////////////////////////////////////////////
/* Ż�� ���� */
#define ESCAPE  0xB4

/* Run-Length ������� ���� ������ ��Ÿ���� �ĺ� �ڵ� */
#define IDENT1  0x11
#define IDENT2  0x22

/* Run-Length ������ ���� */
void run_length_decomp(FILE *src, char * pszOutFile)
{
	int cur;
	FILE *dst;
	int i = 0, j;
	int length;

	//cur = getc(src);
	//if(cur != IDENT1 || getc(src) != IDENT2)   /* Run-Length ���� ������ �´��� Ȯ�� */
	//{
	//	printf("\n Error : That file is not Run-Length Encoding file");
	//	fcloseall();
	//	exit(1);
	//}

	//while((cur = getc(src)) != NULL)       /* ������� ���� �̸��� ���� */
	//	srcname[i++] = cur;

	if((dst = fopen(pszOutFile, "wb")) == NULL)
	{
		printf("\n Error : Disk full?");
		fcloseall();
		return;
	}

	cur = getc(src);
	while(!feof(src))
	{
		if(cur != ESCAPE) putc(cur, dst);
		else
		{
			cur = getc(src);
			if (cur == ESCAPE) putc(ESCAPE, dst);   
			else
			{
				length = getc(src);
				for(j = 0; j < length; j++) putc(cur, dst);
			}
		}

		cur = getc(src);   
	}

	fclose(dst);
}

int fz_my_RunLength_Decrypt(char *dst, long *dstLen, char *src, long srcLen)
{
	char szTempPath[512];
	char szInputFile[512]; 
	char szOutputFile[512]; 
	FILE * rle_file;

	_getcwd(szTempPath, 512);
	if(szTempPath[strlen(szTempPath)-1] == '\\') szTempPath[strlen(szTempPath)-1] = 0;

	strcpy(szInputFile, szTempPath);
	strcat(szInputFile, "\\tempEncrypt.rle");

	strcpy(szOutputFile, szTempPath);
	strcat(szOutputFile, "\\tempDecrypt.rle");

	rle_file = fopen(szInputFile, "w+b");
	if(!rle_file) return 0;
	fwrite(src, 1, srcLen, rle_file);
	fclose(rle_file);

	rle_file = fopen(szInputFile, "rb");
	if(!rle_file) return 0;

	run_length_decomp(rle_file, szOutputFile);
	fclose(rle_file);

	rle_file = fopen(szOutputFile, "rb");
	if(!rle_file) return 0;
	fseek(rle_file, 0, SEEK_END);
	*dstLen = ftell(rle_file);
	fseek(rle_file, 0, SEEK_SET);
	fread(dst, 1, *dstLen, rle_file);
	fclose(rle_file);

	return 1;
}