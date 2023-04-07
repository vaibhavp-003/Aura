#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#define	ELFMAG		"\177ELF"	/* ELF identification */
#define ELFCLASS32	1			/* 32-bit objects */
#define ELFCLASS64	2			/* 64-bit objects */

typedef struct tagELFIdent
{
	unsigned char	Magic [ 4 ] ;
	unsigned char	el_class ;
	unsigned char	el_data ;
	unsigned char	el_version ;
	unsigned char	el_pad [ 9 ] ;
} ELFIDENT ;

typedef struct tagELFHeader
{
	ELFIDENT	ElfIdent ;
	unsigned short int	Type ;
	unsigned short int	Machine ;
	unsigned long int	Version ;
	unsigned long int	Entry ;
	unsigned long int	Phoff ;
	unsigned long int	Shoff ;
	unsigned long int	Flags ;
	unsigned short int	Ehsize ;
	unsigned short int	Phentsize ;
	unsigned short int	Phnum ;
	unsigned short int	Shentsize ;
	unsigned short int	Shnum ;
	unsigned short int	Shtridx ;
} ELF_HEADER ;

typedef struct tagELFSectionHeader32
{
	unsigned long int	Name ;
	unsigned long int	Type ;
	unsigned long int	Flags ;
	unsigned long int	Addr ;
	unsigned long int	Offset ;
	unsigned long int	Size ;
	unsigned long int	Link ;
	unsigned long int	Info ;
	unsigned long int	Allign ;
	unsigned long int	Entsize ;
} ELF_SECTION_HEADER32 ;


typedef struct tagELFProgramHeader32
{
	unsigned long int	Type ;
	unsigned long int	Offset ;
	unsigned long int	Vaddr ;
	unsigned long int	Paddr ;
	unsigned long int	Filesz ;
	unsigned long int	Memsz ;
	unsigned long int	Flags ;
	unsigned long int	Allign ;
} ELF_PROGRAM_HEADER32 ;
