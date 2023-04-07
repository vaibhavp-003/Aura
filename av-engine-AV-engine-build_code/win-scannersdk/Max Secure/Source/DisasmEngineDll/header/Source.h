// Link list structure 
#pragma pack  ( 1 )

#ifdef _DEBUG
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

typedef struct node
{
	char			* Ptr ;
	struct node*	Zero ; // Left 
	struct node*	One ;  // Right 
} BinaryTreeNode ;
#pragma pack  ( )