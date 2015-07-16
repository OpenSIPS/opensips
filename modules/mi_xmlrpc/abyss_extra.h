


#ifndef ABYSS_EXTRA_H
#define ABYSS_EXTRA_H

typedef unsigned long uint64;
typedef long int64;

typedef unsigned int uint32;
typedef int int32;

typedef unsigned short uint16;
typedef short int16;

typedef unsigned char byte;
typedef unsigned char uint8;
typedef char int8;

typedef struct
{
        void *data;
        uint32 size;
        uint32 staticid;
} TBuffer;

typedef struct
{
        TBuffer buffer;
        uint32 size;
} TString;


/*********************************************************************
** Buffer
*********************************************************************/

abyss_bool BufferAlloc(TBuffer *buf,uint32 memsize);
abyss_bool BufferRealloc(TBuffer *buf,uint32 memsize);
void BufferFree(TBuffer *buf);


/*********************************************************************
** String
*********************************************************************/

abyss_bool StringAlloc(TString *s);
abyss_bool StringConcat(TString *s,char *s2);
abyss_bool StringBlockConcat(TString *s,char *s2,char **ref);
void StringFree(TString *s);
char *StringData(TString *s);

#endif

