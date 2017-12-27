// some basic type definitions
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
#ifdef __x86_64__
typedef unsigned long long uintptr_t;
typedef long long intptr_t;
#else
typedef unsigned int uintptr_t;
typedef int intptr_t;
#endif
typedef uintptr_t size_t;
typedef intptr_t ssize_t;

// function definitions
int strlen(char* str);
char* strcpy(char* dst, char* src);
void* memcpy(void* dst, void* src, size_t size);
void* memset(void* dst, int fill, size_t size);
