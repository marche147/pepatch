
int strlen(char* str)
{
	char* p;
	int result = 0;
	for(p = str; *p; p++) {
		result++;
	}
	return result;
}

char* strcpy(char* dest, char* src)
{
	char* result = dest;
	while(*src) {
		*dest = *src;
		dest++, src++;
	}
	return result;
}

void* memcpy(void* dst, void* src, size_t size)
{
	char* p1 = dst, *p2 = src;
	void* result = dst;
	while(size--) {
		*p1 = *p2;
		p1++, p2++;
	}
	return result;
}

void* memset(void* dst, int fill, size_t size)
{
	char* p1 = dst;
	void* result = dst;
	while(size--) {
		*p1 = fill;
		p1++;
	}
	return result;
}
