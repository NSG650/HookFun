#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

#include "log.h"

VOID Logf(UCHAR Level, PCSTR Fmt, ...) {
	va_list Args;
	CHAR Buffer[512];
	va_start(Args, Fmt);
	vsprintf_s(Buffer, 512, Fmt, Args);
	switch (Level) { 
		case 0:
			printf("[+] %s\n", Buffer);
			break;
		case 1:
			printf("[!] %s\n", Buffer);
			break;
		default:
			printf("[*] %s\n", Buffer);
			break;
	}
	va_end(Args);
}