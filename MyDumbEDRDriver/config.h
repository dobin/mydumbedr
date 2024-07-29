#pragma once

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>


typedef struct _config {
	BOOL enable_processnotify;
	BOOL enable_threadnotify;
	BOOL enable_imagenotify;
	BOOL enable_obnotify;
} Config;


// Declare a global configuration instance
extern Config g_config;

void init_config();
void print_config();