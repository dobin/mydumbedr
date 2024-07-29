#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "config.h"


Config g_config;


void init_config() {
	g_config.enable_processnotify = TRUE;
	g_config.enable_threadnotify = TRUE;
	g_config.enable_imagenotify = TRUE;
	g_config.enable_obnotify = TRUE;

	HANDLE pid;
}


void print_config() {

}