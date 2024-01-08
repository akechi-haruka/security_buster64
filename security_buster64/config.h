#pragma once
#include <windows.h>

#define MAX_STR 128

struct buster_config {
	int enable;
	int bypass_verification;
	int strip_https;
	wchar_t redirect_host[MAX_STR];
	int redirect_port;
	int heap_alloc;
};

static const char* CONFIG_FILE = ".\\security_buster.ini";
static const wchar_t* CONFIG_FILE_W = L".\\security_buster.ini";

void load_config(struct buster_config* config);