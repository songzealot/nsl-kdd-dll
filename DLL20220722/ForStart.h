#pragma once

#ifdef CREATEDLL_EXPORTS
#define FORSTART_DECLSPEC __declspec(dllexport)
#else
#define FORSTART_DECLSPEC __declspec(dllimport)
#endif

extern "C" FORSTART_DECLSPEC void Test(char* dev_name);
extern "C" FORSTART_DECLSPEC void output_false();
extern "C" FORSTART_DECLSPEC bool output_status();
extern "C" FORSTART_DECLSPEC const char* rt_output();