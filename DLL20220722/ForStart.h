#pragma once

#ifdef CREATEDLL_EXPORTS
#define FORSTART_DECLSPEC __declspec(dllexport)
#else
#define FORSTART_DECLSPEC __declspec(dllimport)
#endif

extern "C" FORSTART_DECLSPEC void Test();
