// Compiled with:
// cl /O2 example.c -WX -Wall -wd4710 -wd5045 /link bddisasm.lib

#define NOINLINE __declspec(noinline)
#define WIN32_MEAN_AND_LEAN

#pragma warning(push, 0)
#include <windows.h>
#include <assert.h>
#include <stdio.h>

#include "bddisasm/bddisasm.h"
#pragma warning(pop)

#define X64_HOOK_ASSERT(x) assert(x)
#define X64_HOOK_DEBUG 1
#define X64_HOOK_BDDISASM_ALREADY_INCLUDED

#include "x64_hook.h"

void(*trampoline)(void);

void original(void) {
    printf("original\n");
}

void hook(void) {
     printf("hook\n");
     trampoline();
}

int main(void) {
    x64_Hook_Handle *handle = x64_hook_allocate();
    if (x64_hook_add(handle, (void *)original, (void *)hook, (void **)&trampoline)) {
        if (x64_hook_install(handle)) {
            original();
            hook();
            trampoline();

            if (!x64_hook_uninstall(handle)) {
                printf("Failed to uninstall hooks!\n");
            }
        } else {
            printf("Failed to install hooks!\n");
        }
    } else {
        printf("Failed to hook!\n");
    }

    if (!x64_hook_free(handle)) {
        printf("Failed to free hook handle!\n");
    }

    printf("Done!\n");
    return 0;
}
