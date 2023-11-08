// Compiled with:
// cl /nologo /O2 example.c -WX -Wall -wd4710 /I. /link bddisasm.lib

#pragma warning(push, 0)
#include <assert.h>
#include <stdio.h>

#include "bddisasm/bddisasm.h"
#pragma warning(pop)

// Just so we don't have to set the include path for the example.
#define X64_HOOK_BDDISASM_ALREADY_INCLUDED

#define X64_HOOK_DEBUG 1
#define X64_HOOK_PRINTF(...) printf(__VA_ARGS__)
#define X64_HOOK_ASSERT(x) assert(x)

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
