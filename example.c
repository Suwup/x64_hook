// Compiled with:
// cl /nologo /O2 example.c -WX -Wall -wd4710 /I. /link bddisasm.lib
//
// Correct output:
//
// original
// hook
// original
// original
//

#pragma warning(push, 0)
#include <assert.h>
#include <stdio.h>
#pragma warning(pop)

#define X64_HOOK_ASSERT(x) assert(x)
#define X64_HOOK_IMPLEMENTATION

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
        x64_hook_install(handle);
        
        original();
        hook();
        trampoline();
        
        x64_hook_uninstall(handle);
    } else {
        printf("Failed to hook!\n");
    }

    if (!x64_hook_free(handle)) {
        printf("Failed to free hook handle!\n");
    }

    printf("Done!\n");
    return 0;
}
