In order to use this library, all you need to do is to have the bddisasm folder in your include path.
You also need to link with the latest version of bddisasm.lib, that you will find under the releases

You can find both of these over at https://github.com/bitdefender/bddisasm, this library was built and tested on v2.1.0 however the latest version should _probably_ always work perfectly.

Where you want to include the implementation of the library, pound-define X64_HOOK_IMPLEMENTATION.

Example implementation & usage can be found in: example.c

---------------------------------------------------------------------------------------

The general api usage & recommendations:

You should only call these unless you really know what you are doing.
You may enumerate over the "hooks" found in x64_Hook_Handle with "num_hooks",
however in that case you NEED to make sure not to add or install/uninstall
anything while doing this or you will run into thread-safety issues.

x64_hook_allocate(void);
x64_hook_free

(There is no _remove on purpose, just allocate another handle in that case.)
x64_hook_add

x64_hook_install
x64_hook_uninstall