#include "../module.h"
#include <string.h>

#define DLL __declspec(dllexport)

struct {
	module_context_t context;
} static state;

DLL module_version_t module_version = {
	1,
	0,
	0,
};

DLL b8 module_setup(module_context_t context) {
	memcpy(&state.context, &context, sizeof(module_context_t));
	context.register_to_port(0x01, module_port_callback);

	return 1;
}

DLL void module_update(void) {

}

DLL void module_port_callback(u16 port, u8 value) {
	if (value == 0x69) {
		state.context.out_port(0x01, 0x42);
	}
}