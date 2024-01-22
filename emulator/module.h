#ifndef KRISVERS_KRISC_MODULE_H
#define KRISVERS_KRISC_MODULE_H

#include "types.h"

typedef void (*port_callback_f)(u16 port, u8 value);

typedef b8 (*map_memory_f)(u32 addr, u32 len);
typedef u8 (*in_port_f)(u16 port);
typedef void (*out_port_f)(u16 port, u8 value);
typedef void (*register_to_port_f)(u16 port, port_callback_f port_callback);

typedef struct module_version {
	u8 major;
	u8 minor;
	u8 patch;
} module_version_t;

typedef struct module_context {
	module_version_t version;
	map_memory_f map_memory;
	in_port_f in_port;
	out_port_f out_port;
	register_to_port_f register_to_port;
} module_context_t;

typedef b8 (*module_setup_f)(module_context_t context);
typedef void (*module_update_f)(void);

typedef struct module {
	module_setup_f module_setup;
	module_update_f module_update;
	b8 enabled;
} module_t;

#endif