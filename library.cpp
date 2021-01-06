#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drsyms.h"
#include <string.h>

#define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#define NULL_TERMINATE(buf) (buf)[(sizeof((buf)) / sizeof((buf)[0])) - 1] = '\0'

static void event_exit(void);
static void wrap_pre(void *wrapcxt, OUT void **user_data);
static void wrap_post(void *wrapcxt, void *user_data);

static size_t max_malloc;
static uint   malloc_oom;
static void   *mod_lock;
static file_t fd;

static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
	app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, "malloc");

	if (towrap != NULL && strstr("libc", mod->names.file_name))
	{
		bool ok = drwrap_wrap(towrap, wrap_pre, wrap_post);
		if (ok)
		{
			dr_fprintf(STDERR, "load module name : %s\n", mod->names.file_name);
			dr_fprintf(STDERR, "<wrapped malloc @" PFX "\n", towrap);
		}
	}
}

static dr_emit_flags_t
event_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
				  bool for_trace, bool translating, void *user_data)
{
	/* ignore tool-inserted instrumentation */
	if (!instr_is_app(instr))
		return DR_EMIT_DEFAULT;

	/* instrument calls and returns -- ignore far calls/rets */
	if (instr_is_call_direct(instr)) {
//		insert_counter_update(drcontext, bb, instr,
//							  offsetof(per_thread_t, num_direct_calls));
//	} else if (instr_is_call_indirect(instr)) {
//		insert_counter_update(drcontext, bb, instr,
//							  offsetof(per_thread_t, num_indirect_calls));
//	} else if (instr_is_return(instr)) {
//		insert_counter_update(drcontext, bb, instr, offsetof(per_thread_t, num_returns));
		byte val[8];
		dr_mcontext_t mcontext;
		mcontext.size = sizeof(mcontext);
		mcontext.flags = DR_MC_ALL;

		dr_get_mcontext(drcontext, &mcontext);
		reg_get_value_ex(DR_REG_RDI, &mcontext, val);
		dr_fprintf(STDOUT, "RDI : 0x%llX\n", *val);
		reg_get_value_ex(DR_REG_RSI, &mcontext, val);
		dr_fprintf(STDOUT, "RSI : 0x%llX\n", *val);
		reg_get_value_ex(DR_REG_RDX, &mcontext, val);
		dr_fprintf(STDOUT, "RDX : 0x%llX\n", *val);
		reg_get_value_ex(DR_REG_RCX, &mcontext, val);
		dr_fprintf(STDOUT, "RCX : 0x%llX\n", *val);
		reg_get_value_ex(DR_REG_R8, &mcontext, val);
		dr_fprintf(STDOUT, "R8 : 0x%llX\n", *val);
		reg_get_value_ex(DR_REG_R9, &mcontext, val);
		dr_fprintf(STDOUT, "R9 : 0x%llX\n", *val);
		instr_disassemble(drcontext, instr, STDOUT);
		dr_fprintf(STDOUT, "\n");
	}

	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data)
{
	instr_t *instr = instrlist_first_app(bb);

	dr_mutex_lock(mod_lock);

	app_pc pc = instr_get_app_pc(instr);
	module_data_t *mod = dr_lookup_module(pc);
	module_data_t *data = dr_get_main_module();
	if (mod->start == data->start)
		instrlist_disassemble(drcontext, (app_pc) tag, bb, STDOUT);
	dr_mutex_unlock(mod_lock);
	return DR_EMIT_DEFAULT;
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	dr_set_client_name("DynamoRIO Sample Client 'wrap'", "http://dynamorio.org/issues");
	/* make it easy to tell, by looking at log file, which client executed */
	dr_log(NULL, DR_LOG_ALL, 1, "Client 'wrap' initializing\n");
	/* also give notification to stderr */
	if (dr_is_notify_on())
	{
		dr_fprintf(our_stderr, "Client wrap is running\n");
	}
	disassemble_set_syntax(DR_DISASM_INTEL);
	//fd = dr_open_file("123.txt", DR_FILE_WRITE_OVERWRITE);
	drmgr_init();
	drwrap_init();
	dr_register_exit_event(event_exit);
	//drmgr_register_module_load_event(module_load_event);
	//drmgr_register_bb_instrumentation_event(event_bb_analysis, NULL, NULL);
	drmgr_register_bb_instrumentation_event(NULL, event_instruction, NULL);
	mod_lock = dr_mutex_create();
}

static void event_exit(void)
{
	char msg[256];
	int  len;
	len = dr_snprintf(msg, sizeof(msg) / sizeof(msg[0]), "<Largest  malloc request: %d>\n<OOM simulations: %d>\n",
					  max_malloc, malloc_oom);
	DR_ASSERT(len > 0);
	NULL_TERMINATE(msg);
	DISPLAY_STRING(msg);

	dr_mutex_destroy(mod_lock);
	drwrap_exit();
	drmgr_exit();
}

static void wrap_pre(void *wrapcxt, OUT void **user_data)
{
	/* malloc(size) or HeapAlloc(heap, flags, size) */
	size_t sz = (size_t) drwrap_get_arg(wrapcxt, 0);
	/* find the maximum malloc request */
	dr_fprintf(STDOUT, "<malloc size : \t0x%x\n", sz);
	*user_data = (void *) sz;
}

static void wrap_post(void *wrapcxt, void *user_data)
{
	size_t sz = (size_t) user_data;
	dr_fprintf(STDOUT, "<malloc addr : \t%p\n", drwrap_get_retval(wrapcxt));
}

