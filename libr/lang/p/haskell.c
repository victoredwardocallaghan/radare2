/* radare - LGPL - Copyright 2014 eocallaghan */
/* haskell extension for libr (radare2) */
// TODO: add cache directory (~/.r2/cache)

#include "r_lib.h"
#include "r_core.h"
#include "r_lang.h"

static int lang_haskell_file(RLang *lang, const char *file) {
	void *lib;
	char *cc, *p, name[512], buf[512];

	if (strlen (file) > (sizeof(name)-10))
		return R_FALSE;
	if (!strstr (file, ".hs"))
		sprintf (name, "%s.hs", file);
	else strcpy (name, file);
	if (!r_file_exists (name)) {
		eprintf ("file not found (%s)\n", name);
		return R_FALSE;
	}

	p = strstr (name, ".hs"); if (p) *p=0;
	cc = r_sys_getenv ("CC");
	if (!cc || !*cc)
		cc = strdup ("gcc");
	snprintf (buf, sizeof (buf), "%s -fPIC -shared %s -o lib%s."R_LIB_EXT
		" $(pkg-config --cflags --libs r_core)", cc, file, name);
	free (cc);
	if (system (buf) != 0)
		return R_FALSE;

	snprintf (buf, sizeof (buf), "./lib%s."R_LIB_EXT, name);
	lib = r_lib_dl_open (buf);
	if (lib!= NULL) {
		void (*fcn)(RCore *);
		fcn = r_lib_dl_sym (lib, "entry");
		if (fcn) fcn (lang->user);
		else eprintf ("Cannot find 'entry' symbol in library\n");
		r_lib_dl_close (lib);
	} else eprintf ("Cannot open library\n");
	r_file_rm (buf); // remove lib
	return 0;
}

static int lang_haskell_init(void *user) {
	// TODO: check if "valac" is found in path
	return R_TRUE;
}

static int lang_haskell_run(RLang *lang, const char *code, int len) {
	FILE *fd = fopen (".tmp.hs", "w");
	if (fd) {
		fputs ("{-# LANGUAGE ForeignFunctionInterface #-}\n\n", fd);
		fputs ("module R2H where\n\n", fd);
		fputs ("import Radare\n", fd);
		fputs ("import Foreign.C.Types\n\n", fd);
		fputs ("entry :: RCore -> IO ()\n", fd);
		fputs ("entry core = do\n", fd);
		fputs (code, fd);
		fclose (fd);
		lang_c_file (lang, ".tmp.hs");
		r_file_rm (".tmp.hs");
	} else eprintf ("Cannot open .tmp.hs\n");
	return R_TRUE;
}

static struct r_lang_plugin_t r_lang_plugin_haskell = {
	.name = "hs",
	.ext = "hs",
	.desc = "Haskell language extension",
	.help = NULL,
	.run = lang_haskell_run,
	.init = (void*)lang_haskell_init,
	.fini = NULL,
	.run_file = (void*)lang_haskell_file,
	.set_argv = NULL,
};
