/*$Id$
 *
 * Example ser module, it will just print its string parameter to stdout
 *
 */



#include "../../sr_module.h"
#include "../../dprint.h"
#include <stdio.h>

int print_f(struct sip_msg*, char*);

static struct module_exports print_exports= {	"print_stdout", 
												(char*[]){"print"},
												(cmd_function[]){print_f},
												1,
												0
											};


struct module_exports* mod_register()
{
	fprintf(stderr, "print - registering...\n");
	return &print_exports;
}


int print_f(struct sip_msg* msg, char* str)
{
	printf("%s\n",str);
	DBG("just printed %s\n",str);
	return 1;
}


