/* $Id$*/

#ifndef _CMD_H_
#define _CMD_H_

#include <string.h>

const char *cmdlist[] = {"SPOP","GET"};
int num_elements = 2;

int find_cmd_type(char cmd[])
{	
	
    int i;
    for (i=0; i<num_elements; i++)
   	{
	 	if (!strcmp(cmdlist[i],cmd)) return i;
   	}
   	return -1;
}

#endif /* _CMD_H_ */