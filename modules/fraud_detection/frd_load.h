#ifndef __FRD_LOAD_H__
#define __FRD_LOAD_H__

int frd_init_db(void);
int frd_connect_db(void);
void frd_disconnect_db(void);

int frd_reload_data(void);
void frd_destroy_data(void);

#endif
