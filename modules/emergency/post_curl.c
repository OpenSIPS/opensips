/*
 * emergency module - basic support for emergency calls
 *
 * Copyright (C) 2014-2015 Robison Tesini & Evandro Villaron
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2014-10-14 initial version (Villaron/Tesini)
 *  2015-03-21 implementing subscriber function (Villaron/Tesini)
 *  2015-04-29 implementing notifier function (Villaron/Tesini)
 *  2015-08-05 code review (Villaron/Tesini)
 *  2015-09-07 final test cases (Villaron/Tesini)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "post_curl.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

struct url_data {
	size_t size;
	char* data;
};

size_t write_data(char *ptr, size_t size, size_t nmemb, void *stream) {
	struct url_data *data = (struct url_data *)stream;
	size_t index = data->size;
	size_t n = (size * nmemb);
	char* tmp;

	data->size += (size * nmemb);

#ifdef DEBUG
	fprintf(stderr, "data at %p size=%ld nmemb=%ld\n", ptr, size, nmemb);
#endif
	tmp = realloc(data->data, data->size + 1); /* +1 for '\0' */

	if(tmp) {
		data->data = tmp;
	} else {
		if(data->data) {
			free(data->data);
		}
		fprintf(stderr, "Failed to allocate memory.\n");
		return 0;
	}

	memcpy((data->data + index), ptr, n);
	data->data[data->size] = '\0';

	return size * nmemb;
}

/* simple FTTP POST using curl lib */
int post(char*  url, char* xml, char** response){
	CURL *curl;
	CURLcode res;
	LM_DBG("INIT CURL\n");
	curl = curl_easy_init();
	struct url_data data;
	data.size = 0;
	data.data = malloc(1024); /* reasonable size initial buffer */
	if(NULL == data.data) {
		LM_ERR("NO MEMORY\n");
		return -1;
	}
	memset(data.data, '\0', 1024);
	LM_DBG("CURL PASSOU MALLOC\n");

	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, xml);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
		long http_code = 0;
		res = curl_easy_perform(curl);
		int resp = -1;
		if(res != CURLE_OK){
			LM_DBG("CURL curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
			resp = -1;
		}else{
			curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
			if(http_code != 0 &&(http_code <200 || http_code >=300)){
				LM_DBG("CURL HTTP STATUS %ld", http_code);
				return -1;
			}
			LM_DBG("CURL OK...\n");
			*response = pkg_malloc(sizeof(char)*strlen(data.data));
			strcpy(*response,data.data);
			LM_DBG("CURL DEPOIS DO DATA OK...\n");
			resp = 1;
		}
		/* always  cleanup */
		curl_easy_cleanup(curl);
		LM_DBG("CURL DEPOIS DO CLEANUP...\n");
		free(data.data);
		LM_DBG("CURL DEPOIS DO FREE...\n");
		return resp;
	}

	free(data.data);
	return  -1;
}
