---
title: "mmgeoip Module"
description: "This module is a lightweight wrapper for the MaxMind GeoIP API. It adds IP address-to-location lookup capability to OpenSIPS scripts."
---

## Admin Guide


### Overview


This module is a lightweight wrapper for the MaxMind GeoIP
	  API. It adds IP address-to-location lookup capability to
	  OpenSIPS scripts.


Lookups are executed against the freely-available GeoLite City
	  database; and the non-free GeoIP City database is drop-in
	  compatible. All lookup fields provided by the API are accessible
	  by the script. Visit the
	  [MaxMind
	  website](https://dev.maxmind.com/geoip/) for more information on the location
	  databases.


The module is compatible with both legacy GeoIP and the
		newer GeoIP2 APIs and databases.


### Dependencies


#### OpenSIPS Modules


The following  modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
		OpenSIPS with this module loaded:


- *libGeoIP* - for the legacy GeoIP API and database;
- *libmaxminddb* - for the GeoIP2 API and database.


You can select which GeoIP library to use by setting the GEOIP environment variable,
	  	before compiling the module, to one of the following values:


- *GEOIPLEGACY  **** libGeoIP library shall be used
- *GEOIP2  **** libmaxminddb library shall be used;


IMPORTANT: If the selected library is not installed the module won't compile.
	  	NOTE: If GEOIP env is not set, the module will try to find which GeoIP library is installed,
	  		prioritizing libmaxminddb.


### Exported Parameters


#### mmgeoip_city_db_path (string)


Path to either a GeoLite or GeoIP City database file.


*Mandatory parameter.*


```c title="Set 'mmgeoip_city_db_path' parameter"
...
modparam("mmgeoip", "mmgeoip_city_db_path",
  "/usr/share/GeoIP/GeoLiteCity.dat")
...
		
```


#### cache_type (string)


Databse memory caching options. The following options are available:


- *STANDARD* - Read database from file system;
					least memory used;
- *MMAP_CACHE* - Load database into mmap allocated
					memory;
					*WARNING: this option will cause a segmentation
							fault if database file is changed at runtime!*
- *MEM_CACHE_CHECK* - Load database into memory;
					this mode checks for database updates; if database was modified,
					the file will be reloaded after 60 seconds; it will be slower than
					*MMAP_CACHE* but it will allow reloads;


Default value for this parameter is *MMAP_CACHE*.


NOTE: If libmaxminddb is used, this parameter will be ignored as the library only
	  	supports loading the database into mmap allocated memory.


```c title="Set 'cache_type' parameter"
...
modparam("mmgeoip", "cache_type","MEM_CACHE_CHECK")
...
		
```


### Exported Functions


#### mmg_lookup([fields,]src,dst)


Looks up information specified by `field` associated with
		the IP address `src`. The resulting data is loaded in
		*reverse* order into the `dst` AVP.


Parameters:


- *fields* (string, optional) - a list of elements delimited by
			one of these separators: ':', '|', ',', '/' or ' '(space). Accepts the following tokens:
	  		  
	  			 *lat* - Latitude
	  			 *lon* - Longitude
	  			 *cont* - Continent
	  			 *cc* - Country Code
	  			 *reg* - Region
	  			 *city* - City
	  			 *pc* - Postal Code
	  			 *dma* - DMA Code
	  			 *ac* - Area Code, only available in the legacy GeoIP
	  			database
	  			 *tz* - Time Zone
- *src* (string) - IP address
- *dst* (var) - AVP to return the information associated with the IP in.


When using the GeoIP2 library, each token from the list given in the `fields`
	  	parameter can be provided as a path to a specific key in the data structure associated with an
	  	IP. Thus, the token format is '*key_name*.*key_name*[*.key_name*]*'. If a key's value is an array, instead of a subkey name, an index should be
	  	provided in order to select the appropriate value.


Example tokens: '*country.names.en*', '*continent.names.en*', '*subdivisions.0.iso_code*'. For more details about
	  	the available fields in the database and the key names that should be used to
	  	retrieve them, check the [MaxMind
		GeoIP2 documentation](https://dev.maxmind.com/geoip/geoip2/).


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
		ONREPLY_ROUTE, BRANCH_ROUTE,ERROR_ROUTE, and LOCAL_ROUTE.


```c title="mmg_lookup usage"
...
if(mmg_lookup("lon:lat",$si,$avp(lat_lon))) {
  xlog("L_INFO","Source IP latitude:$(avp(lat_lon)[0])\n");
  xlog("L_INFO","Source IP longitude:$(avp(lat_lon)[1])\n");
};
...
# fields format only supported for GeoIP2
if(mmg_lookup("continent.names.en:country.iso_code,",$si,$avp(geodata))) {
  xlog("L_INFO","Source IP country code:$(avp(geodata)[0])\n");
  xlog("L_INFO","Source IP continent:$(avp(geodata)[1])\n");
};
...
		
```


### Known Issues


It is not currently possible to load an updated location
	  database without first stalling the server.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
