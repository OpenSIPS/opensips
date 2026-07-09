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
website](http://www.maxmind.com/app/geolitecity) for more information on the location 
databases.


### Dependencies


#### OpenSIPS Modules


The following  modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules*.


#### External Libraries or Applications


The following libraries or applications must be installed before running
OpenSIPS with this module loaded:


- *libGeoIP*.


### Exported Parameters


#### mmgeoip_city_db_path (string)


Path to either a GeoLite or GeoIP City database file.


*Mandatory parameter.*


```opensips title="Set 'mmgeoip_city_db_path' parameter"
...
modparam("mmgeoip", "mmgeoip_city_db_path",
  "/usr/share/GeoIP/GeoLiteCity.dat")
...
		
```


### Exported Functions


#### mmg_lookup([fields,]src,dst)


Looks up specified `field`s associated with IP address
specified by the `src`. The resulting data are
loaded in *reverse* order into
the `dst` AVP.


`src` can be a pseudo-variable or AVP;
and `dst` *must* be an AVP.
`fields` defaults to "lon:lat," and is a
colon-delimited list of these elements:


- `lat` Latitude
- `lon` Longitude
- `cont` Continent
- `cc` Country Code
- `reg` Region
- `city` City
- `pc` Postal Code
- `dma` DMA Code
- `ac` Area Code
- `TZ` Time Zone


This function can be used from REQUEST_ROUTE, FAILURE_ROUTE,
ONREPLY_ROUTE, BRANCH_ROUTE,ERROR_ROUTE, and LOCAL_ROUTE.


```opensips title="mmg_lookup usage"
...
if(mmg_lookup("lon:lat","$si","$avp(lat_lon)")) {
  xlog("L_INFO","Source IP latitude:$(avp(lat_lon)[0])\n");
  xlog("L_INFO","Source IP longitude:$(avp(lat_lon)[1])\n");
};
...
		
```


### Known Issues


It is not currently possible to load an updated location
database without first stalling the server.
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
