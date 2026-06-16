---
title: "RATE_CACHER Module"
description: "The *rate_cacher* module provides a means of caching and real-time querying of the ratesheets assigned to your clients and / or vendors. It also allows for real-time cost-based routing and cost-based filtering."
---

## Admin Guide


### Overview


The *rate_cacher* module provides a means of caching
	and real-time querying of the ratesheets assigned to your clients and / or vendors.
	It also allows for real-time cost-based routing and cost-based filtering.


### Dependencies


#### OpenSIPS Modules


The following modules must be loaded before this module:


- *No dependencies on other OpenSIPS modules.*.


#### External Libraries or Applications


The following libraries or applications must be installed before
		running OpenSIPS with this module loaded:


- *None*.


### Exported Parameters


#### vendors_db_url (str)


The DB URL for querying the Vendors used by the module


*Default value is "NULL".*


```c title="Setting the vendors_db_url parameter"
...
modparam("rate_cacher", "vendors_db_url", "mysql://opensips:opensipsrw@localhost/opensips")
...
```


#### vendors_db_table (str)


The DB Table for querying the Vendors used by the module


*Default value is "rc_vendors".*


```c title="Setting the vendors_db_table parameter"
...
modparam("rate_cacher", "vendors_db_table", "my_vendors_view")
...
```


#### vendors_hash_size (int)


The size of the hash table internally used to keep the vendors. A
		larger table is much faster but consumes more memory. The hash size
		must be a power of 2 number.


*Default value is "256".*


```c title="Setting the vendors_hash_size parameter"
...
modparam("rate_cacher", "vendors_hash_size", 1024)
...
```


#### clients_db_url (str)


The DB URL for querying the Clients used by the module


*Default value is "NULL".*


```c title="Setting the clients_db_url parameter"
...
modparam("rate_cacher", "clients_db_url", "mysql://opensips:opensipsrw@localhost/opensips")
...
```


#### clients_db_table (str)


The DB Table for querying the Clients used by the module


*Default value is "rc_clients".*


```c title="Setting the clients_db_table parameter"
...
modparam("rate_cacher", "clients_db_table", "my_clients_view")
...
```


#### clients_hash_size (int)


The size of the hash table internally used to keep the clients. A
		larger table is much faster but consumes more memory. The hash size
		must be a power of 2 number.


*Default value is "256".*


```c title="Setting the vendors_hash_size parameter"
...
modparam("rate_cacher", "clients_hash_size", 1024)
...
```


#### rates_db_url (str)


The DB URL for querying the Ratesheets used by the module


*Default value is "NULL".*


```c title="Setting the rates_db_url parameter"
...
modparam("rate_cacher", "rates_db_url", "mysql://opensips:opensipsrw@localhost/opensips")
...
```


#### rates_db_table (str)


The DB Table for querying the Ratesheets used by the module


*Default value is "rc_ratesheets".*


```c title="Setting the rates_db_table parameter"
...
modparam("rate_cacher", "rates_db_table", "my_clients_view")
...
```


### Exported Functions


#### get_client_price(client_id,is_wholesale,dialled_no,prefix_pvar,destination_pvar,price_pvar,minimum_pvar,increment_pvar)


For a call originating from the provided Client ID, on a wholesale or retail quality, going to dialled_no, the function will matched the dialled number against the client's ratesheet and return the matched prefix, destination, price, minimum and increment.


The *client_id* pseudo-var will hold the client_id originating this call


The  *is_wholesale* pseudo-var will contain either a 1 or a 0, depending on whether the call is wholesale or retail ( see client ratesheet provisioning ).


The *dialled_no* pseudo-var contains the DNIS - the dialled number for the current call. It needs to be in E164 format, without the leading +


The *prefix* pseudo-var will contain the matched prefix from the client's ratesheet


The *destination* pseudo-var will contain the matched destination from the client's ratesheet


The *price* pseudo-var will contain the matched price from the client's ratesheet


The *minimum* pseudo-var will contain the matched minimum from the client's ratesheet


The *increment* pseudo-var will contain the matched increment from the client's ratesheet


Possible parameter types


- *ALL Parameters* - String/Integer or pseudo-variables


This function can be used from any route.


```c title="get_client_price usage"
...
if (get_client_price("my_client",1,"4072794242",$var(prefix),$var(dest),$var(price),$var(min),$var(inc))) {
                        xlog("We matched $var(prefix) , $var(dest) , $var(price) , $var(min) , $var(inc) for the client's ratesheet\n");
                }

...
```


#### get_vendor_price(vendor_id,dialled_no,prefix_pvar,destination_pvar,price_pvar,minimum_pvar,increment_pvar)


For a call originating going to the provided vendor ID, going to dialled_no, the function will matched the dialled number against the vendor's ratesheet and return the matched prefix, destination, price, minimum and increment.


The *vendor_id* pseudo-var will hold the vendor_id


The *dialled_no* pseudo-var contains the DNIS - the dialled number for the current call. It needs to be in E164 format, without the leading +


The *prefix* pseudo-var will contain the matched prefix from the vendor's ratesheet


The *destination* pseudo-var will contain the matched destination from the vendor's ratesheet


The *price* pseudo-var will contain the matched price from the vendor's ratesheet


The *minimum* pseudo-var will contain the matched minimum from the vendor's ratesheet


The *increment* pseudo-var will contain the matched increment from the vendor's ratesheet


Possible parameter types


- *ALL Parameters* - String/Integer or pseudo-variables


This function can be used from any route.


```c title="get_vendor_price usage"
...
if (get_vendor_price("my_vendor","4072794242",$var(prefix),$var(dest),$var(price),$var(min),$var(inc))) {
                        xlog("We matched $var(prefix) , $var(dest) , $var(price) , $var(min) , $var(inc) for the vendor's ratesheet\n");
                }

...
```


#### cost_based_filtering(client_id,is_wholesale,vendors_csv,dialled_no,desired_margin,out_vendor_csv)


For a call originating from the provided Client ID, on a wholesale or retail quality, going to dialled_no, the function removes the Vendors ( from the vendor_csv list ) which do not pass the desired_margin condition, and sets the out_vendor_csv variable to the list of Vendor that meet the margin condition, while maintaining the initial order provided in the vendor_csv variable.


The *client_id* pseudo-var will hold the client_id originating this call


The  *is_wholesale* pseudo-var will contain either a 1 or a 0, depending on whether the call is wholesale or retail ( see client ratesheet provisioning ).


The *vendors_csv* pseudo-var contains a list of Vendors that need to be filtered based on the desired margin ( keep just those that match your desired percentage margin for this call )


The *dialled_no* pseudo-var contains the DNIS - the dialled number for the current call. It needs to be in E164 format, without the leading +


The *desired_margin* pseudo-var contains the minimum Integer margin that the script writer wants to achieve, based on the Client sell and Vendor buy prices. The formula used is : vendor_margin=(client_price - results[i])*100/client_price) . If the vendor_margin is higher than the desired_margin, then the Vendor is ok to use. The desired margin can be positive ( call will be profitable ) or negative ( the call will cause a loss ).


The *out_vendors_csv* pseudo-var is an output parameter, and the pvar will get populated with the CSV list of Vendors that meet the desired margin condition


Possible parameter types


- *ALL Parameters* - String/Integer or pseudo-variables


This function can be used from a REQUEST or FAILURE route.


```c title="cost_based_filtering usage"
...


# If we get a call from testClient on it's wholesale quality,
# going to number 40720018124, and we have to pick from the list 
# of vendors 'testVendor,testVendor2' based on a a profit margin 
# of 0 ( we do not want to lose money on this call ),
# then $avp(out_vendor_csv) will have the vendors that we need 
# to use based on the above call characteristics, the order of the
# vendors that was provided in $avp(carrierlist) and the desired margin
$avp(client_id)="testClient";
$avp(is_ws)=1;  
$avp(carrierlist)="testVendor,testVendor2";
$avp(dnis)="40720018124";
$avp(profit_margin)=0;

if (cost_based_filtering("$avp(client_id)","$avp(is_ws)","$avp(carrierlist)","$avp(dnis)","$avp(profit_margin)","$avp(out_vendor_result)")) {
	xlog("XXX - Out of the $avp(carrierlist) carriers, we should only use $avp(out_vendor_result) \n");
...
```


#### cost_based_ordering(client_id,is_wholesale,vendors_csv,dialled_no,desired_margin,out_vendor_csv)


For a call originating from the provided Client ID, on a wholesale or retail quality, going to dialled_no, the function removes the Vendors ( from the vendor_csv list ) which do not pass the desired_margin condition, and sets th out_vendor_csv variable to the list of Vendor that meet the margin condition, in descending order of their margin ( from most profitable Vendor to least profitable Vendor that still meets the margin condition )


The *client_id* pseudo-var will hold the client_id originating this call


The  *is_wholesale* pseudo-var will contain either a 1 or a 0, depending on whether the call is wholesale or retail ( see client ratesheet provisioning ).


The *vendors_csv* pseudo-var contains a list of Vendors that need to be filtered based on the desired margin ( keep just those that match your desired percentage margin for this call )


The *dialled_no* pseudo-var contains the DNIS - the dialled number for the current call. It needs to be in E164 format, without the leading +


The *desired_margin* pseudo-var contains the minimum Integer margin that the script writer wants to achieve, based on the Client sell and Vendor buy prices. The formula used is : vendor_margin=(client_price - results[i])*100/client_price) . If the vendor_margin is higher than the desired_margin, then the Vendor is ok to use. The desired margin can be positive ( call will be profitable ) or negative ( the call will cause a loss ).


The *out_vendors_csv* pseudo-var is an output parameter, and the pvar will get populated with the CSV list of Vendors that meet the desired margin condition


Possible parameter types


- *ALL Parameters* - String/Integer or pseudo-variables


This function can be used from any route.


```c title="cost_based_ordering usage"
...
# If we get a call from testClient on it's wholesale quality,
# going to number 40720018124, and we have to pick from the list 
# of vendors 'testVendor,testVendor2' based on a a profit margin 
# of 0 ( we do not want to lose money on this call ),
# then $avp(out_vendor_csv) will have the vendors that we need 
# to use based on the above call characteristics, and the desired margin
# The order in $avp(carrierlist) does not matter, the vendors will be
# ordered from most profitable to least profitable
$avp(client_id)="testClient";
$avp(is_ws)=1;  
$avp(carrierlist)="testVendor,testVendor2";
$avp(dnis)="40720018124";
$avp(profit_margin)=0;

if (cost_based_ordering("$avp(client_id)","$avp(is_ws)","$avp(carrierlist)","$avp(dnis)","$avp(profit_margin)","$avp(out_vendor_result)")) {
	xlog("XXX - Out of the $avp(carrierlist) carriers, we should only use $avp(out_vendor_result) , in the provided order\n");

...
```


### Exported MI Functions


#### rate_cacher:addVendor


Replaces obsolete MI command: *rc_addVendor*.


Adds a new Vendor, without assigning any ratesheet to it.


Name: *rate_cacher:addVendor*


Parameters :


- *vendorName* - name of the Vendor to be added


MI FIFO Command Format:


```c
## Add a new Vendor
# opensips-cli -x mi rate_cacher:addVendor myNewVendor
		
```


#### rate_cacher:deleteVendor


Replaces obsolete MI command: *rc_deleteVendor*.


Removes a vendor from memory, along with the ratesheet asigned with it ( if any )


Name: *rate_cacher:deleteVendor*


Parameters :


- *vendorName* - name of the Vendor to be deleted


MI FIFO Command Format:


```c
## Delete a Vendor
# opensipss-cli -x mi rate_cacher:deleteVendor myNewVendor
		
```


#### rate_cacher:reloadVendorRate


Replaces obsolete MI command: *rc_reloadVendorRate*.


Reloads the provided ratesheet and assigns it to the Vendor


Name: *rate_cacher:reloadVendorRate*


Parameters :


- *vendorName* - name of the Vendor
- *ratesheet_id* - ID of the ratesheet to be reloaded and assigned


MI FIFO Command Format:


```c
## Reloads a Vendor Ratesheet
# opensips-cli -x mi rate_cacher:reloadVendorRate myVendor 3
		
```


#### rate_cacher:deleteVendorRate


Replaces obsolete MI command: *rc_deleteVendorRate*.


Deletes the assigned ratesheet from the Vendor


Name: *rate_cacher:deleteVendorRate*


Parameters :


- *vendorName* - name of the Vendor


MI FIFO Command Format:


```c
## Reloads a Vendor Ratesheet
# opensips-cli -x mi rate_cacher:deleteVendorRate myVendor
		
```


#### rate_cacher:getVendorPrice


Replaces obsolete MI command: *rc_getVendorPrice*.


Fetches all the ratesheet information ( destination name, price, minimum, increment ) for the provided Vendor and dialled number


Name: *rate_cacher:getVendorPrice*


Parameters :


- *vendorName* - name of the Vendor
- *dialledNumber* - number to match in the above Vendor's ratesheet


MI FIFO Command Format:


```c
## Query for the price of myVendor for the 4072731825 number
#/usr/local/bin/opensips-cli -x mi rate_cacher:getVendorPrice myVendor 4072731825
{
    "prefix": "40727",
    "destination": "ROMANIA MOBILE VODAFONE",
    "price": 0.05,
    "minimum": 1,
    "increment": 1,
    "currency": "USD"
}
		
```


#### rate_cacher:addClient


Replaces obsolete MI command: *rc_addClient*.


Adds a new Client, without assigning any ratesheet to it.


Name: *rate_cacher:addClient*


Parameters :


- *clientName* - name of the Client to be added


MI FIFO Command Format:


```c
## Add a new Client
# opensips-cli -x mi fifo rate_cacher:addClient myNewClient
		
```


#### rate_cacher:deleteClient


Replaces obsolete MI command: *rc_deleteClient*.


Removes a Client from memory, along with the ratesheet asigned with it ( if any )


Name: *rate_cacher:deleteClient*


Parameters :


- *clientName* - name of the Client to be deleted


MI FIFO Command Format:


```c
## Delete a Client
# opensips-cli -x mi rate_cacher:deleteClient myClient
		
```


#### rate_cacher:reloadClientRate


Replaces obsolete MI command: *rc_reloadClientRate*.


Reloads the provided ratesheet and assigns it to the Client


Name: *rate_cacher:reloadClientRate*


Parameters :


- *clientName* - name of the Cient
- *isWholesale* - is the ratesheet assigned on the wholesale or retail quality
- *ratesheet_id* - ID of the ratesheet to be reloaded and assigned


MI FIFO Command Format:


```c
## Reloads the Client's wholesale Ratesheet, assigning it rate id 3
# opensips-cli -x mi rate_cacher:reloadClientRate myClient 1 3
		
```


#### rate_cacher:deleteClientRate


Replaces obsolete MI command: *rc_deleteClientRate*.


Deletes the assigned ratesheet from the Client


Name: *rate_cacher:deleteClientRate*


Parameters :


- *ClientName* - name of the Client
- *isWholesale* - delete the wholesale or retail ratesheet


MI FIFO Command Format:


```c
## Deletes a Client Ratesheet
# opensips-cli -x mi rate_cacher:deleteClientRate myClient 1
		
```


#### rate_cacher:getClientPrice


Replaces obsolete MI command: *rc_getClientPrice*.


Fetches all the ratesheet information ( destination name, price, minimum, increment ) for the provided Client, on the specified quality ( wholesale vs retail ) and dialled number


Name: *rate_cacher:getClientPrice*


Parameters :


- *ClientName* - name of the Client
- *isWholesale* - wholesale = 1, retail = 0
- *dialledNumber* - number to match in the above Client's ratesheet


MI FIFO Command Format:


```c
## Query for the price of myClient, on the retail quality, for the 4072731825 number
#/usr/local/bin/opensips-cli -x mi rate_cacher:getClientPrice myClient 0 4072731825
{
    "prefix": "40727",
    "destination": "ROMANIA MOBILE VODAFONE",
    "price": 0.03,
    "minimum": 1,
    "increment": 1,
    "currency": "USD"
}

		
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
