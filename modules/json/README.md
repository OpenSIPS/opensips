---
title: "JSON Module"
description: "This module introduces a new type of variable that provides both serialization and de-serialization from JSON format."
---

## Admin Guide


### Overview


This module introduces a new type of variable that provides both
	serialization and de-serialization from JSON format.


The variable provides ways to access objects and arrays to add,replace
	or delete values from the script.


The correct approach is to consider a json object as a hashtable
	( you can put (key;value) pairs, and you can delete and get
	 values by key) and a json array as an array ( you can append,
	 delete and replace values).


Since the JSON format can have objects inside other objects
	you can have multiple nested hashtables or arrays and you can
	access these using paths.


### Dependencies


#### OpenSIPS Modules


This module does not depend on other modules.


#### External Libraries or Applications


- *libjson*
				The libjson C library can be downloaded from:
				http://oss.metaparadigm.com/json-c/


### Exported Parameters


#### enable_long_quoting (boolean)


Enable this parameter if your input JSONs contain signed integers which
		do not fit into 4 bytes (e.g. larger than 2147483647, etc.).  If the
		parameter is enabled, 4-byte integers will continue to be returned as
		integers, while larger values will be returned as strings, in order to
		avoid the integer overflow.


*Default value is *false*.*


```opensips title="Set enable_long_quoting parameter"
...
modparam("json", "enable_long_quoting", true)
...
# normalize the "gateway_id" int/string value to be always a string
$var(gateway_id) = "" + $json(body/gateway_id);
...
```


### Exported Pseudo-Variables


#### $json(id)


The `json` variable provides
			methods to access fields in json objects and
			indexes in json arrays.


##### Variable lifetime


The json variables will be available to the
			process that created them from the moment they were
			initialized. They will not reset per message or per
			transaction. If you want to use the on a per message
			basis you should initialize them each time.


##### Accessing the $json(id) variable


The grammar that describes the id is:


id = name(identifier)*


identifier = key | index


key = /string | /$var


index = [integer] | [$var] | []


The "[]" index represents appending to the array.
			It should only be used when trying to set a value and
			not when trying to get one.


Negative indexes can be used to access an array starting
			from the end. So "[-1]" signifies the last element.


IMPORTANT: The id strictly complies to this grammar.
			You should be careful when using spaces because they will
			NOT be ignored. This was done to allow keys that contain
			spaces.


Variables can be used as indexes or keys. Variables
			that will be used as indexes must contain integer values.
			Variables that will be used as keys should contain
			string values.


Trying to get a value from a non-existing path
			(key or value) will return the NULL value and notice
			messages will be placed in the log describing the value
			of the json and the path used.


Trying to replace or insert a value in a
			non-existing path will cause an error in setting the value
			and notice messages will be printed in the log
			describing the value of the json and the path used


```opensips title="Accessing the $json variable"
...
$json(obj1/key) = "value"; #replace or insert the (key,value)
			   #pair into the json object;
			   
$json(matrix1[1][2]) = 1;  #replace the element at index 2 in the element
			   #at index 1 in an array

xlog("$json(name/key1[0][-1]/key2)"); # a more complex example

...
		
```


```opensips title="Iterating through an array using variables"
...

$json(ar1) := "[1,2,3,4]";

$var(i) = 0;

while( $json(ar1[$var(i)]) )
{

	#print each value
	xlog("Found:[$json(ar1[$var(i)])]\n");

	#increment each value
	$json(ar1[$var(i)])  = $json(ar1[$var(i)]) + 1 ;

	$var(i) = $var(i) + 1;

}


...
		
```


##### Traversal


Dynamic traversal of a JSON object or array is possible by using a
			for each statement, similarly to the indexed pseudo variables iteration.
			However, note that indexing the $json variable is not supported in
			any other statements (this refers to indexing the entire variable
			and not to the indexes accepted in the grammar of the *id*).


In order to explicitly iterate over a JSON object keys or values, you can use the
			*.keys* or *.values* suffix for the path
			specified in the *id*.


```opensips title="iteration over $json object keys"
...
$json(foo) := "{\"a\": 1, \"b\": 2, \"c\": 3}";
for ($var(k) in $(json(foo.keys)[*]))
    xlog("$var(k) ");
...
		
```


```opensips title="iteration over $json object values"
...
$json(foo) := "{\"a\": 1, \"b\": 2, \"c\": 3}";
for ($var(v) in $(json(foo.values)[*]))
    xlog("$var(v) ");

# equivalent to:

$json(foo) := "{\"a\": 1, \"b\": 2, \"c\": 3}";
for ($var(v) in $(json(foo)[*]))
    xlog("$var(v) ");
...
		
```


```opensips title="iteration over $json array values"
...
$json(foo) := "[1, 2, 3]";
for ($var(v) in $(json(foo)[*]))
    xlog("$var(v) ");
...
		
```


##### Returned values from $json(id)


If the value specified by the id is an integer
			it will be returned as an integer value.


If the value specified by the id is a string it will
			be returned as a string.


If the value specified by the id is any other
			type of json ( null, boolean, object, array )
			the serialized version of the object will be returned
			as a string value. Using this and the ":="
			operator you can duplicate json objects and put them
			in other json objects ( for string or integer you may
			use the "=" operator).


If the id does not exist a NULL value will be returned.


##### Operators for the $json(id) variable


There are 2 operators available for this variable.


###### The "=" operator


This will cause the value to be taken
				as is and be added to the json object
				( e.g. string value or integer	value ).


Setting a value to NULL will cause it to be
				deleted.


```opensips title="Appending integers to arrays"
...
$json(array1[]) = 1;
...
			
```


```opensips title="Deleting the last element in an array"
...
$json(array1[-1]) = NULL;
...
			
```


```opensips title="Adding a string value to a json object"
...
$json(object1/some_key) = "some_value";
...
			
```


###### The ":=" operator


This will cause the value to be taken
				and interpreted as a json object
				( e.g. this operator should be used to parse
				 json inputs ).


```opensips title="Initializing an array"
...
$json(array1) := "[]";
...
			
```


```opensips title="Setting a boolean or null value"
...
$json(array1[]) := "null";
$json(array1[]) := "true";
$json(array1[]) := "false";
...
			
```


```opensips title="Adding a json to another json"
...

$json(array) := "[1,2,3]";
$json(object) := "{}";
$json(object/array) := $json(array) ;
...
			
```


#### $json_pretty(id)


The `json_pretty` variable has the
			same purpose as the [json](#pv_json) variable,
			but prints the JSON object in a pretty format, adding
			spaces and tabs to make the output more readable.


#### $json_compact(id)


The `json_compact` variable has the
			same purpose as the [json](#pv_json) variable,
			but prints the JSON object in a more compact form,
			without formatting spaces.


#### $json_compact_noescape(id)


The `json_compact_noescape` variable has the
			same purpose as the [json compact](#pv_json_compact) variable,
			printing the JSON object in the compact form, but without
			escaping the slashes.


*NOTICE:* due to the libjson-c library
			limitations, this variable only skips the slashes escaping
			starting with version *0.13* - older versions
			of the library make the variable behave just like the
			[json compact](#pv_json_compact) variable.


```opensips title="Difference between json_compact and json_compact_noescape"
...
$json(obj) := "{}";
$json(obj/path) = "/path/to/some/file";
xlog("The json is: $json_compact(obj)\n");
# will print:
# The json is: {"path":"\/path\/to\/some\/file"}

xlog("The json no escape is: $json_compact_noescape(obj)\n");
# will print:
# The json no escape is: {"path":"/path/to/some/file"}
...
			
```


### Exported Functions


#### json_link($json(dest_id), $json(source_id))


This function can be used to link json objects together.
			This will work simillar to setting a value to an object,
			the only difference is that the second object is not
			copied, only a reference is created.


Changes to any of the objects will be visible in both of
			them.


You can use this method either to create references
			so each time you access the field you don't
			have to go through the full path
			(for speed efficiency and shorter code), or
			if you have an object that must be added to many
			other objects and you don't want to copy it each
			time (space and speed efficiency).


You can think of this object exactly as a reference
			in an object-oriented language. Modifying fields
			referenced by the variable will cause modifications
			in all the objects, BUT modifying the variable itsef
			will not cause any changes to other objects.


WARNING: You should be careful when using references.
			If you accidentally create a circular reference and try
			to get the value from the object you will crash OPENSIPS.


```opensips title="Creating a reference"
...

$json(b) := "[{},{},{}]";

json_link($json(stub), $json(b[0]));

$json(stub/ana) = "are"; #add to the stub
$json(stub/ar) := "[]";
$json(stub/ar[]) = 1;
$json(stub/ar[]) = 2;
$json(stub/ar[]) = 3;

$json(b[0]/ar[0]) = NULL; # delete from the original object

xlog("\nTest link :\n$json(stub)\n$json(b)\n\n");

/*Output:

Test link :
{ "ana": "are", "ar": [ 2, 3 ] }
[ { "ana": "are", "ar": [ 2, 3 ] }, { }, { } ]

*/

$json(stub) = NULL; #delete the stub, no change will happen to the source


xlog("\nTest link :\n$json(stub)\n$json(b)\n\n");

/* Output:

Test link :
<null>
[ { "ana": "are", "ar": [ 2, 3 ] }, { }, { } ]

*/





...
			
```


```opensips title="[LOGICAL ERROR] Creating a circular reference"
...

$json(b) := "[1]";

/* NEVER do this, it is meant only to show where problems might occur  */
json_link($json(b[0]), $json(b)); # replace 1 with a reference to b

xlog("\nTest link :\n$json(stub)\n$json(b)\n\n");

/* this will cause OPENSIPS to crash because it will continuously try
 to get b, then b[0], then b ... */


...
			
```


#### json_merge(main_json_var,patch_json_var,output_var))


The function can be used to patch merge patch_json_var into main_json_var and the output will be populated into the output_var


```opensips title="Using json_merge"
...

$json(val1) := "{}";
$json(val1/test1) = "test_val1";
$json(val1/common_val) = "val_from1";

$json(val2) := "{}";
$json(val2/test2) = "test_val2";
$json(val1/common_val) = "val_from2";

json_merge($json(val1),$json(val2),$var(merged_json));
xlog("we merged and got $var(merged_json) \n");
# will print : 
# we merged and got {"test1":"test_val1","common_val":"val_from2","test2":"test_val2"} 
			
```
<!-- CONTRIBUTORS -->

### License

All documentation files (i.e. .md extension) are licensed under the Creative Common License 4.0
