#ifndef new_mod_h
#define new_mod_h

#define MAPPING_DELIM '='

struct ua_mapping {
	str value;
	str translated;
	struct ua_mapping *next;
};

#endif

