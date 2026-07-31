/* Lightweight XML DOM compatibility layer used by the PI framework parser. */
#ifndef _PI_XML_H_
#define _PI_XML_H_

typedef char xmlChar;

typedef struct pi_xml_node *xmlNodePtr;
typedef struct pi_xml_attr *xmlAttrPtr;
typedef struct pi_xml_doc *xmlDocPtr;

struct pi_xml_attr {
	char *name;
	xmlNodePtr children;
	xmlAttrPtr next;
};

struct pi_xml_node {
	char *name;
	char *content;
	xmlNodePtr children;
	xmlNodePtr next;
	xmlNodePtr parent;
	xmlAttrPtr properties;
};

struct pi_xml_doc {
	unsigned magic;
	xmlNodePtr children;
};

xmlDocPtr xmlParseFile(const char *filename);
char *xmlNodeGetContent(xmlNodePtr node);
void xmlFree(void *ptr);
int xmlStrcasecmp(const xmlChar *a, const xmlChar *b);

#endif
