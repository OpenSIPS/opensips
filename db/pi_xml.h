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

xmlDocPtr pi_xml_parse_file(const char *filename);
char *pi_xml_node_get_content(xmlNodePtr node);
void pi_xml_free(void *ptr);
int pi_xml_strcasecmp(const xmlChar *a, const xmlChar *b);

#endif
