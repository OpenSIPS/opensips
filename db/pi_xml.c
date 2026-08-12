/*
 * Small XML DOM adapter for the PI framework.
 *
 * The parser itself is yxml, a small MIT-licensed streaming XML parser.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "../mem/mem.h"
#include "pi_xml.h"
#include "../lib/yxml.h"

#define PI_XML_DOC_MAGIC 0x5049584d

static char *pi_xml_strdup(const char *s)
{
	char *copy = malloc(strlen(s) + 1);
	if (copy) strcpy(copy, s);
	return copy;
}

static void pi_xml_free_node(xmlNodePtr node)
{
	xmlNodePtr child, next;
	xmlAttrPtr attr, attr_next;

	if (!node) return;
	for (child = node->children; child; child = next) {
		next = child->next;
		pi_xml_free_node(child);
	}
	for (attr = node->properties; attr; attr = attr_next) {
		attr_next = attr->next;
		pi_xml_free_node(attr->children);
		free(attr->name);
		free(attr);
	}
	free(node->name);
	free(node->content);
	free(node);
}

static void pi_xml_append_child(xmlNodePtr parent, xmlNodePtr child)
{
	xmlNodePtr *tail;
	child->parent = parent;
	if (!parent->children) {
		parent->children = child;
		return;
	}
	for (tail = &parent->children; *tail; tail = &(*tail)->next);
	*tail = child;
}

static int pi_xml_append_content(xmlNodePtr node, const char *data)
{
	size_t old_len = node->content ? strlen(node->content) : 0;
	size_t add_len = strlen(data);
	char *content = realloc(node->content, old_len + add_len + 1);
	if (!content) return -1;
	memcpy(content + old_len, data, add_len + 1);
	node->content = content;
	return 0;
}

static int pi_xml_add_attr(xmlNodePtr node, const char *name,
		const char *value)
{
	xmlAttrPtr attr, *tail;
	attr = calloc(1, sizeof(*attr));
	if (!attr) return -1;
	attr->name = pi_xml_strdup(name);
	attr->children = calloc(1, sizeof(*attr->children));
	if (!attr->name || !attr->children) {
		free(attr->children);
		free(attr->name);
		free(attr);
		return -1;
	}
	attr->children->content = pi_xml_strdup(value);
	if (!attr->children->content) {
		pi_xml_free_node(attr->children);
		free(attr->name);
		free(attr);
		return -1;
	}
	for (tail = &node->properties; *tail; tail = &(*tail)->next);
	*tail = attr;
	return 0;
}

xmlDocPtr pi_xml_parse_file(const char *filename)
{
	FILE *file;
	long size;
	char *input = NULL, *attrval = NULL;
	size_t pos, attr_len = 0;
	char stack[65536];
	yxml_t parser;
	xmlDocPtr doc = NULL;
	xmlNodePtr current = NULL, node;
	yxml_ret_t ret;

	file = fopen(filename, "rb");
	if (!file) return NULL;
	if (fseek(file, 0, SEEK_END) || (size = ftell(file)) < 0 ||
		fseek(file, 0, SEEK_SET)) goto error;
	input = malloc((size_t)size);
	if (!input || fread(input, 1, (size_t)size, file) != (size_t)size)
		goto error;
	fclose(file);
	file = NULL;

	doc = calloc(1, sizeof(*doc));
	if (!doc) goto error;
	doc->magic = PI_XML_DOC_MAGIC;
	yxml_init(&parser, stack, sizeof(stack));
	for (pos = 0; pos < (size_t)size; pos++) {
		ret = yxml_parse(&parser, (unsigned char)input[pos]);
		if (ret < 0) goto error;
		switch (ret) {
		case YXML_ELEMSTART:
			node = calloc(1, sizeof(*node));
			if (!node) goto error;
			node->name = strndup(parser.elem,
					yxml_symlen(&parser, parser.elem));
			if (!node->name) goto error;
			if (current) pi_xml_append_child(current, node);
			else if (!doc->children) doc->children = node;
			else goto error;
			current = node;
			break;
		case YXML_ATTRSTART:
			free(attrval);
			attrval = calloc(1, 1);
			attr_len = 0;
			if (!attrval) goto error;
			break;
		case YXML_ATTRVAL: {
				size_t len = strlen(parser.data);
				char *value = realloc(attrval, attr_len + len + 1);
				if (!value) goto error;
				memcpy(value + attr_len, parser.data, len + 1);
				attrval = value;
				attr_len += len;
			}
			break;
		case YXML_ATTREND:
			if (!current || pi_xml_add_attr(current, parser.attr, attrval))
				goto error;
			break;
		case YXML_CONTENT:
			if (!current || pi_xml_append_content(current, parser.data))
				goto error;
			break;
		case YXML_ELEMEND:
			if (!current) goto error;
			current = current->parent;
			break;
		default:
			break;
		}
	}
	if (yxml_eof(&parser) < 0 || current) goto error;
	free(attrval);
	free(input);
	return doc;

error:
	if (file) fclose(file);
	free(attrval);
	free(input);
	if (doc) {
		pi_xml_free_node(doc->children);
		free(doc);
	}
	return NULL;
}

char *pi_xml_node_get_content(xmlNodePtr node)
{
	xmlNodePtr child;
	size_t len = 0;
	char *content;

	if (!node) return NULL;
	if (node->content) len = strlen(node->content);
	for (child = node->children; child; child = child->next)
		if (child->content) len += strlen(child->content);
	content = malloc(len + 1);
	if (!content) return NULL;
	content[0] = 0;
	if (node->content) strcat(content, node->content);
	for (child = node->children; child; child = child->next)
		if (child->content) strcat(content, child->content);
	return content;
}

void pi_xml_free(void *ptr)
{
	xmlDocPtr doc = ptr;
	if (!ptr) return;
	if (doc->magic == PI_XML_DOC_MAGIC) {
		pi_xml_free_node(doc->children);
		free(doc);
	} else free(ptr);
}

int pi_xml_strcasecmp(const xmlChar *a, const xmlChar *b)
{
	return strcasecmp(a, b);
}
