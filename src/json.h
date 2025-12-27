#ifndef JSON_H
#define JSON_H
#include <stddef.h>

struct json_string {
	size_t length;
	/* NUL-terminated for convenience */
	/* XXX may contain lone surrogates and non-characters */
	char *bytes;
};

struct json_array {
	size_t length;
	struct json_value *elements;
};

struct json_object {
	size_t length;
	/* XXX may contain duplicate names */
	struct json_string *names;
	struct json_value  *values;
};

/* all pointers above are returned by malloc() or realloc() */
/* length fields also hold the capacity */

struct json_value {
	enum {
		JSON_NULL = 1,
		JSON_FALSE,
		JSON_TRUE,
		JSON_NUMBER,
		/* for numbers that can't be represented as `long long' */
		JSON_NUMERIC_STRING,
		JSON_STRING,
		JSON_ARRAY,
		JSON_OBJECT
	} type;
	union {
		long long number;
		struct json_string string;
		struct json_array  array;
		struct json_object object;
	} as;
};

enum json_parse_status {
	JSON_PARSE_SUCCESS,
	JSON_PARSE_OUT_OF_MEMORY,
	JSON_PARSE_UNEXPECTED_SYMBOL,
	JSON_PARSE_INVALID_LITERAL,
	JSON_PARSE_INVALID_NUMBER,
	JSON_PARSE_ILLEGAL_CHAR,
	JSON_PARSE_INVALID_ESCAPE,
	JSON_PARSE_INVALID_ENCODING,
	JSON_PARSE_UNKNOWN_ERROR
};

enum json_parse_status json_parse(const char *, struct json_value *, size_t *);
char *json_stringify(const struct json_value *, int, size_t *);
int json_free(struct json_value *);
#endif
