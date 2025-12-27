/* Copyright 2025 Oğuz İsmail Uysal <oguzismailuysal@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <limits.h> /* CHAR_BIT, LLONG_MIN, LLONG_MAX */
#include <stdlib.h> /* malloc(), realloc(), free() */
#include <string.h> /* memcpy(), memset() */
#include "json.h"

#define NUMBER_MAX_LEN (sizeof(long long)*CHAR_BIT * 30103/100000 + 1)

#define ISDIGIT(c) ((c) >= '0' && (c) <= '9')
#define FREE_AND_NULL(p) do { free(p); (p) = NULL;} while (0)
#define SLICE(x, i, n) (((x) >> (i)) & (1ull << (n))-1)
#define MAX(x, y) ((x) > (y) ? (x) : (y))

static void *alloc_stack(size_t *);
static int alloc_string(struct json_string *, size_t *);
static int alloc_array(struct json_array *);
static int alloc_object(struct json_object *);
static int maybe_grow_stack(void *, size_t *, size_t);
static int maybe_grow_string(struct json_string *, size_t *, size_t);
static int maybe_grow_array(struct json_array *);
static int maybe_grow_object(struct json_object *);
static void trim_string(struct json_string *);
static void trim_array(struct json_array *);
static void trim_object(struct json_object *);
static int make_string(struct json_string *, const char *, size_t);

static inline const char *
skip_ws(const char *s) {
	for (; *s == ' ' || *s == '\n' || *s == '\r' || *s == '\t'; s++);
	return s;
}

static int
scan_number(const char *s, size_t *lenp) {
	int ret;
	const char *start = s;
	/* The JSON spec doesn't allow a plus sign or extra zeros in front of
	 * a number. Alternative formats like `0.' and `.5' aren't recognized
	 * either. */
	if (*s == '-')
		s++;
	if (!ISDIGIT(*s))
		return -2;
	if (*s == '0' && ISDIGIT(s[1]))
		return -1;
	ret = 0;
	for (s++; ISDIGIT(*s); s++);
	if (*s == '.') {
		s++;
		if (!ISDIGIT(*s))
			return -1;
		for (s++; ISDIGIT(*s); s++);
		ret = 1;
	}
	if (*s == 'E' || *s == 'e') {
		s++;
		if (*s == '+' || *s == '-')
			s++;
		if (!ISDIGIT(*s))
			return -1;
		for (s++; ISDIGIT(*s); s++);
		ret = 1;
	}
	*lenp = s-start;
	return ret;
}

static int
parse_integer(const char *s, long long *dst, const char **end) {
	int neg, d;
	unsigned long long max, x;
	if ((neg = (*s == '-')))
		s++;
	max = neg ? 0ull-LLONG_MIN : LLONG_MAX;
	for (x = 0; ISDIGIT(*s); s++) {
		d = *s - '0';
		if (x > (max-d)/10)
			return 0;
		x = x*10 + d;
	}
	*dst = neg ? (x < max ? -(long long)x : LLONG_MIN)
		: (long long)x;
	*end = s;
	return 1;
}

static enum json_parse_status
parse_number(const char *s, struct json_value *dst, const char **end) {
	size_t len;
	switch (scan_number(s, &len)) {
	case -2: return JSON_PARSE_UNEXPECTED_SYMBOL;
	case -1: return JSON_PARSE_INVALID_NUMBER;
	/* There is no limit to the magnitude or precision of a JSON number.
	 * strtod() overflows or loses precision when converting extreme
	 * values, and is tied to the locale. So we store each number that
	 * couldn't be converted to a `long long' as a string. */
	case 0:
		if (parse_integer(s, &dst->as.number, end)) {
			dst->type = JSON_NUMBER;
			break;
		}
	case 1:
		if (!make_string(&dst->as.string, s, len))
			return JSON_PARSE_OUT_OF_MEMORY;
		dst->type = JSON_NUMERIC_STRING;
		*end = s+len;
	}
	return JSON_PARSE_SUCCESS;
}

static int
decode_hex4(const char *s, unsigned *dst) {
	int x, i;
	x = 0;
	for (i = 0; i < 4; i++) {
		x *= 16;
		if (s[i] >= '0' && s[i] <= '9')
			x += s[i]-'0';
		else if (s[i] >= 'A' && s[i] <= 'F')
			x += s[i]-'A' + 10;
		else if (s[i] >= 'a' && s[i] <= 'f')
			x += s[i]-'a' + 10;
		else
			return 0;
	}
	*dst = x;
	return 1;
}

static int
parse_escape(const char *s, struct json_string *dst, const char **end) {
	unsigned cp, hi, lo;
	unsigned char *p;
	if (s[1] == 'u') {
		if (!decode_hex4(&s[2], &hi))
			return 0;
		/* No \UXXXXXXXX or \u{...} in JSON. Code points above U+FFFF may
		 * be escaped as a pair of \uXXXX instead, each encoding a Unicode
		 * surrogate. We accept lone surrogates and non-characters in both
		 * raw and escaped forms for flexibility. */
		if (hi >= 0xd800 && hi <= 0xdbff &&
		    s[6] == '\\' && s[7] == 'u' && decode_hex4(&s[8], &lo) &&
		    lo >= 0xdc00 && lo <= 0xdfff) {
			cp = ((SLICE(hi, 0, 10) << 10)|SLICE(lo, 0, 10))+0x10000;
			s += 12;
		}
		else {
			cp = hi;
			s += 6;
		}
	}
	else {
		switch (s[1]) {
		case '\\':
		case '"':
		case '/': cp = s[1]; break;
		case 'b': cp = '\b'; break;
		case 'f': cp = '\f'; break;
		case 'n': cp = '\n'; break;
		case 'r': cp = '\r'; break;
		case 't': cp = '\t'; break;
		default:
			return 0;
		}
		s += 2;
	}
	p = (unsigned char *)dst->bytes + dst->length;
	if (cp < 0x80) {
		*p++ = cp;
	}
	else if (cp < 0x800) {
		*p++ = SLICE(cp, 6, 5)|0xc0;
		*p++ = SLICE(cp, 0, 6)|0x80;
	}
	else if (cp < 0x10000) {
		*p++ = SLICE(cp, 12, 4)|0xe0;
		*p++ = SLICE(cp, 6, 6)|0x80;
		*p++ = SLICE(cp, 0, 6)|0x80;
	}
	else {
		*p++ = SLICE(cp, 18, 3)|0xf0;
		*p++ = SLICE(cp, 12, 6)|0x80;
		*p++ = SLICE(cp, 6, 6)|0x80;
		*p++ = SLICE(cp, 0, 6)|0x80;
	}
	dst->length = (char *)p - dst->bytes;
	*end = s;
	return 1;
}

/* adapted from https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c */
static int
utf8_char_length(const char *p) {
	const unsigned char *s = (const unsigned char *)p;
	if (*s < 0x80) {
		return 1;
	}
	else if ((s[0] & 0xe0) == 0xc0) {
		if ((s[1] & 0xc0) != 0x80 ||
		    /* overlong? */
		    (s[0] & 0xfe) == 0xc0)
			return 0;
		return 2;
	}
	else if ((s[0] & 0xf0) == 0xe0) {
		if ((s[1] & 0xc0) != 0x80 ||
		    (s[2] & 0xc0) != 0x80 ||
		    /* overlong? */
		    (s[0] == 0xe0 && (s[1] & 0xe0) == 0x80))
			return 0;
		return 3;
	}
	else if ((s[0] & 0xf8) == 0xf0) {
		if ((s[1] & 0xc0) != 0x80 ||
		    (s[2] & 0xc0) != 0x80 ||
		    (s[3] & 0xc0) != 0x80 ||
		    /* overlong? */
		    (s[0] == 0xf0 && (s[1] & 0xf0) == 0x80) ||
		    /* > U+10FFFF? */
		    (s[0] == 0xf4 && s[1] > 0x8f) || s[0] > 0xf4)
			return 0;
		return 4;
	}
	else {
		return 0;
	}
}

#define APPEND_BYTES(dst, src, n) do { \
	memcpy((dst)->bytes+(dst)->length, src, n); \
	(dst)->length += (n); \
} while (0)

static enum json_parse_status
parse_string(const char *s, struct json_string *dst, const char **end) {
	size_t n, clen;
	enum json_parse_status err;
	const char *lit = s;
	if (!alloc_string(dst, &n))
		return JSON_PARSE_OUT_OF_MEMORY;
	dst->length = 0;
	err = JSON_PARSE_SUCCESS;
	for (; ; )
		if (*s == '\\' || *s == '"') {
			/* escaped character | '\0' */
			if (!maybe_grow_string(dst, &n, s-lit + 4)) {
				err = JSON_PARSE_OUT_OF_MEMORY;
				break;
			}
			APPEND_BYTES(dst, lit, s-lit);
			if (*s == '"') {
				s++;
				break;
			}
			else if (!parse_escape(s, dst, &s)) {
				err = JSON_PARSE_INVALID_ESCAPE;
				break;
			}
			lit = s;
		}
		/* C0 control codes must be escaped */
		else if ((unsigned char)*s < ' ') {
			err = JSON_PARSE_ILLEGAL_CHAR;
			break;
		}
		else if (!(clen = utf8_char_length(s))) {
			err = JSON_PARSE_INVALID_ENCODING;
			break;
		}
		else {
			s += clen;
		}
	if (err) {
		free(dst->bytes);
	}
	else {
		dst->bytes[dst->length] = '\0';
		trim_string(dst);
	}
	*end = s;
	return err;
}

enum json_parse_status
json_parse(const char *s, struct json_value *dst, size_t *lenp) {
	struct json_value **stk, x;
	size_t n, i;
	enum json_parse_status err;
	struct json_array  *arr;
	struct json_object *obj;
	const char *start = s;
	if (!(stk = alloc_stack(&n))) {
		if (lenp)
			*lenp = 0;
		return JSON_PARSE_OUT_OF_MEMORY;
	}
	i = 0;
	x.type = 0;
	stk[i] = &x;
parse_value:
	switch (*(s = skip_ws(s))) {
	case 'n':
		if (s[1] != 'u' || s[2] != 'l' || s[3] != 'l') {
			err = JSON_PARSE_INVALID_LITERAL;
			goto error;
		}
		s += 4;
		stk[i]->type = JSON_NULL;
		break;
	case 'f':
		if (s[1] != 'a' || s[2] != 'l' || s[3] != 's' || s[4] != 'e') {
			err = JSON_PARSE_INVALID_LITERAL;
			goto error;
		}
		s += 5;
		stk[i]->type = JSON_FALSE;
		break;
	case 't':
		if (s[1] != 'r' || s[2] != 'u' || s[3] != 'e') {
			err = JSON_PARSE_INVALID_LITERAL;
			goto error;
		}
		s += 4;
		stk[i]->type = JSON_TRUE;
		break;
	default:
		if ((err = parse_number(s, stk[i], &s)))
			goto error;
		/* parse_number() assigns the type */
		break;
	case '"':
		if ((err = parse_string(s+1, &stk[i]->as.string, &s)))
			goto error;
		stk[i]->type = JSON_STRING;
		break;
	case '[':
		arr = &stk[i]->as.array;
		arr->elements = NULL;
		arr->length   = 0;
		stk[i]->type = JSON_ARRAY;
		if (*(s = skip_ws(s+1)) == ']') {
			s++;
			break;
		}
		if (!alloc_array(arr) || !maybe_grow_stack(&stk, &n, i)) {
			err = JSON_PARSE_OUT_OF_MEMORY;
			goto error;
		}
		goto parse_element;
	case '{':
		obj = &stk[i]->as.object;
		obj->names  = NULL;
		obj->values = NULL;
		obj->length = 0;
		stk[i]->type = JSON_OBJECT;
		if (*(s = skip_ws(s+1)) == '}') {
			s++;
			break;
		}
		if (!alloc_object(obj) || !maybe_grow_stack(&stk, &n, i)) {
			err = JSON_PARSE_OUT_OF_MEMORY;
			goto error;
		}
		goto parse_member;
	}
pop:
	if (i == 0) {
		if (dst)
			*dst = x;
		if (lenp)
			/* trailing whitespace is part of a complete JSON value */
			*lenp = skip_ws(s)-start;
		free(stk);
		return JSON_PARSE_SUCCESS;
	}
	i--;
	switch (stk[i]->type) {
	case JSON_ARRAY:
		arr = &stk[i]->as.array;
		switch (*(s = skip_ws(s))) {
		case ',':
			if (!maybe_grow_array(arr)) {
				err = JSON_PARSE_OUT_OF_MEMORY;
				goto error;
			}
			s++;
parse_element:
			i++;
			stk[i] = &arr->elements[arr->length++];
			stk[i]->type = 0;
			goto parse_value;
		case ']':
			trim_array(arr);
			s++;
			goto pop;
		default:
			err = JSON_PARSE_UNEXPECTED_SYMBOL;
			goto error;
		}
	case JSON_OBJECT:
		obj = &stk[i]->as.object;
		switch (*(s = skip_ws(s))) {
		case ',':
			if (!maybe_grow_object(obj)) {
				err = JSON_PARSE_OUT_OF_MEMORY;
				goto error;
			}
			s++;
parse_member:
			if (*(s = skip_ws(s)) != '"') {
				err = JSON_PARSE_UNEXPECTED_SYMBOL;
				goto error;
			}
			if ((err = parse_string(s+1, &obj->names[obj->length], &s)))
				goto error;
			i++;
			stk[i] = &obj->values[obj->length++];
			stk[i]->type = 0;
			if (*(s = skip_ws(s)) != ':') {
				err = JSON_PARSE_UNEXPECTED_SYMBOL;
				goto error;
			}
			s++;
			goto parse_value;
		case '}':
			trim_object(obj);
			s++;
			goto pop;
		default:
			err = JSON_PARSE_UNEXPECTED_SYMBOL;
			goto error;
		}
	default:
		err = JSON_PARSE_UNKNOWN_ERROR;
	}
error:
	/* nothing's exposed to the caller yet, use plain free() */
	for (; ; ) {
		switch (stk[i]->type) {
		case JSON_STRING:
		case JSON_NUMERIC_STRING:
			free(stk[i]->as.string.bytes);
		default:
			break;
		case JSON_ARRAY:
			arr = &stk[i]->as.array;
			if (!arr->length) {
				free(arr->elements);
				break;
			}
			i++;
			arr->length--;
			stk[i] = &arr->elements[arr->length];
			continue;
		case JSON_OBJECT:
			obj = &stk[i]->as.object;
			if (!obj->length) {
				free(obj->names);
				free(obj->values);
				break;
			}
			i++;
			obj->length--;
			free(obj->names[obj->length].bytes);
			stk[i] = &obj->values[obj->length];
			continue;
		}
		if (i == 0)
			break;
		stk[i]->type = 0;
		i--;
	}
	free(stk);
	if (lenp)
		*lenp = s-start;
	return err;
}

/* json_stringify() assumes this adds exactly N bytes to S */
#define INDENT(s, n) do { \
	memset((s)->bytes+(s)->length, '\t', n); \
	(s)->length += (n); \
} while (0)

#define PRINT_LITERAL(s, lit) APPEND_BYTES(s, lit, (sizeof (lit))-1)

static void
print_integer(struct json_string *s, long long x) {
	unsigned long long abs;
	char buf[NUMBER_MAX_LEN], *p;
	abs = x < 0 ? 0ull-x : x;
	p = buf+(sizeof buf);
	do {
		*--p = abs%10 + '0';
		abs /= 10;
	}
	while (abs);
	if (x < 0)
		*--p = '-';
	APPEND_BYTES(s, p, (sizeof buf)-(p-buf));
}

static void
print_escape(struct json_string *s, unsigned char c) {
	static const char *hex = "0123456789abcdef";
	char *p = s->bytes + s->length;
	*p++ = '\\';
	switch (c) {
	case '\b': *p++ = 'b'; break;
	case '\f': *p++ = 'f'; break;
	case '\n': *p++ = 'n'; break;
	case '\r': *p++ = 'r'; break;
	case '\t': *p++ = 't'; break;
	case '\\': case '"': case '/':
		*p++ = c;
		break;
	default:
		*p++ = 'u';
		*p++ = '0';
		*p++ = '0';
		*p++ = hex[c/16];
		*p++ = hex[c%16];
	}
	s->length = p - s->bytes;
}

static int
print_string(struct json_string *buf, size_t *n,
		const struct json_string *str) {
	size_t i, lit, clen;
	const char *s = str->bytes;
	buf->bytes[buf->length++] = '"';
	for (lit = i = 0; ; )
		if (i == str->length || (unsigned char)s[i] < ' ' ||
#if JSON_STRINGIFY_ESCAPE_SLASH
				s[i] == '/' ||
#endif
				s[i] == '"' || s[i] == '\\') {
			/* escape sequence | '"' [ ':' space ] */
			if (!maybe_grow_string(buf, n, i-lit + 6))
				return 0;
			APPEND_BYTES(buf, s+lit, i-lit);
			if (i == str->length)
				break;
			print_escape(buf, s[i++]);
			lit = i;
		}
		else {
#if JSON_STRINGIFY_DONT_VALIDATE
			i++;
#else
			if (!(clen = utf8_char_length(&s[i])))
				return 0;
			i += clen;
#endif
		}
	buf->bytes[buf->length++] = '"';
	return 1;
}

char *
json_stringify(const struct json_value *x, int compact, size_t *lenp) {
	struct json_string s;
	size_t cap;
	const struct json_value **stk, *next;
	size_t n, i;
	const struct json_string *str;
	const struct json_array  *arr;
	const struct json_object *obj;
	size_t len;
	stk = NULL;
	if (!alloc_string(&s, &cap) || !(stk = alloc_stack(&n)))
		goto error;
	s.length = 0;
	i = 0;
	stk[i] = x;
print_value:
	/* number | '{' [ '\n' indentation ] '"' */
	if (!maybe_grow_string(&s, &cap,
				compact ? NUMBER_MAX_LEN : MAX(i+4, NUMBER_MAX_LEN)))
		goto error;
	switch (stk[i]->type) {
	case JSON_NULL:
		PRINT_LITERAL(&s, "null");
		break;
	case JSON_FALSE:
		PRINT_LITERAL(&s, "false");
		break;
	case JSON_TRUE:
		PRINT_LITERAL(&s, "true");
		break;
	case JSON_NUMBER:
		print_integer(&s, stk[i]->as.number);
		break;
	case JSON_NUMERIC_STRING:
		str = &stk[i]->as.string;
		if (
#if !JSON_STRINGIFY_DONT_VALIDATE
				scan_number(str->bytes, &len) < 0 || len != str->length ||
#endif
				!maybe_grow_string(&s, &cap, str->length))
			goto error;
		APPEND_BYTES(&s, str->bytes, str->length);
		break;
	case JSON_STRING:
		if (!print_string(&s, &cap, &stk[i]->as.string))
			goto error;
		break;
	case JSON_ARRAY:
		arr = &stk[i]->as.array;
		if (!arr->length) {
			PRINT_LITERAL(&s, "[]");
			break;
		}
		if (!maybe_grow_stack(&stk, &n, i))
			goto error;
		i++;
		s.bytes[s.length++] = '[';
		if (!compact) {
			s.bytes[s.length++] = '\n';
			INDENT(&s, i);
		}
		stk[i] = arr->elements;
		goto print_value;
	case JSON_OBJECT:
		/* Don't check NAMES, VALUES, BYTES, or ELEMENTS. The caller is
		 * responsible for ensuring the internal consistency of the input.
		 * If there is a bug in his code, a core dump will provide more
		 * information about it than we can. */
		obj = &stk[i]->as.object;
		if (!obj->length) {
			PRINT_LITERAL(&s, "{}");
			break;
		}
		if (!maybe_grow_stack(&stk, &n, i))
			goto error;
		i++;
		s.bytes[s.length++] = '{';
		if (!compact) {
			s.bytes[s.length++] = '\n';
			INDENT(&s, i);
		}
		stk[i] = obj->values;
		goto print_member;
	default:
		goto error;
	}
pop:
	/* ',' [ '\n' indentation ] '"' */
	if (!maybe_grow_string(&s, &cap, compact ? 2 : i+3))
		goto error;
	if (i == 0) {
		free(stk);
		if (!compact)
			s.bytes[s.length++] = '\n';
		s.bytes[s.length] = '\0';
		if (lenp)
			*lenp = s.length;
		return s.bytes;
	}
	next = stk[i]+1;
	i--;
	switch (stk[i]->type) {
	case JSON_ARRAY:
		arr = &stk[i]->as.array;
		if (next == &arr->elements[arr->length]) {
			if (!compact) {
				s.bytes[s.length++] = '\n';
				INDENT(&s, i);
			}
			s.bytes[s.length++] = ']';
			goto pop;
		}
		i++;
		s.bytes[s.length++] = ',';
		if (!compact) {
			s.bytes[s.length++] = '\n';
			INDENT(&s, i);
		}
		stk[i] = next;
		goto print_value;
	case JSON_OBJECT:
		obj = &stk[i]->as.object;
		if (next == &obj->values[obj->length]) {
			if (!compact) {
				s.bytes[s.length++] = '\n';
				INDENT(&s, i);
			}
			s.bytes[s.length++] = '}';
			goto pop;
		}
		i++;
		s.bytes[s.length++] = ',';
		if (!compact) {
			s.bytes[s.length++] = '\n';
			INDENT(&s, i);
		}
		stk[i] = next;
print_member:
		str = &obj->names[stk[i] - obj->values];
		if (!print_string(&s, &cap, str))
			goto error;
		s.bytes[s.length++] = ':';
		if (!compact)
			s.bytes[s.length++] = ' ';
		goto print_value;
	default:;
	}
error:
	free(s.bytes);
	free(stk);
	return NULL;
}

static void
free_string(struct json_string *s) {
#if JSON_FREE_ERASE_STRINGS
	memset(s->bytes, 0, s->length);
#endif
	s->length = 0;
	FREE_AND_NULL(s->bytes);
}

int
json_free(struct json_value *x) {
	struct json_value **stk;
	size_t n, i;
	struct json_array  *arr;
	struct json_object *obj;
	if (!(stk = alloc_stack(&n)))
		return 0;
	i = 0;
	stk[i] = x;
free_value:
	switch (stk[i]->type) {
	case JSON_STRING:
	case JSON_NUMERIC_STRING:
		free_string(&stk[i]->as.string);
	default:
		break;
	case JSON_ARRAY:
		arr = &stk[i]->as.array;
		if (!arr->length)
			break;
		if (!maybe_grow_stack(&stk, &n, i))
			goto error;
		goto free_element;
	case JSON_OBJECT:
		obj = &stk[i]->as.object;
		if (!obj->length)
			break;
		if (!maybe_grow_stack(&stk, &n, i))
			goto error;
		goto free_member;
	}
pop:
	stk[i]->type = 0;
	if (i == 0) {
		free(stk);
		return 1;
	}
	i--;
	switch (stk[i]->type) {
	case JSON_ARRAY:
		arr = &stk[i]->as.array;
		arr->length--;
		if (!arr->length) {
			FREE_AND_NULL(arr->elements);
			goto pop;
		}
free_element:
		i++;
		stk[i] = &arr->elements[arr->length-1];
		goto free_value;
	case JSON_OBJECT:
		obj = &stk[i]->as.object;
		free_string(&obj->names[obj->length-1]);
		obj->length--;
		if (!obj->length) {
			FREE_AND_NULL(obj->names);
			FREE_AND_NULL(obj->values);
			goto pop;
		}
free_member:
		i++;
		stk[i] = &obj->values[obj->length-1];
		goto free_value;
	default:;
	}
error:
	free(stk);
	return 0;
}

#define STACK_INIT_CAP  (1 << 2)
#define STRING_INIT_CAP (1 << 5)
#define ARRAY_INIT_CAP  (1 << 3)
#define OBJECT_INIT_CAP (1 << 3)

#define ALLOC_ARRAY(x, n) ((x) = malloc((n)*(sizeof (x)[0])))
#define REALLOC_ARRAY(x, n) (realloc((x), (n)*(sizeof (x)[0])))

static void *
alloc_stack(size_t *n) {
	struct json_value **p;
	if (ALLOC_ARRAY(p, STACK_INIT_CAP))
		*n = STACK_INIT_CAP;
	return p;
}

static int
alloc_string(struct json_string *s, size_t *n) {
	if (!ALLOC_ARRAY(s->bytes, STRING_INIT_CAP))
		return 0;
	*n = STRING_INIT_CAP;
	return 1;
}

static int
alloc_array(struct json_array *arr) {
	return ALLOC_ARRAY(arr->elements, ARRAY_INIT_CAP) != NULL;
}

static int
alloc_object(struct json_object *obj) {
	if (!ALLOC_ARRAY(obj->names,  OBJECT_INIT_CAP))
		return 0;
	if (!ALLOC_ARRAY(obj->values, OBJECT_INIT_CAP)) {
		FREE_AND_NULL(obj->names);
		return 0;
	}
	return 1;
}

static int
maybe_grow_stack(void *p, size_t *n, size_t off) {
	void *new;
	// this is so json_stringify() can take a `const struct json_value *'
	const struct json_value ***old = p;
	if (off+1 >= *n) {
		if (!(new = REALLOC_ARRAY(*old, 2*(*n))))
			return 0;
		*old = new;
		*n *= 2;
	}
	return 1;
}

static inline int
maybe_grow_string(struct json_string *s, size_t *n, size_t add) {
	void *p;
	size_t cap = *n;
	size_t need = s->length+add+1;
	if (need > cap) {
		while ((cap *= 2) < need);
		if (!(p = REALLOC_ARRAY(s->bytes, cap)))
			return 0;
		s->bytes = p;
		*n = cap;
	}
	return 1;
}

static int
maybe_grow_array(struct json_array *arr) {
	void *p;
	size_t len = arr->length;
	if (len >= ARRAY_INIT_CAP && !(len & (len-1))) {
		if (!(p = REALLOC_ARRAY(arr->elements, 2*len)))
			return 0;
		arr->elements = p;
	}
	return 1;
}

static int
maybe_grow_object(struct json_object *obj) {
	void *p;
	size_t len = obj->length;
	if (len >= OBJECT_INIT_CAP && !(len & (len-1))) {
		if (!(p = REALLOC_ARRAY(obj->names,  2*len)))
			return 0;
		obj->names = p;
		if (!(p = REALLOC_ARRAY(obj->values, 2*len)))
			return 0;
		obj->values = p;
	}
	return 1;
}

static void
trim_string(struct json_string *s) {
	void *p;
	if ((p = REALLOC_ARRAY(s->bytes, s->length+1)))
		s->bytes = p;
}

static void
trim_array(struct json_array *arr) {
	void *p;
	if ((p = REALLOC_ARRAY(arr->elements, arr->length)))
		arr->elements = p;
}

static void
trim_object(struct json_object *obj) {
	void *p;
	if ((p = REALLOC_ARRAY(obj->names,  obj->length)))
		obj->names  = p;
	if ((p = REALLOC_ARRAY(obj->values, obj->length)))
		obj->values = p;
}

static int
make_string(struct json_string *s, const char *src, size_t len) {
	if (!ALLOC_ARRAY(s->bytes, len+1))
		return 0;
	memcpy(s->bytes, src, len);
	s->bytes[len] = '\0';
	s->length = len;
	return 1;
}
