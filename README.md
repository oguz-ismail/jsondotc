# Using
This library provides the following functions.
```c
enum json_parse_status json_parse(const char *s, struct json_value *dst, size_t *endp);
```
Parse a JSON value from the NUL-terminated string `s`. Returns `JSON_PARSE_SUCCESS` on success and one of the error codes enumerated in [src/json.h](src/json.h#L49) on failure. If `dst` isn't `NULL` and parse succeeds, `*dst` points to the resulting object. If `endp` isn't `NULL`, `*endp` points to where in `s` parse stopped.

Refer to [src/json.h](src/json.h) for definition and semantics of the type `struct json_value`.
```c
char *json_stringify(const struct json_value *jv, int compact, size_t *lenp);
```
Convert `jv` to string. Returns A NUL-terminated string on success, and `NULL` on failure. If `compact` is non-zero, no decorative whitespace is used. If `lenp` isn't NULL, `*lenp` is the length of the result in bytes.

```c
int json_free(struct json_value *jv);
```
Deallocate all memory associated with `jv`. Returns 1 on success and 0 on failure. On failure `jv` is modified but not broken, so you can try again later.

# Compiling
**src/json.c** should compile with any C99 compiler. **libc** is the only dependency and no extra flags are needed.

Macros below, if defined as non-zero during compilation, change behavior as described.
|Name|Description|
|-|-|
|`JSON_STRINGIFY_ESCAPE_SLASH`|`json_stringify()` escapes slash characters (`/`) embedded in strings.|
|`JSON_STRINGIFY_DONT_VALIDATE`|`json_stringify()` doesn't perform standards conformity checks on strings and numbers.|
|`JSON_FREE_ERASE_STRINGS`|`json_free()` zeroes strings before freeing them.|
