#include <json.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv) {
	static char buf[1l << 26];
	int err, compact;
	struct json_value in, out;
	size_t len;
	struct json_string *s;
	fread(buf, 1, sizeof buf, stdin);
	err = json_parse(buf, &in, &len);
	fseek(stdin, len, SEEK_SET);
	if (err)
		return err;
	compact = argc > 1 && strncmp(argv[1], "-c", 2) == 0;
	s = &out.as.string;
	s->bytes = json_stringify(&in, compact, &s->length);
	while (!json_free(&in));
	if (!s->bytes)
		return JSON_PARSE_UNKNOWN_ERROR + 1;
	fwrite(s->bytes, 1, s->length, stdout);
	if (compact)
		fputc('\n', stdout);
	out.type = JSON_STRING;
	while (!json_free(&out));
}
