#include <json.h>
#include <stdlib.h>

int
LLVMFuzzerTestOneInput(char *data, size_t size) {
	struct json_value jv;
	char *s;
	size_t n;
	if (size == 0 || data[size-1] != '\0')
		return -1;
	if (json_parse(data, &jv, &n) == 0) {
		if ((s = json_stringify(&jv, 0, &n)))
			free(s);
		if ((s = json_stringify(&jv, 1, &n)))
			free(s);
		json_free(&jv);
	}
	jv.as.string.bytes = data;
	jv.as.string.length = size-1;
	jv.type = JSON_STRING;
	if ((s = json_stringify(&jv, 0, &n)))
		free(s);
	jv.type = JSON_NUMERIC_STRING;
	if ((s = json_stringify(&jv, 0, &n)))
		free(s);
	return 0;
}
