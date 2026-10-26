/*
 * Fuzzer for the OpenSIPS script transformation engine (transformations.c):
 * parses a transformation chain from the first input line and applies it to
 * the remaining input bytes as the pseudo-variable value. In production the
 * value is typically SIP-message-derived data, so both the transformation
 * expression and the value are attacker-influenced.
 *
 * Input: "<transformation chain>\n<value bytes>" e.g. "{s.len}\nhello".
 */

#include <stdint.h>
#include <string.h>

#include "../str.h"
#include "../mem/mem.h"
#include "../pvar.h"
#include "../parser/msg_parser.h"
#include "../transformations.h"

#include "../sr_module.h"
#include "../test/fuzz/fuzz_standalone.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
const uint8_t *nl;
str tr_text, val_text;
trans_t *tr = NULL;
char *end;

if (size < 4 || size > 8192)
return 0;

nl = memchr(data, '\n', size);
if (nl == NULL)
return 0;

tr_text.len = nl - data;
if (tr_text.len < 3 || data[0] != '{')
return 0;
/* parse_transformation() expects NUL-terminated input (config-file
 * semantics); production callers pass terminated buffers. */
char expr[8196];
memcpy(expr, data, tr_text.len);
expr[tr_text.len] = '\0';
tr_text.s = expr;
val_text.s = (char *)nl + 1;
val_text.len = size - (nl - data) - 1;

end = parse_transformation(&tr_text, &tr);
if (end == NULL)
return 0; /* rejected expression, valid outcome */

{
struct sip_msg msg = {};
pv_value_t val = {};

val.rs = val_text;
val.flags = PV_VAL_STR;

run_transformations(&msg, tr, &val);

pv_value_destroy(&val);
}

free_transformation(tr);
return 0;
}
