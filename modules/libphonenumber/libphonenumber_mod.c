#include "../../sr_module.h"
#include "libphonenumber.h"

#define OUT_BUFFER_SIZE 32
#define FN_SUCCESS 1
#define FN_FAILURE -1

static int fixup_check_out_var(void **param);

static int w_convert_alpha_characters_in_number(struct sip_msg *msg,
                                                str *number,
                                                pv_spec_t *out_var);
static int w_format(struct sip_msg *msg, str *number, int *number_format,
                    pv_spec_t *out_var, str *default_region);

static int w_format_in_original_format(struct sip_msg *msg, str *number,
                                       str *region_calling_from,
                                       pv_spec_t *out_var, str *default_region);
static int w_format_national_number_with_carrier_code(struct sip_msg *msg,
                                                      str *number,
                                                      str *carrier_code,
                                                      pv_spec_t *out_var,
                                                      str *default_region);
static int w_format_national_number_with_preferred_carrier_code(
    struct sip_msg *msg, str *number, str *preferred_carrier_code,
    pv_spec_t *out_var, str *default_region);

static int w_format_number_for_mobile_dialing(struct sip_msg *msg, str *number,
                                              str *region_calling_from,
                                              int *with_formatting,
                                              pv_spec_t *out_var,
                                              str *default_region);
static int w_format_out_of_country_calling_number(struct sip_msg *msg,
                                                  str *number,
                                                  str *calling_from,
                                                  pv_spec_t *out_var,
                                                  str *default_region);
static int w_format_out_of_country_keeping_alpha_chars(struct sip_msg *msg,
                                                       str *number,
                                                       str *calling_from,
                                                       pv_spec_t *out_var,
                                                       str *default_region);
static int w_get_country_code_for_region(struct sip_msg *msg, str *region_code,
                                         pv_spec_t *out_var);
static int w_get_country_mobile_token(struct sip_msg *msg,
                                      int *country_calling_code,
                                      pv_spec_t *out_var);
static int w_get_length_of_geographical_area_code(struct sip_msg *msg,
                                                  str *number,
                                                  pv_spec_t *out_var,
                                                  str *default_region);
static int w_get_length_of_national_destination_code(struct sip_msg *msg,
                                                     str *number,
                                                     pv_spec_t *out_var,
                                                     str *default_region);
static int w_get_national_significant_number(struct sip_msg *msg, str *number,
                                             pv_spec_t *out_var,
                                             str *default_region);
static int w_get_ndd_prefix_for_region(struct sip_msg *msg, str *region_code,
                                       int *strip_non_digits,
                                       pv_spec_t *out_var);
static int w_get_number_type(struct sip_msg *msg, str *number,
                             pv_spec_t *out_var, str *default_region);

static int w_get_region_code_for_country_code(struct sip_msg *msg,
                                              int *country_code,
                                              pv_spec_t *out_var);
static int w_get_region_code_for_number(struct sip_msg *msg, str *number,
                                        pv_spec_t *out_var,
                                        str *default_region);
static int w_is_alpha_number(struct sip_msg *msg, str *number);
static int w_is_nanpa_country(struct sip_msg *msg, str *region_code);
static int w_is_number_match(struct sip_msg *msg, str *number1, str *number2,
                             str *default_region1, str *default_region2);
static int w_is_possible_number(struct sip_msg *msg, str *number,
                                str *default_region);
static int w_is_possible_number_for_string(struct sip_msg *msg, str *number,
                                           str *region_dialing_from);
static int w_is_valid_number(struct sip_msg *msg, str *number,
                             str *default_region);
static int w_is_valid_number_for_region(struct sip_msg *msg, str *number,
                                        str *region, str *default_region);
static int w_normalize_diallable_chars_only(struct sip_msg *msg, str *number,
                                            pv_spec_t *out_var);
static int w_normalize_digits_only(struct sip_msg *msg, str *number,
                                   pv_spec_t *out_var);

static cmd_export_t cmds[] = {
    {"pn_convert_alpha_characters_in_number",
     (cmd_function)w_convert_alpha_characters_in_number,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_format",
     (cmd_function)w_format,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_INT, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_format_in_original_format",
     (cmd_function)w_format_in_original_format,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_format_national_number_with_carrier_code",
     (cmd_function)w_format_national_number_with_carrier_code,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_format_national_number_with_preferred_carrier_code",
     (cmd_function)w_format_national_number_with_preferred_carrier_code,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_format_number_for_mobile_dialing",
     (cmd_function)w_format_number_for_mobile_dialing,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_INT, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_format_out_of_country_calling_number",
     (cmd_function)w_format_out_of_country_calling_number,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_format_out_of_country_keeping_alpha_chars",
     (cmd_function)w_format_out_of_country_keeping_alpha_chars,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_country_code_for_region",
     (cmd_function)w_get_country_code_for_region,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_country_mobile_token",
     (cmd_function)w_get_country_mobile_token,
     {{CMD_PARAM_INT, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_length_of_geographical_area_code",
     (cmd_function)w_get_length_of_geographical_area_code,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_length_of_national_destination_code",
     (cmd_function)w_get_length_of_national_destination_code,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_national_significant_number",
     (cmd_function)w_get_national_significant_number,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_ndd_prefix_for_region",
     (cmd_function)w_get_ndd_prefix_for_region,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_INT, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_number_type",
     (cmd_function)w_get_number_type,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_region_code_for_country_code",
     (cmd_function)w_get_region_code_for_country_code,
     {{CMD_PARAM_INT, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_get_region_code_for_number",
     (cmd_function)w_get_region_code_for_number,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_is_alpha_number",
     (cmd_function)w_is_alpha_number,
     {{CMD_PARAM_STR, 0, 0}, {0, 0, 0}},
     ALL_ROUTES},
    {"pn_is_nanpa_country",
     (cmd_function)w_is_nanpa_country,
     {{CMD_PARAM_STR, 0, 0}, {0, 0, 0}},
     ALL_ROUTES},
    {"pn_is_number_match",
     (cmd_function)w_is_number_match,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_is_possible_number",
     (cmd_function)w_is_possible_number,
     {{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}},
     ALL_ROUTES},
    {"pn_is_possible_number_for_string",
     (cmd_function)w_is_possible_number_for_string,
     {{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR, 0, 0}, {0, 0, 0}},
     ALL_ROUTES},
    {"pn_is_valid_number",
     (cmd_function)w_is_valid_number,
     {{CMD_PARAM_STR, 0, 0}, {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0}, {0, 0, 0}},
     ALL_ROUTES},
    {"pn_is_valid_number_for_region",
     (cmd_function)w_is_valid_number_for_region,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_STR | CMD_PARAM_OPT, 0, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_normalize_diallable_chars_only",
     (cmd_function)w_normalize_diallable_chars_only,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {"pn_normalize_digits_only",
     (cmd_function)w_normalize_digits_only,
     {{CMD_PARAM_STR, 0, 0},
      {CMD_PARAM_VAR, fixup_check_out_var, 0},
      {0, 0, 0}},
     ALL_ROUTES},
    {0, 0, {{0, 0, 0}}, 0}};

struct module_exports exports = {
    "phonenumer",     /* module's name */
    MOD_TYPE_DEFAULT, /* class of this module */
    MODULE_VERSION,   /* module's version */
    DEFAULT_DLFLAGS,  /* dlopen flags */
    0,                /* load function */
    0,                /* OpenSIPS module dependencies */
    cmds,             /* exported functions */
    0,                /* exported async functions */
    0,                /* param exports */
    0,                /* exported statistics */
    0,                /* exported MI functions */
    0,                /* exported pseudo-variables */
    0,                /* exported transformations */
    0,                /* extra processes */
    0,                /* module pre-initialization function */
    0,                /* module initialization function */
    0,                /* reply processing function */
    0,                /* destroy function */
    0,                /* per-child init function */
    0                 /* reload confirm function */
};

static int fixup_check_out_var(void **param) {
  if (((pv_spec_t *)*param)->setf == NULL) {
    LM_ERR("Output parameter is not writeable variable\n");
    return E_SCRIPT;
  }
  return 0;
}

static int set_out_string(struct sip_msg *msg, pv_spec_t *out_var, char *data,
                          ssize_t len) {
  if (len <= 0)
    return FN_FAILURE;

  pv_value_t out_val;
  out_val.rs.s = data;
  out_val.rs.len = len;
  out_val.flags = PV_VAL_STR;

  if (pv_set_value(msg, out_var, 0, &out_val) != 0)
    return FN_FAILURE;
  return FN_SUCCESS;
}

static int set_out_int(struct sip_msg *msg, pv_spec_t *out_var, int data) {
  pv_value_t out_val;
  out_val.ri = data;
  out_val.flags = PV_VAL_INT | PV_TYPE_INT;

  if (pv_set_value(msg, out_var, 0, &out_val) != 0)
    return FN_FAILURE;
  return FN_SUCCESS;
}

static int w_convert_alpha_characters_in_number(struct sip_msg *msg,
                                                str *number,
                                                pv_spec_t *out_var) {
  char res[OUT_BUFFER_SIZE];
  const int len =
      convert_alpha_characters_in_number(number->s, res, sizeof(res));
  return set_out_string(msg, out_var, res, len);
}

/* number_format:
 *   0 - E164
 *   1 - International
 *   2 - National
 *   3 - RFC3966
 */
static int w_format(struct sip_msg *msg, str *number, int *number_format,
                    pv_spec_t *out_var, str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = format(number->s, *number_format, res, sizeof(res),
                         default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_format_in_original_format(struct sip_msg *msg, str *number,
                                       str *region_calling_from,
                                       pv_spec_t *out_var,
                                       str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = format_in_original_format(
      number->s, region_calling_from->s, res, sizeof(res),
      default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_format_national_number_with_carrier_code(struct sip_msg *msg,
                                                      str *number,
                                                      str *carrier_code,
                                                      pv_spec_t *out_var,
                                                      str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = format_national_number_with_carrier_code(
      number->s, carrier_code->s, res, sizeof(res),
      default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_format_national_number_with_preferred_carrier_code(
    struct sip_msg *msg, str *number, str *preferred_carrier_code,
    pv_spec_t *out_var, str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = format_national_number_with_preferred_carrier_code(
      number->s, preferred_carrier_code->s, res, sizeof(res),
      default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_format_number_for_mobile_dialing(struct sip_msg *msg, str *number,
                                              str *region_calling_from,
                                              int *with_formatting,
                                              pv_spec_t *out_var,
                                              str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = format_number_for_mobile_dialing(
      number->s, region_calling_from->s, *with_formatting, res, sizeof(res),
      default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_format_out_of_country_calling_number(struct sip_msg *msg,
                                                  str *number,
                                                  str *calling_from,
                                                  pv_spec_t *out_var,
                                                  str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = format_out_of_country_calling_number(
      number->s, calling_from->s, res, sizeof(res),
      default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_format_out_of_country_keeping_alpha_chars(struct sip_msg *msg,
                                                       str *number,
                                                       str *calling_from,
                                                       pv_spec_t *out_var,
                                                       str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = format_out_of_country_keeping_alpha_chars(
      number->s, calling_from->s, res, sizeof(res),
      default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_get_country_code_for_region(struct sip_msg *msg, str *region_code,
                                         pv_spec_t *out_var) {
  int code = get_country_code_for_region(region_code->s);
  int ret = set_out_int(msg, out_var, code);
  return ret;
}

static int w_get_country_mobile_token(struct sip_msg *msg,
                                      int *country_calling_code,
                                      pv_spec_t *out_var) {
  char res[OUT_BUFFER_SIZE];
  const int len =
      get_country_mobile_token(*country_calling_code, res, sizeof(res));
  return set_out_string(msg, out_var, res, len);
}

static int w_get_length_of_geographical_area_code(struct sip_msg *msg,
                                                  str *number,
                                                  pv_spec_t *out_var,
                                                  str *default_region) {
  int len = get_length_of_geographical_area_code(
      number->s, default_region ? default_region->s : DEFAULT_REGION);
  return set_out_int(msg, out_var, len);
}

static int w_get_length_of_national_destination_code(struct sip_msg *msg,
                                                     str *number,
                                                     pv_spec_t *out_var,
                                                     str *default_region) {
  int len = get_length_of_national_destination_code(
      number->s, default_region ? default_region->s : DEFAULT_REGION);
  return set_out_int(msg, out_var, len);
}

static int w_get_national_significant_number(struct sip_msg *msg, str *number,
                                             pv_spec_t *out_var,
                                             str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = get_national_significant_number(
      number->s, res, sizeof(res),
      default_region ? default_region->s : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_get_ndd_prefix_for_region(struct sip_msg *msg, str *region_code,
                                       int *strip_non_digits,
                                       pv_spec_t *out_var) {
  char res[OUT_BUFFER_SIZE];
  const int len = get_ndd_prefix_for_region(region_code->s, *strip_non_digits,
                                            res, sizeof(res));
  return set_out_string(msg, out_var, res, len);
}

/*
 * out_var:
 *   -1 - Parsing error
 *    0 - Fixed line
 *    1 - Mobile
 *    2 - Fixed line or mobile
 *    3 - Toll free
 *    4 - Premium rate
 *    5 - Shared cost
 *    6 - VoIP
 *    7 - Personal number
 *    8 - Pager
 *    9 - UAN
 *   10 - Voicemail
 *   11 - Unknown
 */
static int w_get_number_type(struct sip_msg *msg, str *number,
                             pv_spec_t *out_var, str *default_region) {
  int type = get_number_type(number->s, default_region ? default_region->s
                                                       : DEFAULT_REGION);
  return set_out_int(msg, out_var, type);
}

static int w_get_region_code_for_country_code(struct sip_msg *msg,
                                              int *country_code,
                                              pv_spec_t *out_var) {
  char res[OUT_BUFFER_SIZE];
  const int len =
      get_region_code_for_country_code(*country_code, res, sizeof(res));
  return set_out_string(msg, out_var, res, len);
}

static int w_get_region_code_for_number(struct sip_msg *msg, str *number,
                                        pv_spec_t *out_var,
                                        str *default_region) {
  char res[OUT_BUFFER_SIZE];
  const int len = get_region_code_for_number(number->s, res, sizeof(res),
                                             default_region ? default_region->s
                                                            : DEFAULT_REGION);
  return set_out_string(msg, out_var, res, len);
}

static int w_is_alpha_number(struct sip_msg *msg, str *number) {
  return is_alpha_number(number->s) ? FN_SUCCESS : FN_FAILURE;
}

static int w_is_nanpa_country(struct sip_msg *msg, str *region_code) {
  return is_nanpa_country(region_code->s) ? FN_SUCCESS : FN_FAILURE;
}

/*
 * Return value:
 *   -1 - Invalid number
 *    1 - No match
 *    2 - Short NSN match
 *    3 - NSN match
 *    4 - Exact match
 */
static int w_is_number_match(struct sip_msg *msg, str *number1, str *number2,
                             str *default_region1, str *default_region2) {
  const int match =
      is_number_match(number1->s, number2->s,
                      default_region1 ? default_region1->s : DEFAULT_REGION,
                      default_region2 ? default_region2->s : DEFAULT_REGION);
  return match == 0 ? -1 : match;
}

static int w_is_possible_number(struct sip_msg *msg, str *number,
                                str *default_region) {
  return is_possible_number(number->s,
                            default_region ? default_region->s : DEFAULT_REGION)
             ? FN_SUCCESS
             : FN_FAILURE;
}

static int w_is_possible_number_for_string(struct sip_msg *msg, str *number,
                                           str *region_dialing_from) {
  return is_possible_number_for_string(number->s, region_dialing_from->s)
             ? FN_SUCCESS
             : FN_FAILURE;
}

static int w_is_valid_number(struct sip_msg *msg, str *number,
                             str *default_region) {
  return is_valid_number(number->s,
                         default_region ? default_region->s : DEFAULT_REGION)
             ? FN_SUCCESS
             : FN_FAILURE;
}

static int w_is_valid_number_for_region(struct sip_msg *msg, str *number,
                                        str *region, str *default_region) {
  return is_valid_number_for_region(number->s, region->s,
                                    default_region ? default_region->s
                                                   : DEFAULT_REGION)
             ? FN_SUCCESS
             : FN_FAILURE;
}

static int w_normalize_diallable_chars_only(struct sip_msg *msg, str *number,
                                            pv_spec_t *out_var) {
  char res[OUT_BUFFER_SIZE];
  const int len = normalize_diallable_chars_only(number->s, res, sizeof(res));
  return set_out_string(msg, out_var, res, len);
}

static int w_normalize_digits_only(struct sip_msg *msg, str *number,
                                   pv_spec_t *out_var) {
  char res[OUT_BUFFER_SIZE];
  const int len = normalize_digits_only(number->s, res, sizeof(res));
  return set_out_string(msg, out_var, res, len);
}
