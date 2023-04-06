#ifndef _LIBPHONENUMBER_H_
#define _LIBPHONENUMBER_H_

#ifdef __cplusplus
#include <cstddef>
#else
#include <stdbool.h>
#include <stddef.h>
#endif

#define DEFAULT_REGION "ZZ"

#ifdef __cplusplus
extern "C" {
#endif

enum PhoneNumberFormat {
  E164 = 0,
  INTERNATIONAL,
  NATIONAL,
  RFC3966,
};

enum PhoneNumberType {
  FIXED_LINE = 0,
  MOBILE,
  FIXED_LINE_OR_MOBILE,
  TOLL_FREE,
  PREMIUM_RATE,
  SHARED_COST,
  VOIP,
  PERSONAL_NUMBER,
  PAGER,
  UAN,
  VOICEMAIL,
  UNKNOWN,
  PARSING_ERROR = -1,
};

enum MatchType {
  NO_MATCH = 1,
  SHORT_NSN_MATCH,
  NSN_MATCH,
  EXACT_MATCH,
  INVALID_NUMBER = -1,
};

int convert_alpha_characters_in_number(const char *number, char *out,
                                       size_t out_len);
size_t format(const char *number, enum PhoneNumberFormat format, char *out,
              size_t out_len, const char *default_region);
size_t format_in_original_format(const char *number,
                                 const char *region_calling_from, char *out,
                                 size_t out_len, const char *default_region);
size_t format_national_number_with_carrier_code(const char *number,
                                                const char *carrier_code,
                                                char *out, size_t out_len,
                                                const char *default_region);
size_t format_national_number_with_preferred_carrier_code(
    const char *number, const char *preferred_carrier_code, char *out,
    size_t out_len, const char *default_region);
size_t format_number_for_mobile_dialing(const char *number,
                                        const char *region_calling_from,
                                        bool with_formatting, char *out,
                                        size_t out_len,
                                        const char *default_region);
size_t format_out_of_country_calling_number(const char *number,
                                            const char *calling_from, char *out,
                                            size_t out_len,
                                            const char *default_region);
size_t format_out_of_country_keeping_alpha_chars(const char *number,
                                                 const char *calling_from,
                                                 char *out, size_t out_len,
                                                 const char *default_region);
int get_country_code_for_region(const char *region_code);
size_t get_country_mobile_token(int country_calling_code, char *out,
                                size_t out_len);
int get_length_of_geographical_area_code(const char *number,
                                         const char *default_region);
int get_length_of_national_destination_code(const char *number,
                                            const char *default_region);
size_t get_national_significant_number(const char *number, char *out,
                                       size_t out_len,
                                       const char *default_region);
size_t get_ndd_prefix_for_region(const char *region_code, bool strip_non_digits,
                                 char *out, size_t out_len);
enum PhoneNumberType get_number_type(const char *number,
                                     const char *default_region);
size_t get_region_code_for_country_code(int country_code, char *out,
                                        size_t out_len);
size_t get_region_code_for_number(const char *number, char *out, size_t out_len,
                                  const char *default_region);
bool is_alpha_number(const char *number);
bool is_nanpa_country(const char *region_code);
enum MatchType is_number_match(const char *number1, const char *number2,
                               const char *default_region1,
                               const char *default_region2);
bool is_possible_number(const char *number, const char *default_region);
bool is_possible_number_for_string(const char *number,
                                   const char *region_dialing_from);
bool is_valid_number(const char *number, const char *default_region);
bool is_valid_number_for_region(const char *number, const char *region,
                                const char *default_region);
size_t normalize_diallable_chars_only(const char *number, char *out,
                                      size_t out_len);
size_t normalize_digits_only(const char *number, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif // _LIBPHONENUMBER_H
