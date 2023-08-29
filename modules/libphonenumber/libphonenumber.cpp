#include "libphonenumber.h"
#include <phonenumbers/phonenumberutil.h>
#include <string>

using namespace i18n::phonenumbers;

const PhoneNumberUtil &UTIL(*PhoneNumberUtil::GetInstance());

static bool parse_phone_number(const char *number, PhoneNumber &out,
                               const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  const auto res = UTIL.Parse(number, default_region, &parsed_number);
  if (res == PhoneNumberUtil::ErrorType::NO_PARSING_ERROR) {
    out = parsed_number;
    return true;
  }
  return false;
}

static bool copy_string_output(const std::string &src, char *dst,
                               size_t dst_len) {
  if (dst_len < src.length() + 1)
    return false;
  ::snprintf(dst, dst_len, "%s", src.c_str());
  return true;
}

int convert_alpha_characters_in_number(const char *number, char *out,
                                       size_t out_len) {
  std::string converted(number);
  UTIL.ConvertAlphaCharactersInNumber(&converted);
  if (!copy_string_output(converted, out, out_len))
    return -1;
  return converted.length();
}

size_t format(const char *number, enum PhoneNumberFormat format, char *out,
              size_t out_len, const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string formatted_number;
  UTIL.Format(parsed_number,
              static_cast<PhoneNumberUtil::PhoneNumberFormat>(format),
              &formatted_number);
  if (!copy_string_output(formatted_number, out, out_len))
    return -1;
  return formatted_number.length();
}

size_t format_in_original_format(const char *number,
                                 const char *region_calling_from, char *out,
                                 size_t out_len,
                                 const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string formatted_number;
  UTIL.FormatInOriginalFormat(parsed_number, region_calling_from,
                              &formatted_number);
  if (!copy_string_output(formatted_number, out, out_len))
    return -1;
  return formatted_number.length();
}

size_t format_national_number_with_carrier_code(
    const char *number, const char *carrier_code, char *out, size_t out_len,
    const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string formatted_number;
  UTIL.FormatNationalNumberWithCarrierCode(parsed_number, carrier_code,
                                           &formatted_number);
  if (!copy_string_output(formatted_number, out, out_len))
    return -1;
  return formatted_number.length();
}

size_t format_national_number_with_preferred_carrier_code(
    const char *number, const char *preferred_carrier_code, char *out,
    size_t out_len, const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string formatted_number;
  UTIL.FormatNationalNumberWithPreferredCarrierCode(
      parsed_number, preferred_carrier_code, &formatted_number);
  if (!copy_string_output(formatted_number, out, out_len))
    return -1;
  return formatted_number.length();
}

size_t format_number_for_mobile_dialing(
    const char *number, const char *region_calling_from, bool with_formatting,
    char *out, size_t out_len, const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string formatted_number;
  UTIL.FormatNumberForMobileDialing(parsed_number, region_calling_from,
                                    with_formatting, &formatted_number);
  if (!copy_string_output(formatted_number, out, out_len))
    return -1;
  return formatted_number.length();
}

size_t format_out_of_country_calling_number(
    const char *number, const char *calling_from, char *out, size_t out_len,
    const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string formatted_number;
  UTIL.FormatOutOfCountryCallingNumber(parsed_number, calling_from,
                                       &formatted_number);
  if (!copy_string_output(formatted_number, out, out_len))
    return -1;
  return formatted_number.length();
}

size_t format_out_of_country_keeping_alpha_chars(
    const char *number, const char *calling_from, char *out, size_t out_len,
    const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string formatted_number;
  UTIL.FormatOutOfCountryKeepingAlphaChars(parsed_number, calling_from,
                                           &formatted_number);
  if (!copy_string_output(formatted_number, out, out_len))
    return -1;
  return formatted_number.length();
}

int get_country_code_for_region(const char *region_code) {
  return UTIL.GetCountryCodeForRegion(region_code);
}

size_t get_country_mobile_token(int country_calling_code, char *out,
                                size_t out_len) {
  std::string mobile_token;
  UTIL.GetCountryMobileToken(country_calling_code, &mobile_token);
  if (!copy_string_output(mobile_token, out, out_len))
    return -1;
  return mobile_token.length();
}

int get_length_of_geographical_area_code(
    const char *number, const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  return UTIL.GetLengthOfGeographicalAreaCode(parsed_number);
}

int get_length_of_national_destination_code(
    const char *number, const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  return UTIL.GetLengthOfNationalDestinationCode(parsed_number);
}

size_t
get_national_significant_number(const char *number, char *out, size_t out_len,
                                const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string national_significant_number;
  UTIL.GetNationalSignificantNumber(parsed_number,
                                    &national_significant_number);
  if (!copy_string_output(national_significant_number, out, out_len))
    return -1;
  return national_significant_number.length();
}

size_t get_ndd_prefix_for_region(const char *region_code, bool strip_non_digits,
                                 char *out, size_t out_len) {
  std::string national_prefix;
  UTIL.GetNddPrefixForRegion(region_code, strip_non_digits, &national_prefix);
  if (!copy_string_output(national_prefix, out, out_len))
    return -1;
  return national_prefix.length();
}

PhoneNumberType get_number_type(const char *number,
                                const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region)) {
    return PhoneNumberType::PARSING_ERROR;
  }
  return static_cast<PhoneNumberType>(UTIL.GetNumberType(parsed_number));
}

size_t get_region_code_for_country_code(int country_code, char *out,
                                        size_t out_len) {
  std::string region_code;
  UTIL.GetRegionCodeForCountryCode(country_code, &region_code);
  if (!copy_string_output(region_code, out, out_len))
    return -1;
  return region_code.length();
}

size_t get_region_code_for_number(const char *number, char *out, size_t out_len,
                                  const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return -1;
  std::string region_code;
  UTIL.GetRegionCodeForNumber(parsed_number, &region_code);
  if (!copy_string_output(region_code, out, out_len))
    return -1;
  return region_code.length();
}

bool is_alpha_number(const char *number) { return UTIL.IsAlphaNumber(number); }

bool is_nanpa_country(const char *region_code) {
  return UTIL.IsNANPACountry(region_code);
}

MatchType is_number_match(const char *number1, const char *number2,
                          const char *default_region1,
                          const char *default_region2) {
  PhoneNumber parsed_number1;
  PhoneNumber parsed_number2;
  if (!parse_phone_number(number1, parsed_number1, default_region1) ||
      !parse_phone_number(number2, parsed_number2, default_region2)) {
    return MatchType::INVALID_NUMBER;
  }
  return static_cast<MatchType>(
      UTIL.IsNumberMatch(parsed_number1, parsed_number2));
}

bool is_possible_number(const char *number,
                        const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return false;
  return UTIL.IsPossibleNumber(parsed_number);
}

bool is_possible_number_for_string(const char *number,
                                   const char *region_dialing_from) {
  return UTIL.IsPossibleNumberForString(number, region_dialing_from);
}

bool is_valid_number(const char *number,
                     const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return false;
  return UTIL.IsValidNumber(parsed_number);
}

bool is_valid_number_for_region(const char *number, const char *region,
                                const char *default_region = DEFAULT_REGION) {
  PhoneNumber parsed_number;
  if (!parse_phone_number(number, parsed_number, default_region))
    return false;
  return UTIL.IsValidNumberForRegion(parsed_number, region);
}

size_t normalize_diallable_chars_only(const char *number, char *out,
                                      size_t out_len) {
  std::string converted(number);
  UTIL.NormalizeDiallableCharsOnly(&converted);
  if (!copy_string_output(converted, out, out_len))
    return -1;
  return converted.length();
}

size_t normalize_digits_only(const char *number, char *out, size_t out_len) {
  std::string converted(number);
  UTIL.NormalizeDigitsOnly(&converted);
  if (!copy_string_output(converted, out, out_len))
    return -1;
  return converted.length();
}
