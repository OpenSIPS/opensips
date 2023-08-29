#!/usr/bin/env bash

LOGFILE="log.txt"

# Config
CFG="libphonenumber.cfg"

cat > "${CFG}" << 'EOF'
loadmodule "proto_udp.so"
loadmodule "modules/libphonenumber/libphonenumber.so"

log_level=0
socket=udp:127.0.0.1:5060

route {
  exit;
}

route[passed] {
  xlog("[PASSED] Name: $(route[-3]{s.select,1,[}{s.select,0,]})\n");
}

route[failed] {
  xlog("[FAILED] Name: $(route[-3]{s.select,1,[}{s.select,0,]}), expected: \"$param(1)\", actual: \"$param(2)\"\n");
}

route[clean] {
  $var(expected) = "";
  $var(result) = "";
}

route[check_eq] {
  if ($param(1) != $param(2)) {
    route(failed, $param(1), $param(2));
    return;
  }
  route(passed);
}

route[eq] {
  route(check_eq, $param(1), $param(2));
}

route[pn_convert_alpha_characters_in_number] {
  $var(return) = pn_convert_alpha_characters_in_number("abcdefgh", $var(result));
  route(eq, "1", $var(return));
  route(eq, "22233344", $var(result));
  route(clean);
}

route[pn_format] {
  $var(return) = pn_format("202 123 0000", 1, $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "+1 202-123-0000", $var(result));
  route(clean);

  $var(return) = pn_format("202 123 0000", 1, $var(result));
  route(eq, "-1", $var(return));
  route(eq, "", $var(result));
  route(clean);
}

route[pn_format_in_original_format] {
  $var(return) = pn_format_in_original_format("202-123-0000", "US", $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "(202) 123-0000", $var(result));
  route(clean);
}

route[pn_format_national_number_with_carrier_code] {
  $var(return) = pn_format_national_number_with_carrier_code("02234 65-4321", "14", $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "02234654321", $var(result));
  route(clean);
}

route[pn_format_national_number_with_preferred_carrier_code] {
  $var(return) = pn_format_national_number_with_preferred_carrier_code("02234 65-4321", "15", $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "02234654321", $var(result));
  route(clean);
}

route[pn_format_number_for_mobile_dialing] {
  $var(return) = pn_format_number_for_mobile_dialing("1300123456", "AU", 1, $var(result), "AU");
  route(eq, "1", $var(return));
  route(eq, "1300 123 456", $var(result));
  route(clean);
}

route[pn_format_out_of_country_calling_number] {
  $var(return) = pn_format_out_of_country_calling_number("202-456-2121", "JP", $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "010 1 202-456-2121", $var(result));
  route(clean);
}

route[pn_format_out_of_country_keeping_alpha_chars] {
  $var(return) = pn_format_out_of_country_keeping_alpha_chars("202-456-2121", "JP", $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "010 1 202-456-2121", $var(result));
  route(clean);
}

route[pn_get_country_code_for_region] {
  pn_get_country_code_for_region("202", $var(result));
  route(eq, "0", $var(result));
  route(eq, "1", $var(return));
  route(clean);
}

route[pn_get_country_mobile_token] {
  $var(return) = pn_get_country_mobile_token(36, $var(result));
  route(eq, "-1", $var(return));
  route(eq, "", $var(result));
  route(clean);
}

route[pn_get_length_of_geographical_area_code] {
  $var(return) = pn_get_length_of_geographical_area_code("+1 202-123-0000", $var(result), "HU");
  route(eq, "0", $var(result));
  route(eq, "1", $var(return));
  route(clean);
}

route[pn_get_length_of_national_destination_code] {
  $var(return) = pn_get_length_of_national_destination_code("+1 202-123-0000", $var(result), "HU");
  route(eq, "3", $var(result));
  route(eq, "1", $var(return));
  route(clean);
}

route[pn_get_national_significant_number] {
  $var(return) = pn_get_national_significant_number("202-456-2121", $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "2024562121", $var(result));
  route(clean);
}

route[pn_get_ndd_prefix_for_region] {
  $var(return) = pn_get_ndd_prefix_for_region("HU", 1, $var(result));
  route(eq, "1", $var(return));
  route(eq, "06", $var(result));
  route(clean);
}

route[pn_get_number_type] {
  $var(return) = pn_get_number_type("202-456-2121", $var(result), "US");
  route(eq, "1", $var(return));
  route(eq, "2", $var(result));
  route(clean);
}

route[pn_get_region_code_for_country_code] {
  $var(return) = pn_get_region_code_for_country_code(36, $var(result));
  route(eq, "1", $var(return));
  route(eq, "HU", $var(result));
  route(clean);
}

route[pn_get_region_code_for_number] {
  $var(return) = pn_get_region_code_for_number("+36202222222", $var(result));
  route(eq, "1", $var(return));
  route(eq, "HU", $var(result));
  route(clean);
}

route[pn_is_alpha_number] {
  $var(return) = pn_is_alpha_number("800 MICROSOFT");
  route(eq, "1", $var(return));
  route(clean);

  $var(return) = pn_is_alpha_number("+36202222222");
  route(eq, "-1", $var(return));
  route(clean);
}

route[pn_is_nanpa_country] {
  $var(return) = pn_is_nanpa_country("US");
  route(eq, "1", $var(return));
  route(clean);

  $var(return) = pn_is_nanpa_country("HU");
  route(eq, "-1", $var(return));
  route(clean);
}

route[pn_is_number_match] {
  $var(return) = pn_is_number_match("+643 331-6005", "+6433316005");
  route(eq, "4", $var(return));
  route(clean);

  $var(return) = pn_is_number_match("+1 (234) 345 6789", "345 6789", "US", "US");
  route(eq, "2", $var(return));
  route(clean);
}

route[pn_is_possible_number] {
  $var(return) = pn_is_possible_number("202-456-2121", "US");
  route(eq, "1", $var(return));
  route(clean);
}

route[pn_is_possible_number_for_string] {
  $var(return) = pn_is_possible_number_for_string("+1 650 253 0000", "HU");
  route(eq, "1", $var(return));
  route(clean);

  $var(return) = pn_is_possible_number_for_string("650 253 0000", "US");
  route(eq, "1", $var(return));
  route(clean);

  $var(return) = pn_is_possible_number_for_string("650 253 0000", "HU");
  route(eq, "-1", $var(return));
  route(clean);
}

route[pn_is_valid_number] {
  $var(return) = pn_is_valid_number("+41 (0) 78 927 2696");
  route(eq, "1", $var(return));
  route(clean);
}

route[pn_is_valid_number_for_region] {
  $var(return) = pn_is_valid_number_for_region("+36701111111", "HU");
  route(eq, "1", $var(return));
  route(clean);
}

route[pn_normalize_diallable_chars_only] {
  $var(return) = pn_normalize_diallable_chars_only("<> +36701111111", $var(result));
  route(eq, "1", $var(return));
  route(eq, "+36701111111", $var(result));
  route(clean);
}

route[pn_normalize_digits_only] {
  $var(return) = pn_normalize_digits_only("<> +36701111111", $var(result));
  route(eq, "1", $var(return));
  route(eq, "36701111111", $var(result));
  route(clean);
}

route[smoke_test] {
  route(pn_convert_alpha_characters_in_number);
  route(pn_format);
  route(pn_format_in_original_format);
  route(pn_format_national_number_with_carrier_code);
  route(pn_format_national_number_with_preferred_carrier_code);
  route(pn_format_number_for_mobile_dialing);
  route(pn_format_out_of_country_calling_number);
  route(pn_format_out_of_country_keeping_alpha_chars);
  route(pn_get_country_code_for_region);
  route(pn_get_country_mobile_token);
  route(pn_get_length_of_geographical_area_code);
  route(pn_get_length_of_national_destination_code);
  route(pn_get_national_significant_number);
  route(pn_get_ndd_prefix_for_region);
  route(pn_get_number_type);
  route(pn_get_region_code_for_country_code);
  route(pn_get_region_code_for_number);
  route(pn_is_alpha_number);
  route(pn_is_nanpa_country);
  route(pn_is_number_match);
  route(pn_is_possible_number);
  route(pn_is_possible_number_for_string);
  route(pn_is_valid_number);
  route(pn_is_valid_number_for_region);
  route(pn_normalize_diallable_chars_only);
  route(pn_normalize_digits_only);
}

startup_route {
  route(smoke_test);
}
EOF

# Run OpenSIPS
./opensips -w $(pwd) -f "${CFG}" &> "${LOGFILE}"

# Shutdown OpenSIPS
sleep 2
killall -9 opensips

# Result
cat "${LOGFILE}"
TEST_SUCCESS=$(egrep -i '^\[PASSED\] ' "${LOGFILE}" | wc -l)
TEST_FAILURE=$(egrep -i '^\[FAILED\] ' "${LOGFILE}" | wc -l)
echo "---"
echo "Passed: ${TEST_SUCCESS}"
echo "Failed: ${TEST_FAILURE}"
echo "---"

# Cleanup
rm -f "${CFG}" "${LOGFILE}"

# Exit
if [[ "${TEST_FAILURE}" -eq 0 && "${TEST_SUCCESS}" -gt 0 ]]; then
  echo "PASSED"
  exit 0
else
  echo "FAILED"
  exit 1
fi
