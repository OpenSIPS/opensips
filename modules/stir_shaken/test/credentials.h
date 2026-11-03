/* Public test credentials only. All P-256 certificates use the existing
 * test_private_key fixture. P-384 is deliberately unsuitable for ES256.
 * Signed by vs_certificate using Python cryptography, except the deliberately
 * self-signed untrusted variant. No leaf is installed as a trust anchor.
 * Fixed validity avoids clock-sensitive expiry tests.
 * TNAuthList uses RFC 8226 explicit-tag DER; constraints are unsupported. */
#ifndef STIR_SHAKEN_TEST_CREDENTIALS_H
#define STIR_SHAKEN_TEST_CREDENTIALS_H

static const char credential_expired[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBUjCB+KADAgECAgFkMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEU9wZW5TSVBT\n"
	"LURJVi1UZXN0MB4XDTAwMDEwMTAwMDAwMFoXDTAxMDEwMTAwMDAwMFowIDEeMBwG\n"
	"A1UEAwwVT3BlblNJUFMgdGVzdCBleHBpcmVkMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
	"AQcDQgAEjaRI7F43cbJ2U5BSadK1AscH5GFZXHfMHNOo1peKJIBVGKxg1ZZifF/3\n"
	"qnaNPxCdK0vP8EUNtqpjFEnDJeq0OqMnMCUwDAYDVR0TAQH/BAIwADAVBggrBgEF\n"
	"BQcBGgQJMAegBRYDMDAxMAoGCCqGSM49BAMCA0kAMEYCIQCLQJtwPIeBOm+sOZld\n"
	"BKa47iFfrKwhgmelyku5Qu/zoQIhAMaM8VPsaa6MCHZLwiznZmLywtZvtT2mhL4k\n"
	"dgE3+cu/\n"
	"-----END CERTIFICATE-----\n";

static const char credential_untrusted[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBXDCCAQKgAwIBAgIBZTAKBggqhkjOPQQDAjAiMSAwHgYDVQQDDBdPcGVuU0lQ\n"
	"UyB0ZXN0IHVudHJ1c3RlZDAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEwMTAwMDAw\n"
	"MFowIjEgMB4GA1UEAwwXT3BlblNJUFMgdGVzdCB1bnRydXN0ZWQwWTATBgcqhkjO\n"
	"PQIBBggqhkjOPQMBBwNCAASNpEjsXjdxsnZTkFJp0rUCxwfkYVlcd8wc06jWl4ok\n"
	"gFUYrGDVlmJ8X/eqdo0/EJ0rS8/wRQ22qmMUScMl6rQ6oycwJTAMBgNVHRMBAf8E\n"
	"AjAAMBUGCCsGAQUFBwEaBAkwB6AFFgMwMDEwCgYIKoZIzj0EAwIDSAAwRQIgTcJn\n"
	"IEfPolknv2lOzdoiTc/gAre7KB6TaBBslXjmU1ICIQD2eVaKedJsxJ3yhYXrjFxU\n"
	"5ajwEaVyUwpI2ISxVfpc7A==\n"
	"-----END CERTIFICATE-----\n";

static const char credential_missing_tn[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBPjCB5qADAgECAgFmMAoGCCqGSM49BAMCMBwxGjAYBgNVBAMMEU9wZW5TSVBT\n"
	"LURJVi1UZXN0MCAXDTIwMDEwMTAwMDAwMFoYDzIxMjAwMTAxMDAwMDAwWjAjMSEw\n"
	"HwYDVQQDDBhPcGVuU0lQUyB0ZXN0IG1pc3NpbmdfdG4wWTATBgcqhkjOPQIBBggq\n"
	"hkjOPQMBBwNCAASNpEjsXjdxsnZTkFJp0rUCxwfkYVlcd8wc06jWl4okgFUYrGDV\n"
	"lmJ8X/eqdo0/EJ0rS8/wRQ22qmMUScMl6rQ6oxAwDjAMBgNVHRMBAf8EAjAAMAoG\n"
	"CCqGSM49BAMCA0cAMEQCIBk1eicOnVtoPAs2yhBa+z1mYaT+jQgPqHr6sI8zLNV1\n"
	"AiBZ+K54zqboO8J6ai3fDi6QP2ibwhfM4llEgJheO1+24A==\n"
	"-----END CERTIFICATE-----\n";

static const char credential_wrong_tn[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBXTCCAQOgAwIBAgIBZzAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFPcGVuU0lQ\n"
	"Uy1ESVYtVGVzdDAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEwMTAwMDAwMFowITEf\n"
	"MB0GA1UEAwwWT3BlblNJUFMgdGVzdCB3cm9uZ190bjBZMBMGByqGSM49AgEGCCqG\n"
	"SM49AwEHA0IABI2kSOxeN3GydlOQUmnStQLHB+RhWVx3zBzTqNaXiiSAVRisYNWW\n"
	"Ynxf96p2jT8QnStLz/BFDbaqYxRJwyXqtDqjLzAtMAwGA1UdEwEB/wQCMAAwHQYI\n"
	"KwYBBQUHARoEETAPog0WCzEyMTU1NTU5OTk5MAoGCCqGSM49BAMCA0gAMEUCIQDA\n"
	"Z+cn+Y9xu61Ga070E8bSul+DfPOPi70u9ZUpqNjVkwIgWd9by0xOhcb7Pxo/cY6Y\n"
	"TTp4stU4YFdBXqN8bY01+vg=\n"
	"-----END CERTIFICATE-----\n";

static const char credential_div_tn[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBWjCCAQGgAwIBAgIBaDAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFPcGVuU0lQ\n"
	"Uy1ESVYtVGVzdDAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEwMTAwMDAwMFowHzEd\n"
	"MBsGA1UEAwwUT3BlblNJUFMgdGVzdCBkaXZfdG4wWTATBgcqhkjOPQIBBggqhkjO\n"
	"PQMBBwNCAASNpEjsXjdxsnZTkFJp0rUCxwfkYVlcd8wc06jWl4okgFUYrGDVlmJ8\n"
	"X/eqdo0/EJ0rS8/wRQ22qmMUScMl6rQ6oy8wLTAMBgNVHRMBAf8EAjAAMB0GCCsG\n"
	"AQUFBwEaBBEwD6INFgsxMjE1NTU1MTIxMzAKBggqhkjOPQQDAgNHADBEAiB257kp\n"
	"AdvuYHg+kSnx8KfE0sZ+sfOB8iJcV2gu25WxHQIgXR81Mf85MExN7kl1WCfnpe6f\n"
	"DK6Fu65n+IXQUqAyzqI=\n"
	"-----END CERTIFICATE-----\n";

static const char credential_jwt_constraints[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBbDCCARKgAwIBAgIBaTAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFPcGVuU0lQ\n"
	"Uy1ESVYtVGVzdDAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEwMTAwMDAwMFowKDEm\n"
	"MCQGA1UEAwwdT3BlblNJUFMgdGVzdCBqd3RfY29uc3RyYWludHMwWTATBgcqhkjO\n"
	"PQIBBggqhkjOPQMBBwNCAASNpEjsXjdxsnZTkFJp0rUCxwfkYVlcd8wc06jWl4ok\n"
	"gFUYrGDVlmJ8X/eqdo0/EJ0rS8/wRQ22qmMUScMl6rQ6ozcwNTAMBgNVHRMBAf8E\n"
	"AjAAMBUGCCsGAQUFBwEaBAkwB6AFFgMwMDEwDgYIKwYBBQUHARsEAjAAMAoGCCqG\n"
	"SM49BAMCA0gAMEUCIQDVt7s0i6td/+D6eteToBjkvPZL09zz+GOEWQQNGie5pAIg\n"
	"Ojt5sOCfWiAKAnww33S+ZjJdlWUApd+rDhV2D7+SvEo=\n"
	"-----END CERTIFICATE-----\n";

static const char credential_p384[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBbzCCARSgAwIBAgIBajAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFPcGVuU0lQ\n"
	"Uy1ESVYtVGVzdDAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEwMTAwMDAwMFowHTEb\n"
	"MBkGA1UEAwwST3BlblNJUFMgdGVzdCBwMzg0MHYwEAYHKoZIzj0CAQYFK4EEACID\n"
	"YgAEGWElOEQMgD1Bf3TranaN2LYzKV1GazIPJaolkmk8ugkVUEAHBOi3j2YBrk7u\n"
	"Kf+8u6wlsdB59n5mtnRVYoW+UueuaDy4y0TCx0Zu91CRKqrrEvaBkf1SplA9ZncX\n"
	"6HmSoycwJTAMBgNVHRMBAf8EAjAAMBUGCCsGAQUFBwEaBAkwB6AFFgMwMDEwCgYI\n"
	"KoZIzj0EAwIDSQAwRgIhAOrNHhgUMTi27nF/nKi5zr9xaMqAA77SyKxH/RmFG28k\n"
	"AiEA+jcDESsHyo937v/lqevzhyIFs8gn48VnAQBRB18BY7Y=\n"
	"-----END CERTIFICATE-----\n";

#endif
