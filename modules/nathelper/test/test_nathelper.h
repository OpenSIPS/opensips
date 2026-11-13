/* Included here to exercise the actual ping builder and reply parser. */
#include <tap.h>
#include <limits.h>

static ucontact_coords test_latency_coords;

static int test_ping_latency(udomain_t *domain, ucontact_coords coords, int latency)
{
	test_latency_coords = coords;
	return 0;
}

static void test_ping_packet(str *uri, ucontact_coords coords, int flags,
		char *branch)
{
	struct socket_info socket = {0};
	str address = str_init("127.0.0.1"), port = str_init("5060");
	str path = STR_NULL;
	char *packet, *start, *end;
	char copy[MAX_SIPPING_SIZE + 1];
	int len;

	socket.proto = PROTO_UDP;
	socket.address_str = address;
	socket.port_no_str = port;
	packet = build_sipping(NULL, uri, &socket, &path, &len, coords, flags);
	ok(packet != NULL, "build OPTIONS for flags %d", flags);
	if (!packet) {
		branch[0] = '\0';
		return;
	}
	/* build_sipping() returns a length-delimited, static buffer. */
	memcpy(copy, packet, len);
	copy[len] = '\0';
	packet = copy;
	ok(strstr(packet, "\r\nCSeq: 1 OPTIONS\r\n") != NULL,
		"out-of-dialog OPTIONS keeps CSeq 1");
	start = strstr(packet, BSTART);
	if (!start) {
		fail("OPTIONS has a Via branch");
		branch[0] = '\0';
		return;
	}
	start += sizeof(BSTART) - 1;
	end = memchr(start, '\r', packet + len - start);
	if (!end || end - start >= 120) {
		fail("OPTIONS has a bounded Via branch");
		branch[0] = '\0';
		return;
	}
	memcpy(branch, start, end - start);
	branch[end - start] = '\0';
}

static void test_repeated_ping(int flags, ucontact_coords coords,
		unsigned int label)
{
	str uri = str_init("sip:alice@192.0.2.10:5060"), reply;
	char first[120], second[120];
	unsigned int hash = core_hash(&uri, NULL, 0) & (NH_TABLE_ENTRIES - 1);
	struct ping_cell *cell;
	char *suffix;
	unsigned int parsed_label;

	get_htable()->entries[hash].next_via_label = label;
	test_ping_packet(&uri, coords, flags, first);
	if (flags) {
		cell = get_cell(hash, coords);
		if (!cell) {
			fail("tracked ping creates a contact entry");
			return;
		}
		/* Advance the real timeout handler without sleeping. */
		cell->timestamp = now - ping_threshold - 1;
		ping_checker_timer(0, NULL);
	}
	test_ping_packet(&uri, coords, flags, second);
	ok(strcmp(first, second) != 0,
		"successive pings use different branches (flags %d, label %u)",
		flags, label);
	if (!flags)
		return;
	suffix = strrchr(second, '.');
	ok(suffix && suffix[1] == 'p'
		&& reverse_hex2int(suffix + 2, strlen(suffix + 2), &parsed_label) == 0
		&& parsed_label == label + 1,
		"tracked branch ends with .p followed by its ping label");

	cell = get_cell(hash, coords);
	if (!cell) {
		fail("second ping has a contact entry");
		return;
	}
	test_latency_coords = 0;
	/* A response to either outstanding ping confirms contact liveness. */
	reply.s = first;
	reply.len = strlen(first);
	ok(parse_branch(reply) == 0 && cell->state == PING_CELL_STATE_ANSWERED
		&& get_cell(hash, coords) == NULL,
		"reply to an earlier ping confirms the correct contact");
	if (flags & sipping_latency_flag)
		ok(test_latency_coords == coords,
			"reply updates latency for the original contact coordinates");
	/* Also exercise the current branch, including its label. */
	ping_checker_timer(0, NULL);
	test_ping_packet(&uri, coords, flags, second);
	cell = get_cell(hash, coords);
	reply.s = second;
	reply.len = strlen(second);
	ok(parse_branch(reply) == 0 && cell
		&& cell->state == PING_CELL_STATE_ANSWERED,
		"current ping branch matches its contact");
	ping_checker_timer(0, NULL);
}

static void test_ping_contacts(void)
{
	str uri = str_init("sip:alice@192.0.2.10:5060"), reply;
	char first[120], second[120], *separator;
	unsigned int hash = core_hash(&uri, NULL, 0) & (NH_TABLE_ENTRIES - 1);
	struct ping_cell *a, *b;

	/* Distinct contacts must remain distinguishable even in one bucket. */
	test_ping_packet(&uri, 0x1001, 1, first);
	test_ping_packet(&uri, 0x1002, 1, second);
	a = get_cell(hash, 0x1001);
	b = get_cell(hash, 0x1002);
	ok(strcmp(first, second) != 0, "different contacts use different branches");
	reply.s = second;
	reply.len = strlen(second);
	ok(parse_branch(reply) == 0 && a && b
		&& a->state == PING_CELL_STATE_PINGING
		&& b->state == PING_CELL_STATE_ANSWERED,
		"reply confirms only its own contact in a shared bucket");

	/* Keep replies using the old hash.coordinates format working. */
	separator = strchr(first + BMAGIC_LEN, '.');
	if (separator && (separator = strchr(separator + 1, '.')))
		*separator = '\0';
	reply.s = first;
	reply.len = strlen(first);
	ok(parse_branch(reply) == 0 && a
		&& a->state == PING_CELL_STATE_ANSWERED,
		"reply with the old branch format still confirms its contact");
	ping_checker_timer(0, NULL);
}

void mod_tests(void)
{
	bind_usrloc_t bind_usrloc;
	int (*saved_latency)(udomain_t *, ucontact_coords, int);

	bind_usrloc = (bind_usrloc_t)find_export("ul_bind_usrloc", 0);
	if (!bind_usrloc || bind_usrloc(&ul) < 0 || !init_hash_table()) {
		fail("initialize real usrloc API and ping table");
		return;
	}
	saved_latency = ul.update_sipping_latency;
	ul.update_sipping_latency = test_ping_latency;
	rm_on_to_flag = 1;
	sipping_latency_flag = 2;
	natping_interval = 60;
	sipping_from = (str)str_init("sip:ping@127.0.0.1");
	init_sip_ping(1);

	test_repeated_ping(1, 0x1001, 0);
	test_repeated_ping(2, 0x1002, 42);
	test_repeated_ping(3, UINT64_MAX, UINT_MAX);
	test_repeated_ping(0, 0x1003, 0);
	test_ping_contacts();

	ul.update_sipping_latency = saved_latency;
	natping_interval = 0;
	/* mod_destroy() owns the ping table, as in normal operation. */
}
