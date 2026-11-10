/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * nats_ca_dir.h -- libnats has no directory-load API for CA
 * certificates (only a single-file path or an in-memory PEM string).
 * This helper walks a directory in lexicographic order, reads every
 * regular .pem file, concatenates the contents in memory, and
 * returns a single nul-terminated buffer the caller can hand to
 * natsOptions_SetCATrustedCertificates().
 *
 * Mirrors OpenSSL's SSL_CTX_load_verify_locations(NULL, dir)
 * semantics without requiring any libnats change.
 *
 * Self-contained (libc + POSIX dirent only) so the unit test can
 * link against it without pulling in nats_pool / OpenSIPS runtime.
 */

#ifndef LIB_NATS_NATS_CA_DIR_H
#define LIB_NATS_NATS_CA_DIR_H

/**
 * Read every regular .pem file in @dir, concatenate the contents in
 * lexicographic filename order separated by '\n', return as a single
 * nul-terminated buffer the caller frees with libc free().
 *
 * Filename filter: case-sensitive ".pem" suffix.  Non-regular files
 * (symlinks to directories, devices, etc.) are skipped silently.
 *
 * @param dir Directory path to scan (NUL-terminated); NULL or empty
 *            fails with *err set.
 * @param err Optional out-param for a failure reason: on failure set to
 *            a libc-malloc'd human-readable string owned by the caller
 *            (free with libc free()) or to NULL if the message itself
 *            could not be allocated.  Reset to NULL on entry.  Pass
 *            NULL to discard.
 *
 * @return libc-malloc'd PEM concatenation owned by the caller (freed
 *         with libc free(); handed to
 *         natsOptions_SetCATrustedCertificates(), which copies it), or
 *         NULL on any failure (missing dir, no .pem files, OOM, read
 *         error).
 *
 * Locking: none taken.
 * Thread safety: not thread-safe -- holds an open DIR handle and
 * uses dirent's static buffer.  Callers serialise externally.
 * Context: in-tree it runs from nats_pool's TLS option setup
 * (apply_tls_from_mgm) while the calling process establishes its
 * per-process connection; no OpenSIPS allocator or lock is used, so
 * any process or serialised thread may call it.
 */
char *nats_load_ca_directory(const char *dir, char **err);

#endif /* LIB_NATS_NATS_CA_DIR_H */
