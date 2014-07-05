/*
 * Copyright (C) 2014, Christian Mehlis, Freie Universität Berlin
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       HTTP example implementation
 *
 * @author      Christian Mehlis <mehlis@inf.fu-berlin.de>
 *
 * @}
 */

#include "HTTPClient.h"

char buf[1000];
#define URL "http://google.com/"

int sock = 0;

int main(void) {
	http_t h;
	http_new(&h);

	http_seturl(&h, URL);
	http_setsocket(&h, sock);

	memset(buf, 0, sizeof(buf));

	http_result_t r = HTTP_PROCESSING;
	while (r != HTTP_OK && h.max_redirect--) {
		r = http_do(&h, buf, sizeof(buf));

		if (r == HTTP_REDIRECT) {
			http_seturl(&h, h.redirected_to);
			http_setsocket(&h, sock); /*   TODO: open new tcp socket to host */
		}
	}

	printf("RESULT %s: %s", http_result(r), buf);
}
