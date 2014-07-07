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

#include <arpa/inet.h>

#include "HTTPClient.h"

char print_buf[1000];
#define HOST "bing.com"
#define IP "204.79.197.200"

int open_tcp_connection(void) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
		return -1;
	}
	struct in_addr addr;
	inet_aton(IP, &addr);

	int ret = connect(sockfd, (struct sockaddr *) &addr, sizeof(struct in_addr));
	if (ret < 0) {
		perror("ERROR connecting");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

void on_data(http_t *h, http_data_t *d) {
	memset(print_buf, 0, 1000);

	if (d->size != 0) {
		memcpy(print_buf, d->data, d->size);
		print_buf[d->size] = '\0';
		printf("chunk: '%s'\n", print_buf);
	} else {
		printf("end...\n");
	}
}

int main(void) {
	http_t h;
	http_init(&h);

	http_seturl(&h, "http://" HOST "/");

	http_result_t r = HTTP_PROCESSING;
	while (r != HTTP_OK && h.max_redirect--) {
		/* TODO: do dns querry */
		/* TODO: open socket to host */
		http_setsocket(&h, open_tcp_connection());
		r = http_do(&h, on_data);

		if (r == HTTP_REDIRECT) {
			http_seturl(&h, h.redirected_to);
		}
	}

	if (r == HTTP_OK) {
		printf("HTTP DONE\n");
	}
}
