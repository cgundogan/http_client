/*
 * Copyright (C) 2012 mbed.org, MIT License
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

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdint.h>

typedef enum {
	HTTP_PROCESSING, ///<Processing
	HTTP_PARSE, ///<url Parse error
	HTTP_DNS, ///<Could not resolve name
	HTTP_PRTCL, ///<Protocol error
	HTTP_NOTFOUND, ///<HTTP 404 Error
	HTTP_REFUSED, ///<HTTP 403 Error
	HTTP_ERROR, ///<HTTP xxx error
	HTTP_TIMEOUT, ///<Connection timeout
	HTTP_CONN, ///<Connection error
	HTTP_CLOSED, ///<Connection was closed by remote host
	HTTP_REDIRECT,
	HTTP_OK = 0, ///<Success
} http_result_t;

typedef enum {
	HTTP_GET,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
	HTTP_HEAD
} http_method_t;

typedef struct {

	/**
	 * tcpsocket
	 */
	int socket;

	/**
	 * host name to fetch from
	 */
	char* host;

	/**
	 * host port to fetch from
	 */
	uint16_t* port;

	/**
	 * path to request
	 */
	char* path;

	/**
	 * method to use, default is HTTP_GET
	 */
	http_method_t method;

	/**
	 * used for HTTP basic authentication
	 */
	char* basicAuthUser;
	char* basicAuthPassword;

	/**
	 Set custom headers for request.

	 Pass NULL, 0 to turn off custom headers.

	 @code
	 const char * hdrs[] =
	 {
	 "Connection", "keep-alive",
	 "Accept", "text/html",
	 "User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64)",
	 "Accept-Encoding", "gzip,deflate,sdch",
	 "Accept-Language", "en-US,en;q=0.8",
	 };

	 http.basicAuth("username", "password");
	 http.customHeaders(hdrs, 5);
	 @endcode

	 @param headers an array (size multiple of two) key-value pairs, must remain valid during the whole HTTP session
	 @param pairs number of key-value pairs
	 */
	const char** m_customHeaders;
	size_t m_nCustomHeaders;

	/**
	 * response code of the http_do operation
	 */
	int httpResponseCode;

	/** Set the maximum number of automated redirections
	 @param i is the number of redirections. Values < 1 are
	 set to 1.
	 */
	int max_redirect;

	/**
	 * url got from previous request
	 */
	char *redirected_to;

	/**
	 * http data, e.g. http post data
	 */
	http_data_t *data;
} http_t;

typedef struct {
	bool chunked;

} http_data_t;

/**
 * create new http object
 */
int http_new(http_t *r);

/**
 * parse url in r
 */
int http_seturl(http_t *r, const char* url);

/**
 * set tcp socket to use
 */
int http_setsocket(http_t *r, int sock);

/**
 * set http method
 */
int http_setmethod(http_t *r, http_method_t m);

/**
 * do the request
 */
http_result_t http_do(http_t *r, char* result, size_t max_len);

#endif
