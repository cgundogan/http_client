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

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "HTTPClient.h"

#define MIN(x,y) (((x)<(y))?(x):(y))
#define MAX(x,y) (((x)>(y))?(x):(y))

#define DEBUG printf

static http_result_t http_recv(http_t *h, char* buf, size_t minLen, size_t maxLen,
		size_t* pReadLen); //0 on success, err code on failure
static http_result_t http_send(http_t *h, char* buf, size_t len);
static void http_createauth(const char *user, const char *pwd, char *buf,
		int len);
static int http_base64enc(const char *input, unsigned int length, char *output,
		int len);

char *http_method(http_method_t m) {
	switch (m) {
	case (HTTP_GET):
		return "GET";
	case (HTTP_POST):
		return "POST";
	case (HTTP_PUT):
		return "PUT";
	case (HTTP_DELETE):
		return "DELETE";
	default:
		return "ERROR";
	}
}

void http_init(http_t *h) {
	memset(h, 0, sizeof(http_t));

	h->port = 80;
	h->max_redirect = 4;
	h->method = HTTP_GET;
}

void http_setmethod(http_t *h, http_method_t m) {
	h->method = m;
}

char http_io_buf[HTTP_CHUNK_SIZE];

http_result_t http_do(http_t *h, http_on_data_cb_t *cb)
{
	size_t recvContentLength = 0;
	int crlfPos = 0;

	size_t trfLen;
	int ret = 0;

	//Send request
	snprintf(http_io_buf, sizeof(http_io_buf),
			"%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: keep-alive\r\n",
			h->method, h->path, h->host, h->port); //Write request
	ret = http_send(h, http_io_buf, sizeof(http_io_buf));
	if (ret) {
		DEBUG("Could not write request");
		return HTTP_CONN;
	}

	// send authorization
	if (h->basicAuthUser && h->basicAuthPassword) {
		strcpy(http_io_buf, "Authorization: Basic ");
		http_createauth(h->basicAuthUser, h->basicAuthPassword,
				http_io_buf + strlen(http_io_buf), sizeof(http_io_buf) - strlen(http_io_buf));
		strcat(http_io_buf, "\r\n");
		DEBUG(" (%s,%s) => (%s)", h->basicAuthUser, h->basicAuthPassword, http_io_buf);
		ret = http_send(h, http_io_buf, 0);
		DEBUG(" ret = %d", ret);
		if (ret) {
			DEBUG("Could not write request");
			return HTTP_CONN;
		}
	}

	//Send all headers
	DEBUG("Send custom header(s) %d (if any)", h->customHeaders);
	for (size_t nh = 0; nh < h->nCustomHeaders * 2; nh += 2) {
		DEBUG("hdr[%d] %s:", nh, h->customHeaders[nh]);
		DEBUG("        %s", h->customHeaders[nh + 1]);
		int size = snprintf(http_io_buf, sizeof(http_io_buf), "%s: %s\r\n",
				h->customHeaders[nh], h->customHeaders[nh + 1]);
		ret = http_send(h, http_io_buf, size);
		if (ret) {
			DEBUG("Could not write request");
			return HTTP_CONN;
		}
		DEBUG(" hdr %d", ret);
	}

	//Send default headers
	DEBUG("Sending headers");
	if (h->data != NULL) {
		if (h->data->chunked) {
			ret = http_send(h, "Transfer-Encoding: chunked\r\n", 0);
		} else {
			snprintf(http_io_buf, sizeof(http_io_buf), "Content-Length: %d\r\n",
					h->data->size);
			ret = http_send(h, http_io_buf, 0);
		}

		snprintf(http_io_buf, sizeof(http_io_buf), "Content-Type: %s\r\n", h->data->type);
		ret = http_send(h, http_io_buf, 0);
	}

	//Close headers
	DEBUG("Headers sent");
	ret = http_send(h, "\r\n", 0);

	//Send data (if available)
	if (h->data != NULL) {
		DEBUG("Sending data");
		int pos = 0;
		while (pos != h->data->size) {
			pos += http_send(h, h->data->data[pos], h->data->size - pos);
		}
	}

	//Receive response
	DEBUG("Receiving response");
	//ret = recv(buf, CHUNK_SIZE - 1, CHUNK_SIZE - 1, &trfLen); //Read n bytes
	ret = http_recv(http_io_buf, 1, HTTP_CHUNK_SIZE - 1, &trfLen); // recommended by Rob Noble to avoid timeout wait
	http_io_buf[trfLen] = '\0';
	DEBUG("Received \r\n(%s\r\n)", http_io_buf);

	char* crlfPtr = strstr(http_io_buf, "\r\n");
	if (crlfPtr == NULL) {
		return -1;
	}

	crlfPos = crlfPtr - http_io_buf;
	http_io_buf[crlfPos] = '\0';

	//Parse HTTP response
	if (sscanf(http_io_buf, "HTTP/%*d.%*d %d %*[^\r\n]", &h->httpResponseCode) != 1) {
		//Cannot match string, error
		DEBUG("Not a correct HTTP answer : {%s}\n", http_io_buf);
	}

	if ((h->httpResponseCode < 200) || (h->httpResponseCode >= 400)) {
		//Did not return a 2xx code; TODO fetch headers/(&data?) anyway and implement a mean of writing/reading headers
		DEBUG("Response code %d", h->httpResponseCode);
	}

	DEBUG("Reading headers");

	memmove(http_io_buf, &http_io_buf[crlfPos + 2], trfLen - (crlfPos + 2) + 1); //Be sure to move NULL-terminating char as well
	trfLen -= (crlfPos + 2);

	recvContentLength = 0;
	//Now get headers
	while (true) {
		crlfPtr = strstr(http_io_buf, "\r\n");
		if (crlfPtr == NULL) {
			if (trfLen < HTTP_CHUNK_SIZE - 1) {
				size_t newTrfLen = 0;
				ret = http_recv(http_io_buf + trfLen, 1, HTTP_CHUNK_SIZE - trfLen - 1,
						&newTrfLen);
				trfLen += newTrfLen;
				http_io_buf[trfLen] = '\0';
				DEBUG("Read %d chars; In buf: [%s]", newTrfLen, http_io_buf);
				continue;
			} else {
				return -1;
			}
		}

		crlfPos = crlfPtr - http_io_buf;

		if (crlfPos == 0) { //End of headers
			DEBUG("Headers read");
			memmove(http_io_buf, &http_io_buf[2], trfLen - 2 + 1); //Be sure to move NULL-terminating char as well
			trfLen -= 2;
			break;
		}

		http_io_buf[crlfPos] = '\0';

		char key[32];
		char value[64];

		key[31] = '\0';
		value[63] = '\0';

		http_data_t data;

		int n = sscanf(http_io_buf, "%31[^:]: %63[^\r\n]", key, value);
		if (n == 2) {
			DEBUG("Read header : %s: %s", key, value);
			if (!strcmp(key, "Content-Length")) {
				sscanf(value, "%d", &recvContentLength);
				data.size = recvContentLength;
			} else if (!strcmp(key, "Transfer-Encoding")) {
				if (!strcmp(value, "Chunked") || !strcmp(value, "chunked")) {
					data.chunked = true;
					h->chunked_response = true;
				}
			} else if (!strcmp(key, "Content-Type")) {
				data.type = value;
			} else if (!strcmp(key, "Location")) {
				if (h->redirected_to)
					free(h->redirected_to);
				h->redirected_to = (char *) malloc(strlen(value) + 1);
				if (h->redirected_to) {
					strcpy(h->redirected_to, value);
					INFO("Following redirect[%d] to [%s]", h->max_redirect, h->redirected_to);
					break; // exit the while(true) header to follow the redirect
				}
			}

			memmove(http_io_buf, &http_io_buf[crlfPos + 2], trfLen - (crlfPos + 2) + 1); //Be sure to move NULL-terminating char as well
			trfLen -= (crlfPos + 2);

		} else {
			DEBUG("Could not parse header");
		}

	}

	//Receive data
	DEBUG("Receiving data");
	while (true) {
		size_t readLen = 0;

		if (h->chunked_response) {
			//Read chunk header
			bool foundCrlf;
			do {
				foundCrlf = false;
				crlfPos = 0;
				http_io_buf[trfLen] = 0;
				if (trfLen >= 2) {
					for (; crlfPos < trfLen - 2; crlfPos++) {
						if (http_io_buf[crlfPos] == '\r' && http_io_buf[crlfPos + 1] == '\n') {
							foundCrlf = true;
							break;
						}
					}
				}
				if (!foundCrlf) { //Try to read more
					if (trfLen < HTTP_CHUNK_SIZE) {
						size_t newTrfLen = 0;
						ret = http_recv(http_io_buf + trfLen, 0,
						HTTP_CHUNK_SIZE - trfLen - 1, &newTrfLen);
						trfLen += newTrfLen;
						continue;
					} else {
						return -1;
					}
				}
			} while (!foundCrlf);
			http_io_buf[crlfPos] = '\0';
			int n = sscanf(http_io_buf, "%x", &readLen);
			if (n != 1) {
				DEBUG("Could not read chunk length");
				return -1;
			}

			memmove(http_io_buf, &http_io_buf[crlfPos + 2], trfLen - (crlfPos + 2)); //Not need to move NULL-terminating char any more
			trfLen -= (crlfPos + 2);

			if (readLen == 0) {
				//Last chunk
				break;
			}
		} else {
			readLen = recvContentLength;
		}

		DEBUG("Retrieving %d bytes", readLen);

		do {
			http_data_t *data;
			data->data = http_io_buf;
			data->size = MIN(trfLen, readLen);
			cb(h, data);
			if (trfLen > readLen) {
				memmove(http_io_buf, &http_io_buf[readLen], trfLen - readLen);
				trfLen -= readLen;
				readLen = 0;
			} else {
				readLen -= trfLen;
			}

			if (readLen) {
				ret = http_recv(http_io_buf, 1, HTTP_CHUNK_SIZE - trfLen - 1, &trfLen);
			}
		} while (readLen);

		if (h->chunked_response) {
			if (trfLen < 2) {
				size_t newTrfLen;
				//Read missing chars to find end of chunk
				ret = http_recv(http_io_buf + trfLen, 2 - trfLen,
				HTTP_CHUNK_SIZE - trfLen - 1, &newTrfLen);
				trfLen += newTrfLen;
			}
			if ((http_io_buf[0] != '\r') || (http_io_buf[1] != '\n')) {
				DEBUG("Format error");
				return -1;
			}
			memmove(http_io_buf, &http_io_buf[2], trfLen - 2);
			trfLen -= 2;
		} else {
			break;
		}

	}

	DEBUG("Completed HTTP transaction");
	return HTTP_OK;
}

static http_result_t http_recv(http_t *h, char* buf, size_t minLen, size_t maxLen,
		size_t* pReadLen) //0 on success, err code on failure
{
	DEBUG("Trying to read between %d and %d bytes", minLen, maxLen);
	size_t readLen = 0;

	int ret;
	while (readLen < maxLen) {
		if (readLen < minLen) {
			DEBUG("Trying to read at most %d bytes [Blocking]",
					minLen - readLen);
			ret = read(h->socket, buf + readLen, minLen - readLen);
		}

		if (ret > 0) {
			readLen += ret;
		} else if (ret == 0) {
			break;
		} else {
			int error = 0;
			socklen_t len = sizeof (error);
			int retval = getsockopt (h->socket, SOL_SOCKET, SO_ERROR, &error, &len );
			if (!retval) {
				DEBUG("Connection error (recv returned %d)", ret);
				*pReadLen = readLen;
				return HTTP_CONN;
			} else {
				break;
			}
		}

	}
	DEBUG("Read %d bytes", readLen);
	*pReadLen = readLen;
	return HTTP_OK;
}

static http_result_t http_send(http_t *h, char* buf, size_t len) //0 on success, err code on failure
{
	if (len == 0) {
		len = strlen(buf);
	}
	DEBUG("send(%s,%d)", buf, len);
	size_t writtenLen = 0;

	int ret = write(h->socket, buf, len);
	if (ret > 0) {
		writtenLen += ret;
	} else if (ret == 0) {
		DEBUG("Connection was closed by server");
		return HTTP_CLOSED; //Connection was closed by server
	} else {
		DEBUG("Connection error (send returned %d)", ret);
		return HTTP_CONN;
	}

	DEBUG("Written %d bytes", writtenLen);
	return HTTP_OK;
}

int http_seturl(http_t *h, char* url) //, char* scheme, size_t maxSchemeLen, char* host, size_t maxHostLen, uint16_t* port, char* path, size_t maxPathLen) //Parse URL
{
	char* schemePtr = (char*) url;
	char* hostPtr = (char*) strstr(url, "://");
	if (hostPtr == NULL) {
		DEBUG("Could not find host");
		return HTTP_PARSE; //URL is invalid
	}

	hostPtr += 3;

	size_t hostLen = 0;

	char* portPtr = strchr(hostPtr, ':');
	if (portPtr != NULL) {
		hostLen = portPtr - hostPtr;
		portPtr++;
		if (sscanf(portPtr, "%hu", h->port) != 1) {
			DEBUG("Could not find port");
			return HTTP_PARSE;
		}
	}
	char* pathPtr = strchr(hostPtr, '/');
	if (hostLen == 0) {
		hostLen = pathPtr - hostPtr;
	}

	h->host = strdup(hostPtr);
	h->host[hostLen] = '\0';

	size_t pathLen;
	char* fragmentPtr = strchr(hostPtr, '#');
	if (fragmentPtr != NULL) {
		pathLen = fragmentPtr - pathPtr;
	} else {
		pathLen = strlen(pathPtr);
	}

	h->path = strdup(pathPtr);
	h->path[pathLen] = '\0';

	return HTTP_OK;
}

static void http_createauth(const char *user, const char *pwd, char *buf,
		int len) {
	char tmp[80];

	snprintf(tmp, sizeof(tmp), "%s:%s", user, pwd);
	http_base64enc(tmp, strlen(tmp), &buf[strlen(buf)], len - strlen(buf));
}

// Copyright (c) 2010 Donatien Garnier (donatiengar [at] gmail [dot] com)
static int http_base64enc(const char *input, unsigned int length, char *output,
		int len) {
	static const char base64[] =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	unsigned int c, c1, c2, c3;

	if (len < ((((length - 1) / 3) + 1) << 2))
		return -1;
	for (unsigned int i = 0, j = 0; i < length; i += 3, j += 4) {
		c1 = ((((unsigned char) *((unsigned char *) &input[i]))));
		c2 = (length > i + 1) ?
				((((unsigned char) *((unsigned char *) &input[i + 1])))) : 0;
		c3 = (length > i + 2) ?
				((((unsigned char) *((unsigned char *) &input[i + 2])))) : 0;

		c = ((c1 & 0xFC) >> 2);
		output[j + 0] = base64[c];
		c = ((c1 & 0x03) << 4) | ((c2 & 0xF0) >> 4);
		output[j + 1] = base64[c];
		c = ((c2 & 0x0F) << 2) | ((c3 & 0xC0) >> 6);
		output[j + 2] = (length > i + 1) ? base64[c] : '=';
		c = (c3 & 0x3F);
		output[j + 3] = (length > i + 2) ? base64[c] : '=';
	}
	output[(((length - 1) / 3) + 1) << 2] = '\0';
	return 0;
}
