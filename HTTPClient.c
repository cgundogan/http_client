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

#include "HTTPClient.h"

#define MIN(x,y) (((x)<(y))?(x):(y))
#define MAX(x,y) (((x)>(y))?(x):(y))

#define CHUNK_SIZE 256

#define DEBUG printf

static http_result_t http_recv(char* buf, size_t minLen, size_t maxLen,
		size_t* pReadLen);
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

void http_new(http_t *h) {
	memset(h, 0, sizeof(http_t));

	h->port = 80;
	h->max_redirect = 4;
	h->method = HTTP_GET;
}

void http_setmethod(http_t *h, http_method_t m) {
	h->method = m;
}

http_result_t http_do(http_t *h, char* result, size_t max_len) //const char* url, HTTP_METH method, IHTTPDataOut* pDataOut, IHTTPDataIn* pDataIn, int timeout) //Execute request
		{

	char scheme[8];
	uint16_t port;
	char host[32];
	char path[64];
	size_t recvContentLength = 0;
	bool recvChunked = false;
	int crlfPos = 0;
	char buf[CHUNK_SIZE];
	size_t trfLen;
	int ret = 0;

	//Send request
	snprintf(buf, sizeof(buf),
			"%s %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: keep-alive\r\n",
			h->method, h->path, h->host, h->port); //Write request
	ret = http_send(h, buf, sizeof(buf));
	if (ret) {
		DEBUG("Could not write request");
		return HTTP_CONN;
	}

	// send authorization
	if (h->basicAuthUser && h->basicAuthPassword) {
		strcpy(buf, "Authorization: Basic ");
		http_createauth(h->basicAuthUser, h->basicAuthPassword,
				buf + strlen(buf), sizeof(buf) - strlen(buf));
		strcat(buf, "\r\n");
		DEBUG(" (%s,%s) => (%s)", h->basicAuthUser, h->basicAuthPassword, buf);
		ret = http_send(h, buf, 0);
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
		int size = snprintf(buf, sizeof(buf), "%s: %s\r\n",
				h->customHeaders[nh], h->customHeaders[nh + 1]);
		ret = http_send(h, buf, size);
		if (ret) {
			DEBUG("Could not write request");
			return HTTP_CONN;
		}
		DEBUG(" hdr %d", ret);
	}

	//Send default headers
	DEBUG("Sending headers");
	if (pDataOut != NULL) {
		if (pDataOut->getIsChunked()) {
			ret = http_send(h, "Transfer-Encoding: chunked\r\n", 0);
		} else {
			snprintf(buf, sizeof(buf), "Content-Length: %d\r\n",
					pDataOut->getDataLen());
			ret = http_send(h, buf, 0);
		}
		char type[48];
		if (pDataOut->getDataType(type, 48) == HTTP_OK) {
			snprintf(buf, sizeof(buf), "Content-Type: %s\r\n", type);
			ret = http_send(h, buf, 0);
		}
	}

	//Close headers
	DEBUG("Headers sent");
	ret = http_send(h, "\r\n", 0);

	//Send data (if available)
	if (pDataOut != NULL) {
		DEBUG("Sending data");
		while (true) {
			size_t writtenLen = 0;
			pDataOut->read(buf, CHUNK_SIZE, &trfLen);
			if (pDataOut->getIsChunked()) {
				//Write chunk header
				char chunkHeader[16];
				snprintf(chunkHeader, sizeof(chunkHeader), "%X\r\n", trfLen); //In hex encoding
				ret = gttp_send(h, chunkHeader, 0);
			} else if (trfLen == 0) {
				break;
			}
			if (trfLen != 0) {
				ret = http_send(h, buf, trfLen);
			}

			if (pDataOut->getIsChunked()) {
				ret = http_send(h, "\r\n", 0); //Chunk-terminating CRLF
			} else {
				writtenLen += trfLen;
				if (writtenLen >= pDataOut->getDataLen()) {
					break;
				}
			}

			if (trfLen == 0) {
				break;
			}
		}

	}

	//Receive response
	DEBUG("Receiving response");
	//ret = recv(buf, CHUNK_SIZE - 1, CHUNK_SIZE - 1, &trfLen); //Read n bytes
	ret = http_recv(buf, 1, CHUNK_SIZE - 1, &trfLen); // recommended by Rob Noble to avoid timeout wait
	buf[trfLen] = '\0';
	DEBUG("Received \r\n(%s\r\n)", buf);

	char* crlfPtr = strstr(buf, "\r\n");
	if (crlfPtr == NULL) {
		return -1;
	}

	crlfPos = crlfPtr - buf;
	buf[crlfPos] = '\0';

	//Parse HTTP response
	if (sscanf(buf, "HTTP/%*d.%*d %d %*[^\r\n]", &h->httpResponseCode) != 1) {
		//Cannot match string, error
		DEBUG("Not a correct HTTP answer : {%s}\n", buf);
	}

	if ((h->httpResponseCode < 200) || (h->httpResponseCode >= 400)) {
		//Did not return a 2xx code; TODO fetch headers/(&data?) anyway and implement a mean of writing/reading headers
		DEBUG("Response code %d", h->httpResponseCode);
	}

	DEBUG("Reading headers");

	memmove(buf, &buf[crlfPos + 2], trfLen - (crlfPos + 2) + 1); //Be sure to move NULL-terminating char as well
	trfLen -= (crlfPos + 2);

	recvContentLength = 0;
	recvChunked = false;
	//Now get headers
	while (true) {
		crlfPtr = strstr(buf, "\r\n");
		if (crlfPtr == NULL) {
			if (trfLen < CHUNK_SIZE - 1) {
				size_t newTrfLen = 0;
				ret = http_recv(buf + trfLen, 1, CHUNK_SIZE - trfLen - 1,
						&newTrfLen);
				trfLen += newTrfLen;
				buf[trfLen] = '\0';
				DEBUG("Read %d chars; In buf: [%s]", newTrfLen, buf);
				continue;
			} else {
				return -1;
			}
		}

		crlfPos = crlfPtr - buf;

		if (crlfPos == 0) { //End of headers
			DEBUG("Headers read");
			memmove(buf, &buf[2], trfLen - 2 + 1); //Be sure to move NULL-terminating char as well
			trfLen -= 2;
			break;
		}

		buf[crlfPos] = '\0';

		char key[32];
		char value[64];

		key[31] = '\0';
		value[63] = '\0';

		int n = sscanf(buf, "%31[^:]: %63[^\r\n]", key, value);
		if (n == 2) {
			DEBUG("Read header : %s: %s", key, value);
			if (!strcmp(key, "Content-Length")) {
				sscanf(value, "%d", &recvContentLength);
				pDataIn->setDataLen(recvContentLength);
			} else if (!strcmp(key, "Transfer-Encoding")) {
				if (!strcmp(value, "Chunked") || !strcmp(value, "chunked")) {
					recvChunked = true;
					pDataIn->setIsChunked(true);
				}
			} else if (!strcmp(key, "Content-Type")) {
				pDataIn->setDataType(value);
			} else if (!strcmp(key, "Location")) {
				if (m_location)
					free (m_location);
				m_location = (char *) malloc(strlen(value) + 1);
				if (m_location) {
					strcpy(m_location, value);
					url = m_location;
					INFO("Following redirect[%d] to [%s]", maxRedirect, url);
					m_sock.close();
					takeRedirect = true;
					break; // exit the while(true) header to follow the redirect
				}
			}

			memmove(buf, &buf[crlfPos + 2], trfLen - (crlfPos + 2) + 1); //Be sure to move NULL-terminating char as well
			trfLen -= (crlfPos + 2);

		} else {
			DEBUG("Could not parse header");
		}

	}

	//Receive data
	DEBUG("Receiving data");
	while (true) {
		size_t readLen = 0;

		if (recvChunked) {
			//Read chunk header
			bool foundCrlf;
			do {
				foundCrlf = false;
				crlfPos = 0;
				buf[trfLen] = 0;
				if (trfLen >= 2) {
					for (; crlfPos < trfLen - 2; crlfPos++) {
						if (buf[crlfPos] == '\r' && buf[crlfPos + 1] == '\n') {
							foundCrlf = true;
							break;
						}
					}
				}
				if (!foundCrlf) { //Try to read more
					if (trfLen < CHUNK_SIZE) {
						size_t newTrfLen = 0;
						ret = http_recv(buf + trfLen, 0,
								CHUNK_SIZE - trfLen - 1, &newTrfLen);
						trfLen += newTrfLen;
						continue;
					} else {
						return -1;
					}
				}
			} while (!foundCrlf);
			buf[crlfPos] = '\0';
			int n = sscanf(buf, "%x", &readLen);
			if (n != 1) {
				DEBUG("Could not read chunk length");
				return -1;
			}

			memmove(buf, &buf[crlfPos + 2], trfLen - (crlfPos + 2)); //Not need to move NULL-terminating char any more
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
			pDataIn->write(buf, MIN(trfLen, readLen));
			if (trfLen > readLen) {
				memmove(buf, &buf[readLen], trfLen - readLen);
				trfLen -= readLen;
				readLen = 0;
			} else {
				readLen -= trfLen;
			}

			if (readLen) {
				ret = http_recv(buf, 1, CHUNK_SIZE - trfLen - 1, &trfLen);
			}
		} while (readLen);

		if (recvChunked) {
			if (trfLen < 2) {
				size_t newTrfLen;
				//Read missing chars to find end of chunk
				ret = http_recv(buf + trfLen, 2 - trfLen,
						CHUNK_SIZE - trfLen - 1, &newTrfLen);
				trfLen += newTrfLen;
			}
			if ((buf[0] != '\r') || (buf[1] != '\n')) {
				DEBUG("Format error");
				return -1;
			}
			memmove(buf, &buf[2], trfLen - 2);
			trfLen -= 2;
		} else {
			break;
		}

	}

	DEBUG("Completed HTTP transaction");
	return HTTP_OK;
}

static http_result_t http_recv(char* buf, size_t minLen, size_t maxLen,
		size_t* pReadLen) //0 on success, err code on failure
		{
	DEBUG("Trying to read between %d and %d bytes", minLen, maxLen);
	size_t readLen = 0;

	int ret;
	while (readLen < maxLen) {
		if (readLen < minLen) {
			DEBUG("Trying to read at most %d bytes [Blocking]",
					minLen - readLen);
			ret = m_sock.receive_all(buf + readLen, minLen - readLen);
		}

		if (ret > 0) {
			readLen += ret;
		} else if (ret == 0) {
			break;
		} else {
			if (!m_sock.is_connected()) {
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

	int ret = m_sock.send_all(buf, len);
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

http_result_t http_seturl(const http_t *h, const char* url) //, char* scheme, size_t maxSchemeLen, char* host, size_t maxHostLen, uint16_t* port, char* path, size_t maxPathLen) //Parse URL
		{
	char* schemePtr = (char*) url;
	char* hostPtr = (char*) strstr(url, "://");
	if (hostPtr == NULL) {
		DEBUG("Could not find host");
		return HTTP_PARSE; //URL is invalid
	}

	if (maxSchemeLen < hostPtr - schemePtr + 1) { //including NULL-terminating char
		DEBUG("Scheme str is too small (%d >= %d)", maxSchemeLen,
				hostPtr - schemePtr + 1);
		return HTTP_PARSE;
	}
	memcpy(scheme, schemePtr, hostPtr - schemePtr);
	scheme[hostPtr - schemePtr] = '\0';

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
	} else {
		*port = 0;
	}
	char* pathPtr = strchr(hostPtr, '/');
	if (hostLen == 0) {
		hostLen = pathPtr - hostPtr;
	}

	if (maxHostLen < hostLen + 1) { //including NULL-terminating char
		DEBUG("Host str is too small (%d >= %d)", maxHostLen, hostLen + 1);
		return HTTP_PARSE;
	}
	memcpy(host, hostPtr, hostLen);
	host[hostLen] = '\0';

	size_t pathLen;
	char* fragmentPtr = strchr(hostPtr, '#');
	if (fragmentPtr != NULL) {
		pathLen = fragmentPtr - pathPtr;
	} else {
		pathLen = strlen(pathPtr);
	}

	if (maxPathLen < pathLen + 1) { //including NULL-terminating char
		DEBUG("Path str is too small (%d >= %d)", maxPathLen, pathLen + 1);
		return HTTP_PARSE;
	}
	memcpy(path, pathPtr, pathLen);
	path[pathLen] = '\0';

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
