/*
 *  ser2nets-http - A program for allowing HTTP connection to serial ports
 *  Copyright (C) 2011  Longshine <longxianghe@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __HTTP_H__
#define __HTTP_H__

#include "buffer.h"

#define HTTP_BUFSIZE    1024

#define HTTP_UNCONNECTED 0
#define HTTP_CONNECTING 1
#define HTTP_CONNECTED 2
#define HTTP_CLOSING 3

#ifdef WORDS_BIGENDIAN
typedef struct ws_hdr_s {
  unsigned char FIN:1;
  unsigned char RSV1:1;
  unsigned char RSV2:1;
  unsigned char RSV3:1;
  unsigned char opcode:4;
  unsigned char MASK:1;
  unsigned char length:7;
} ws_hdr_t;

typedef union ws_length_s {
  unsigned int len64;
  unsigned int len16:16;
  struct {
    unsigned char MASK:1;
    unsigned char len7:7;
  };
} ws_length_t;
#else
typedef struct ws_hdr_s {
  unsigned char opcode:4;
  unsigned char RSV3:1;
  unsigned char RSV2:1;
  unsigned char RSV1:1;
  unsigned char FIN:1;
  unsigned char length:7;
  unsigned char MASK:1;
} ws_hdr_t;

typedef union ws_length_s {
  unsigned char len7:7;
  unsigned int len16:16;
  unsigned int len64;
} ws_length_t;
#endif

typedef struct ws_pdu_s {
  ws_hdr_t *hdr;
  ws_length_t *len;
  unsigned char *mask;
  unsigned char *payload;
  unsigned int index;
  unsigned int left;
  unsigned char buf[HTTP_BUFSIZE];
} ws_frame_t;

typedef struct http_data_s
{
  int state;
  struct sbuf request;
  unsigned char request_buf[HTTP_BUFSIZE];
  struct sbuf response;
  unsigned char response_buf[HTTP_BUFSIZE];
  void *cb_data;
  void (*output_ready)(void *cb_data);
  int (*handle_request)(void *cb_data, unsigned char *buf, int size);
  char websocket_key[32];
  ws_frame_t ws_frame;
} http_data_t;

void http_init(http_data_t *hd, void *cb_data,
               void (*output_ready)(void *),
               int (*handle_request)(void *, unsigned char *, int));
char* http_process_request(http_data_t *hd, int fd);
char* http_process_response(http_data_t *hd, unsigned char *buf, int len);

#endif /* __HTTP_H__ */
