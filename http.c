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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>

#include "selector.h"
#include "http.h"
#include "sha1.h"

#define D(...) printf(__VA_ARGS__);

#define IS_WEBSOCKET(hd) hd->websocket_key[0]

#define WEBSOCKET_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define WEBSOCKET_OPCODE_CTN 0x0
#define WEBSOCKET_OPCODE_TXT 0x1
#define WEBSOCKET_OPCODE_BIN 0x2
#define WEBSOCKET_OPCODE_CLOSE 0x8
#define WEBSOCKET_OPCODE_PING 0x9
#define WEBSOCKET_OPCODE_PONG 0xA
#define WEBSOCKET_DEFAULT_OPCODE WEBSOCKET_OPCODE_TXT

#define WEBSOCKET_HEADER_SIZE 2
#define WEBSOCKET_MASK_SIZE 4
#define WEBSOCKET_UNEXTENDED_MAX_LEN 0x7D
#define WEBSOCKET_EXT16_LENGTH 0x7E
#define WEBSOCKET_EXT16_MAX_LEN 0xFFFF
#define WEBSOCKET_EXT16_SIZE 2
#define WEBSOCKET_EXT64_LENGTH 0x7F
#define WEBSOCKET_EXT64_SIZE 8
#define WEBSOCKET_UNEXTENDED(frm) ((frm)->hdr->length < WEBSOCKET_EXT16_LENGTH)
#define WEBSOCKET_EXT16(frm) (WEBSOCKET_EXT16_LENGTH == ((frm)->hdr->length & 0xFF))
#define WEBSOCKET_EXT64(frm) (WEBSOCKET_EXT64_LENGTH == ((frm)->hdr->length & 0xFF))
#define WEBSOCKET_LENGTH(frm) ((frm)->len ? (WEBSOCKET_UNEXTENDED(frm) ? (frm)->len->len7 : (WEBSOCKET_EXT16(frm) ? ntohs((frm)->len->len16) : (frm)->len->len64)) : (frm)->hdr->length)
#define WEBSOCKET_MASKED(frm) (frm->hdr->MASK)
#define WEBSOCKET_FRAME_SIZE(frm) WEBSOCKET_LENGTH(frm) + WEBSOCKET_HEADER_SIZE \
                                  + (WEBSOCKET_UNEXTENDED(frm) ? 0 : (WEBSOCKET_EXT16(frm) ? WEBSOCKET_EXT16_SIZE : WEBSOCKET_EXT64_SIZE)) \
                                  + (WEBSOCKET_MASKED(frm) ? WEBSOCKET_MASK_SIZE : 0)
#define WEBSOCKET_GET_CLOSE_REASON(frm) (ntohs(*(unsigned short *) (frm)->payload))
#define WEBSOCKET_SET_CLOSE_REASON(frm, rsn) *(unsigned short *) (frm)->payload = htons(rsn)

#define MIN(you, me) (you < me ? you : me)

extern selector_t *ser2net_sel;

static char *http_response_header      = "HTTP/1.1 200 OK\r\n" \
                                         "Server: ser2net\r\n" \
                                         "Content-type: text/plain\r\n" \
                                         "\r\n";

static char *websocket_response_header = "HTTP/1.1 101 Switching Protocols\r\n" \
                                         "Upgrade: websocket\r\n" \
                                         "Connection: Upgrade\r\n" \
                                         "Sec-WebSocket-Accept: %s\r\n" \
                                         "Server: ser2net\r\n" \
                                         "\r\n";

static int
sha1(char *src, int src_len, char *dest, int dest_len)
{
  SHA1Context sha;
  int i;

  SHA1Reset(&sha);
  SHA1Input(&sha, (const unsigned char *) src, src_len);
  SHA1Result(&sha);

  for (i = 0; i < 5; i++) {
    *(dest++) = sha.Message_Digest[i] >> 24;
    *(dest++) = sha.Message_Digest[i] >> 16;
    *(dest++) = sha.Message_Digest[i] >> 8;
    *(dest++) = sha.Message_Digest[i];
  }

  return 20;
}

static void
base64_encode(char *src, int src_len, char *dest, int dest_len)
{
  static char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

  // Create data and output buffers
  int dataBuffer[3];
  int outputBuffer[4];
  int pos, i;

  // while there are still bytes to be processed
  for (pos = 0; pos < src_len;) {
    memset(dataBuffer, 0, sizeof(dataBuffer));

    // Create new data buffer and populate next 3 bytes from data
    for (i = 0; i < 3 && pos < src_len; i++) {
      dataBuffer[i] = src[pos++] & 0xFF;
    }

    // Convert to data buffer Base64 character positions and
    // store in output buffer
    outputBuffer[0] = (dataBuffer[0] & 0xfc) >> 2;
    outputBuffer[1] = ((dataBuffer[0] & 0x03) << 4) | ((dataBuffer[1]) >> 4);
    outputBuffer[2] = ((dataBuffer[1] & 0x0f) << 2) | ((dataBuffer[2]) >> 6);
    outputBuffer[3] = dataBuffer[2] & 0x3f;

    // If data buffer was short (i.e not 3 characters) then set
    // end character indexes in data buffer to index of '=' symbol.
    // This is necessary because Base64 data is always a multiple of
    // 4 bytes and is basses with '=' symbols.
    for (; i < 3; i++) {
      outputBuffer[i + 1] = 64;
    }

    // Loop through output buffer and add Base64 characters to
    // encoded data string for each character.
    for (i = 0; i < 4; i++) {
      *(dest++) = base64_chars[outputBuffer[i]];
    }
  }
  *dest = '\0';
}

static void
ws_init_frame(ws_frame_t *frm)
{
  memset(frm, 0, sizeof(ws_frame_t));
  frm->hdr = (ws_hdr_t *) frm->buf;
  frm->hdr->FIN = 1;
  frm->hdr->opcode = WEBSOCKET_DEFAULT_OPCODE;
  frm->left = -1;
}

static void
ws_set_payload_length(ws_frame_t *frm, unsigned int len)
{
  frm->payload = (unsigned char *)frm->hdr + WEBSOCKET_HEADER_SIZE;
  if (len <= WEBSOCKET_UNEXTENDED_MAX_LEN) {
    frm->hdr->length = len;
    frm->len = (ws_length_t *) (frm->payload - 1);
  } else if (len <= WEBSOCKET_EXT16_MAX_LEN){
    frm->hdr->length = WEBSOCKET_EXT16_LENGTH;
    frm->len = (ws_length_t *) frm->payload;
    frm->len->len16 = htons((unsigned short) len);
    frm->payload += WEBSOCKET_EXT16_SIZE;
  } else {
    // TODO set extended length
  }
  if (WEBSOCKET_MASKED(frm)) {
    frm->mask = frm->payload;
    frm->payload = frm->mask + WEBSOCKET_MASK_SIZE;
  }
  frm->left = WEBSOCKET_LENGTH(frm);
}

static void
ws_append_payload(ws_frame_t *frm, const unsigned char *data, unsigned int len)
{
  int i;
//  if (!frm->payload)
//    ws_set_payload_length(frm, frm->length);
  /* make sure that len <= left buffer size */
  if (len > frm->left)
    len = frm->left;
  for (i = 0; i < len; i++)
    frm->payload[frm->index++] = data[i];
  frm->left = WEBSOCKET_LENGTH(frm) - frm->index;
}

static void
ws_unmask(ws_frame_t *frm)
{
  unsigned int i;
  int len = WEBSOCKET_LENGTH(frm);
  for (i = 0; i < len; i++) {
    frm->payload[i] = frm->payload[i] ^ frm->mask[i % WEBSOCKET_MASK_SIZE];
  }
}

static void
ws_print_frame(ws_frame_t *frm)
{
  int i;
  unsigned char *hdr = (unsigned char *) frm->hdr;
  D("FIN: %x, RSV1: %d, RSV2: %d, RSV3: %d, opcode: %d, MASK: %d, length: %d\n",
          frm->hdr->FIN, frm->hdr->RSV1, frm->hdr->RSV2, frm->hdr->RSV3,
          frm->hdr->opcode, frm->hdr->MASK, WEBSOCKET_LENGTH(frm))
  if (WEBSOCKET_MASKED(frm) && frm->mask) {
    D("mask key:")
    for (i = 0; i < WEBSOCKET_MASK_SIZE; i++) {
      D(" %02x", frm->mask[i])
    }
    D("\n")
  }
  if (frm->payload) {
    D("payload: %s\n", frm->payload)
  }
  while (*hdr) {
    D("%02x ", *(hdr++))
  }
  D("\n")
}

static int
get_header_name(char *line, char *name_buf, int len)
{
  char *colon;

  /* Find the : */
  colon = strchr (line, ':');

  /* If there's no :, it's no header */
  if (!colon)
    return 0;

  /* If we have space in the destination to fit this header */
  if ((colon - line) < len) {
    /* Copy it there */
    strncpy(name_buf, line, colon - line);
    name_buf[colon - line] = '\0';

    /* Uppercase it all */
    for (colon = name_buf; *colon; colon++)
      *colon = toupper(*colon);
    return 1;
  }
  return 0;
}

static void
prepare_response_headers(http_data_t *hd, int fd)
{
  if (IS_WEBSOCKET(hd)) {
    /* websocket key negotiation */
    char out[128] = "", tmp[32] = "";
    int len;
    strcpy(out, hd->websocket_key);
    strcat(out, WEBSOCKET_GUID);
    len = sha1(out, strlen(out), tmp, sizeof(tmp));
    base64_encode(tmp, len, out, sizeof(out));
    hd->response_buf_count = sprintf((char *) hd->response_buf, websocket_response_header, out);
  } else {
    hd->response_buf_count = strlen(http_response_header);
    memcpy(hd->response_buf, http_response_header, hd->response_buf_count);
  }
}

static void
send_ws_frame(http_data_t *hd, ws_frame_t *frm)
{
//  ws_print_frame(frm);
  hd->handle_response(hd->cb_data, (unsigned char *) frm->hdr, WEBSOCKET_FRAME_SIZE(frm));
}

static void
send_ws_close_frame(http_data_t *hd)
{
  ws_frame_t ws_frame;
  ws_init_frame(&ws_frame);
  ws_frame.hdr->opcode = WEBSOCKET_OPCODE_CLOSE;
  ws_set_payload_length(&ws_frame, 2);
  WEBSOCKET_SET_CLOSE_REASON(&ws_frame, 1000);
  hd->state = HTTP_CLOSING;
  hd->output_ready(hd->cb_data);
  send_ws_frame(hd, &ws_frame);
}

void
http_init(http_data_t *hd, void *cb_data,
          void (*output_ready)(void *),
          int (*handle_request)(void *, unsigned char *, int),
          int (*handle_response)(void *, unsigned char *, int))
{
  hd->state = HTTP_UNCONNECTED;
  hd->request_buf_count = 0;
  hd->request_buf_start = 0;
  hd->response_buf_count = 0;
  hd->response_buf_start = 0;
  hd->cb_data = cb_data;
  hd->output_ready = output_ready;
  hd->handle_request = handle_request;
  hd->handle_response = handle_response;
  memset(hd->websocket_key, 0, sizeof(hd->websocket_key));
  ws_init_frame(&hd->request_frame);
}

static void
send_response(http_data_t *hd, unsigned char *buf, int len)
{
  if (IS_WEBSOCKET(hd)){
    ws_init_frame(&hd->response_frame);
    ws_set_payload_length(&hd->response_frame, len);
    ws_append_payload(&hd->response_frame, buf, len);

    send_ws_frame(hd, &hd->response_frame);
  } else {
    /* http mode */
    hd->handle_response(hd->cb_data, buf, len);
  }
}

char *
http_process_response(http_data_t *hd, unsigned char *buf, int len)
{
  if (hd->state != HTTP_CONNECTED)
    return NULL;

  base64_encode((char *) buf, len, (char *) hd->response_buf, HTTP_BUFSIZE);
  hd->response_buf_count = strlen((char *) hd->response_buf);
  //hd->response_buf_count = len;
  //memcpy(hd->response_buf, buf, len);

  send_response(hd, hd->response_buf, hd->response_buf_count);

  return NULL;
}

char *
http_process_request(http_data_t *hd, int fd)
{
  unsigned char *ret = NULL, *buf = NULL;
  char line[HTTP_BUFSIZE];
  int header_len;
  char header[64];
  char *header_value;
  int i;

  hd->request_buf_count = read(fd, hd->request_buf + hd->request_buf_start, HTTP_BUFSIZE - hd->request_buf_start);
  if (hd->request_buf_count < 0) {
    /* Got an error on the read, shut down the port. */
    return "tcp read error";
  } else if (hd->request_buf_count == 0) {
    /* The other end closed the port, shut it down. */
    return "tcp read close";
  }
  hd->request_buf_start += hd->request_buf_count;
  hd->request_buf[hd->request_buf_start] = '\0';

  if (HTTP_UNCONNECTED == hd->state) {
    hd->state = HTTP_CONNECTING;
  }

  if (HTTP_CONNECTING == hd->state) {
    /* handshaking */
    buf = hd->request_buf;
    for (;;) {
      ret = (unsigned char *) strchr((char *) buf, '\n');
      if (ret) {
        header_len = ret - buf + 1;
        strncpy(line, (char *) buf, header_len);
        line[header_len - 2] = '\0';

        hd->request_buf_start -= header_len;
        buf = ret + 1;

        // TODO process HTTP Method

        /* If there is nothing left (ie: blank line),
         * the headers are over. */
        if (!strcmp(line, "")) {
          /* request headers over, send response headers */
          prepare_response_headers(hd, fd);
          hd->handle_response(hd->cb_data, hd->response_buf, hd->response_buf_count);
          hd->state = HTTP_CONNECTED;
          hd->output_ready(hd->cb_data);
          break;
        }

        if (get_header_name(line, header, sizeof(header))) {
          header_value = strchr(line, ':');
          if (header_value) {
            header_value++;
            while (header_value && *header_value == ' ')
              header_value++;
          }

          // TODO process other headers

          /* store websocket key */
          if (strcmp(header, "SEC-WEBSOCKET-KEY") == 0) {
            strncpy(hd->websocket_key, header_value, sizeof(hd->websocket_key) - 1);
          }
        }
      } else {
        break;
      }
    }
  } else if (HTTP_CONNECTED == hd->state) {
    if (IS_WEBSOCKET(hd)){
      /* decode websocket frame */
      ws_frame_t *frame = &hd->request_frame;
      unsigned char *hdr;

      buf = hd->request_buf;
      hdr = (unsigned char *)frame->hdr;

      while (hd->request_buf_start > 0) {
        hdr[frame->index++] = *(buf++);
        hd->request_buf_start--;

        if (frame->left > 0) {
          frame->left--;
        }

        if (1 == frame->index) {
          continue;
        }

        if (WEBSOCKET_HEADER_SIZE == frame->index) {
          frame->payload = hdr + frame->index;
          if (WEBSOCKET_UNEXTENDED(frame)) {
            frame->len = (ws_length_t *) (frame->payload - 1);
            frame->left = WEBSOCKET_LENGTH(frame);
            if (WEBSOCKET_MASKED(frame)) {
              frame->left += WEBSOCKET_MASK_SIZE;
              frame->mask = frame->payload;
              frame->payload += WEBSOCKET_MASK_SIZE;
            }
          } else if (WEBSOCKET_EXT16(frame)) {
            /* the following 2 bytes as a 16-bit uint are the payload length. */
            frame->len = (ws_length_t *) frame->payload;
            frame->payload += WEBSOCKET_EXT16_SIZE;
          } else {
            /* TODO the following 8 bytes as a 64-bit unit are the payload length. */
          }
        } else if (WEBSOCKET_HEADER_SIZE + WEBSOCKET_EXT16_SIZE == frame->index) {
          if (WEBSOCKET_EXT16(frame)) {
            frame->left = WEBSOCKET_LENGTH(frame);
            if (WEBSOCKET_MASKED(frame)) {
              frame->left += WEBSOCKET_MASK_SIZE;
              frame->mask = frame->payload;
              frame->payload += WEBSOCKET_MASK_SIZE;
            }
          }
        } else if (WEBSOCKET_HEADER_SIZE + WEBSOCKET_EXT64_SIZE == frame->index) {
          if (WEBSOCKET_EXT64(frame)) {
            /* TODO If 127, the following 8 bytes as a 64-bit unit are the payload length. */
          }
        }

        if (0 == frame->left) {
          /* one frame read */
          if (WEBSOCKET_MASKED(frame)) {
            ws_unmask(frame);
          }
//          ws_print_frame(frame);

          if (frame->hdr->opcode == WEBSOCKET_OPCODE_CLOSE) {
            //printf("close reason: %d\n", WEBSOCKET_GET_CLOSE_REASON(frame));
            send_ws_close_frame(hd);
          } else {
            hd->handle_request(hd->cb_data, frame->payload, WEBSOCKET_LENGTH(frame));
          }
          ws_init_frame(frame);
        }
      }
    } else {
      /* pass http payload to dev directly */
      buf = hd->request_buf;
      hd->handle_request(hd->cb_data, buf, hd->request_buf_start);
      buf += hd->request_buf_start;
      hd->request_buf_start = 0;
    }
  }

  for (i = 0; i < hd->request_buf_start; i++) {
    hd->request_buf[i] = buf[i];
  }
  hd->request_buf[hd->request_buf_start] = '\0';

  return NULL;
}
