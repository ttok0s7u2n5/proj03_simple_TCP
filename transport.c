/*
 * 2021 Spring EE323 Computer Network
 * Project #3 Simple TCP
 * Author: Heewon Yang
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */



#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define WINDOW_SIZE 3072
#define OFFSET 5
#define MSS 536
#define SSTHRESH 2144 // MSS * 4
#define HDR_SIZE sizeof(STCPHeader)

// TODO: Add states to be used as the contextual states of TCP handshaking
// ex) CSTATE_LISTEN, CSTATE_SYN_SENT, ...
enum {
    CSTATE_ESTABLISHED,
    CSTATE_LISTEN,
    CSTATE_SYN_SENT,
    CSTATE_SYN_RCVD,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    CSTATE_CLOSE_WAIT,
    CSTATE_LAST_ACK,
    CSTATE_CLOSING,
    CSTATE_CLOSED
};    /* obviously you should have more states */

/*static const char *state[] = {"CSTATE_ESTABLISHED", "CSTATE_LISTEN", "CSTATE_SYN_SENT", "CSTATE_SYN_RCVD", "CSTATE_FIN_WAIT_1", "CSTATE_FIN_WAIT_2", "CSTATE_CLOSE_WAIT", "CSTATE_LAST_ACK", "CSTATE_CLOSING", "CSTATE_CLOSED"};*/

// TODO: Add your own variables helping your context management
/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    
    /* any other connection-wide global variables go here */
    tcp_seq seq;
    tcp_seq ack;
    size_t len;
    tcp_seq seq_to_send;

    tcp_seq seq_received;
    tcp_seq ack_received;
    tcp_seq win_received;
    size_t len_received;
    
    uint32_t local_window_size;
    uint32_t remote_window_size;
    uint32_t remain_window_size;
    
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

void printHeader(STCPHeader *hdr)
{
    printf("======================HEADER==========================\n");
    printf("Sequence Number: %u\n", ntohl(hdr->th_seq));
    printf("Ack Number: %u\n", ntohl(hdr->th_ack));
    printf("Offset: %u\n", hdr->th_off);
    printf("Flags: 0x%02x\n", hdr->th_flags);
    printf("Window: %u\n", ntohs(hdr->th_win));
    printf("======================================================\n");
}

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */

/* send a stcp packet */
bool send_packet(mysocket_t sd, context_t *ctx, uint8_t flags, char *data, size_t data_len)
{
    STCPHeader *stcp_pkt = (STCPHeader *)calloc(1, HDR_SIZE + data_len);
    stcp_pkt->th_flags = flags;
    if (flags == TH_SYN) {
        ctx->seq = ctx->initial_sequence_num;
        ctx->ack = 0;
        ctx->len = 1;
    }
    else if (flags == TH_ACK) {
        ctx->seq = ctx->seq_to_send;
        ctx->ack = ctx->seq_received + ctx->len_received;
        ctx->len = 1;
    }
    else if (flags == (TH_SYN | TH_ACK)) {
        ctx->seq = ctx->initial_sequence_num;
        ctx->ack = ctx->seq_received + 1;
        ctx->len = 1;
    }
    else if (flags == TH_FIN) {
        ctx->seq = ctx->seq_to_send;
        ctx->ack = ctx->ack;
        ctx->len = 1;
    }
    else if (flags == (TH_FIN | TH_ACK)) {
        ctx->seq = ctx->ack_received;
        ctx->ack = ctx->seq_received + 1;
        ctx->len = 1;
    }
    else if (flags == 0) {
        assert(data);
        assert(data_len);
        stcp_pkt->th_flags = NETWORK_DATA;
        memcpy((void *)stcp_pkt + HDR_SIZE, data, data_len);
        ctx->seq = ctx->seq_to_send;
        ctx->ack = ctx->ack;
        ctx->len = data_len;
        ctx->remain_window_size -= data_len;
    }
    stcp_pkt->th_seq = htonl(ctx->seq);
    stcp_pkt->th_ack = htonl(ctx->ack);
    stcp_pkt->th_off = OFFSET;
    stcp_pkt->th_win = htons(WINDOW_SIZE);
    //printHeader(stcp_pkt);
    // send the packet
    ssize_t sent = stcp_network_send(sd, (void *)stcp_pkt, HDR_SIZE + data_len, NULL);
    if (sent > 0) {
        // sending success
        free(stcp_pkt);
        return true;
    }
    else {
        // sending error
        fprintf(stderr, "send_packet failed\n");
        errno = ECONNREFUSED; // connection refused by a server error
        free(stcp_pkt);
        free(ctx);
        return false;
    }
}

/* wait for a stcp packet and if there's a packet, receive packet, else error  */
bool wait_for_packet(mysocket_t sd, context_t *ctx, uint8_t flags)
{
    STCPHeader *stcp_pkt = (STCPHeader *)calloc(1, HDR_SIZE + MSS);
    stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    ssize_t recv = stcp_network_recv(sd, (void *)stcp_pkt, HDR_SIZE + MSS);
    if (recv < (ssize_t)HDR_SIZE) { // if the packet has wrong size, not receive the packet
        fprintf(stderr, "wait_for_packet failed\n");
        errno = ECONNREFUSED;
        free(stcp_pkt);
        free(ctx);
        return false;
    }
    //printHeader(stcp_pkt);
    if ((flags == TH_SYN) && (stcp_pkt->th_flags == TH_SYN)) {
        ctx->seq_received = ntohl(stcp_pkt->th_seq);
        ctx->ack_received = ntohl(stcp_pkt->th_ack);
        ctx->win_received = ntohs(stcp_pkt->th_win);
        ctx->seq_to_send = ctx->initial_sequence_num;
        if ((size_t)recv == HDR_SIZE) {
            ctx->len_received = 1;
        }
        else {
            ctx->len_received = (size_t)recv - HDR_SIZE;
        }
        free(stcp_pkt);
        return true;
    }
    else if ((flags == TH_ACK) && (stcp_pkt->th_flags == TH_ACK)) {
        ctx->seq_received = ntohl(stcp_pkt->th_seq);
        ctx->ack_received = ntohl(stcp_pkt->th_ack);
        ctx->win_received = ntohs(stcp_pkt->th_win);
        ctx->seq_to_send = ctx->ack_received;
        if ((size_t)recv == HDR_SIZE) {
            ctx->len_received = 1;
        }
        else {
            ctx->len_received = (size_t)recv - HDR_SIZE;
        }
        uint32_t wind = ctx->remote_window_size;
        // congestion control implementation referred to https://tools.ietf.org/html/rfc5681#section-3.1
        if (ctx->len != 1) {
            if (ctx->local_window_size < SSTHRESH) { // if cwnd < SSTHRESH, just increase cwnd with MSS
                ctx->local_window_size += MSS;
            }
            else { // if cwnd >= SSTHRESH, increase cwnd as cwnd += (MSS*MSS)/cwnd
                ctx->local_window_size += ((MSS * MSS) / ctx->local_window_size);
            }
            ctx->remote_window_size = MIN(ctx->local_window_size, WINDOW_SIZE);
            ctx->remain_window_size += ctx->len;
        }
        else {
            ctx->remote_window_size = MIN(ctx->local_window_size, WINDOW_SIZE);
        }
        ctx->remain_window_size += (ctx->remote_window_size - wind);
        free(stcp_pkt);
        return true;
    }
    else if ((flags == (TH_SYN | TH_ACK)) && (stcp_pkt->th_flags == (TH_SYN | TH_ACK))) {
        ctx->seq_received = ntohl(stcp_pkt->th_seq);
        ctx->ack_received = ntohl(stcp_pkt->th_ack);
        ctx->win_received = ntohs(stcp_pkt->th_win);
        ctx->seq_to_send = ctx->ack_received;
        if ((size_t)recv == HDR_SIZE) {
            ctx->len_received = 1;
        }
        else {
            ctx->len_received = (size_t)recv - HDR_SIZE;
        }
        free(stcp_pkt);
        return true;
    }
    else if ((flags == TH_FIN) && (stcp_pkt->th_flags == TH_FIN)) {
        ctx->seq_received = ntohl(stcp_pkt->th_seq);
        ctx->ack_received = ntohl(stcp_pkt->th_ack);
        ctx->win_received = ntohs(stcp_pkt->th_win);
        ctx->seq_to_send = ctx->ack_received;
        if ((size_t)recv == HDR_SIZE) {
            ctx->len_received = 1;
        }
        else {
            ctx->len_received = (size_t)recv - HDR_SIZE;
        }
        free(stcp_pkt);
        return true;
    }
    else if ((flags == (TH_FIN | TH_ACK)) && (stcp_pkt->th_flags == (TH_FIN | TH_ACK))) {
        ctx->seq_received = ntohl(stcp_pkt->th_seq);
        ctx->ack_received = ntohl(stcp_pkt->th_ack);
        ctx->win_received = ntohs(stcp_pkt->th_win);
        ctx->seq_to_send = ctx->ack_received;
        if ((size_t)recv == HDR_SIZE) {
            ctx->len_received = 1;
        }
        else {
            ctx->len_received = (size_t)recv - HDR_SIZE;
        }
        free(stcp_pkt);
        return true;
    }
    else {
        fprintf(stderr, "wait_for_packet failed\n");
        errno = ECONNREFUSED;
        free(stcp_pkt);
        free(ctx);
        return false;
    }
}

/* handle data received from application */
bool app_data(mysocket_t sd, context_t *ctx)
{
    size_t max_data_len = MIN(MSS, ctx->remain_window_size);
    char data[MSS + HDR_SIZE];
    ssize_t data_len = stcp_app_recv(sd, data, max_data_len); // receive and update data_len
    if (data_len > 0) { // if length of data is larger than zero
        if (send_packet(sd, ctx, 0, data, data_len) == false) {
            fprintf(stderr, "app_data: sending data packet failed\n");
            return false;
        }
        if (wait_for_packet(sd, ctx, TH_ACK) == false) {
            fprintf(stderr, "app_data: waiting for ACK packet failed\n");
            return false;
        }
    }
    else {
        fprintf(stderr, "app_data: data_len is zero; received nothing\n");
        errno = ECONNREFUSED;
        free(ctx);
        return false;
    }
    return true;
}

/* handle data received from network */
bool network_data(mysocket_t sd, context_t *ctx)
{
    size_t max_data_len = MIN(MSS, ctx->remain_window_size);
    char data[MSS + HDR_SIZE];
    ssize_t data_len = stcp_network_recv(sd, (void *)data, HDR_SIZE + max_data_len); // receive and update data_len
    if (data_len >= (ssize_t)HDR_SIZE) { // if length of data is larger or equal to size of STCPHeader
        STCPHeader *stcp_pkt = (STCPHeader *)data;
        //printHeader(stcp_pkt);
        if (stcp_pkt->th_flags == (TH_FIN | TH_ACK)) { // 4-way Handshaking
            if (send_packet(sd, ctx, TH_ACK, NULL, 0) == false) { // Sending ACK
                fprintf(stderr, "network_data: sending ACK packet failed\n");
                return false;
            }
            ctx->connection_state = CSTATE_CLOSE_WAIT;
            //printf("Connection state: %s\n", state[ctx->connection_state]);
            stcp_fin_received(sd);
            if (send_packet(sd, ctx, (TH_FIN | TH_ACK), NULL, 0) == false) { // Sending FINACK
                fprintf(stderr, "network_data: sending FINACK packet failed\n");
                return false;
            }
            ctx->connection_state = CSTATE_LAST_ACK;
            //printf("Connection state: %s\n", state[ctx->connection_state]);
            if (wait_for_packet(sd, ctx, TH_ACK) == false) { // Waiting for ACK
                fprintf(stderr, "network_data: waiting for ACK packet failed\n");
                return false;
            }
            ctx->connection_state = CSTATE_CLOSED;
            //printf("Connection state: %s\n", state[ctx->connection_state]);
            ctx->done = 1;
            return true;
        }
        else { // send data to app
            stcp_app_send(sd, ((char *)data + HDR_SIZE), ((size_t)data_len - HDR_SIZE));
            ctx->seq_received = ntohl(stcp_pkt->th_seq);
            ctx->ack_received = ntohl(stcp_pkt->th_ack);
            ctx->len_received = (size_t)data_len - HDR_SIZE;
            ctx->win_received = ntohl(stcp_pkt->th_win);
            
            if (send_packet(sd, ctx, TH_ACK, NULL, 0) == false) { // Sending ACK
                fprintf(stderr, "network_data: sending ACK packet failed\n");
                return false;
            }
        }
        return true;
    }
    else {
        fprintf(stderr, "network_data: data_len is zero; received nothing\n");
        free(ctx);
        return false;
    }
    return true;
}
/* handle when the socket gets close request */
bool app_close_requested(mysocket_t sd, context_t *ctx)
{
    if (send_packet(sd, ctx, (TH_FIN | TH_ACK), NULL, 0) == false) { // Sending FINACK
        fprintf(stderr, "app_close_requested: sending FINACK packet failed\n");
        return false;
    }
    ctx->connection_state = CSTATE_FIN_WAIT_1;
    //printf("Connection state: %s\n", state[ctx->connection_state]);
    if (wait_for_packet(sd, ctx, TH_ACK) == false) { // Waiting for ACK
        fprintf(stderr, "app_close_requested: waiting for ACK packet failed\n");
        return false;
    }
    ctx->connection_state = CSTATE_FIN_WAIT_2;
    //printf("Connection state: %s\n", state[ctx->connection_state]);
    if (wait_for_packet(sd, ctx, (TH_FIN | TH_ACK)) == false) { // Waiting for FINACK
        fprintf(stderr, "app_close_requested: waiting for FINACK packet failed\n");
        return false;
    }
    if (send_packet(sd, ctx, TH_ACK, NULL, 0) == false) { // Sending ACK
        fprintf(stderr, "app_close_requested: sending ACK packet failed\n");
        return false;
    }
    ctx->connection_state = CSTATE_CLOSED;
    //printf("Connection state: %s\n", state[ctx->connection_state]);
    ctx->done = 1;
    return true;
}

void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* TODO: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    ctx->done = 0;
    ctx->seq_received = 0;
    ctx->connection_state = CSTATE_LISTEN;
    ctx->local_window_size = MSS;
    ctx->remote_window_size = MSS;
    ctx->remain_window_size = MSS;
    
    if (is_active == true) { // active open
        if (send_packet(sd, ctx, TH_SYN, NULL, 0) == false) { // send SYN packet
            fprintf(stderr, "transport_init: sending SYN packet failed\n");
            return;
        }
        ctx->connection_state = CSTATE_SYN_SENT; // SYN_SENT
        //printf("Connection state: %s\n", state[ctx->connection_state]);
        if (wait_for_packet(sd, ctx, (TH_SYN | TH_ACK)) == false) { // wait for SYNACK
            fprintf(stderr, "transport_init: waiting for SYNACK packet failed\n");
            return;
        }
        ctx->connection_state = CSTATE_ESTABLISHED;
        //printf("Connection state: %s\n", state[ctx->connection_state]);
        if (send_packet(sd, ctx, TH_ACK, NULL, 0) == false) { // send ACK packet
            fprintf(stderr, "transport_init: sending ACK packet failed\n");
            return;
        }
    }
    else { // passive open
        if (wait_for_packet(sd, ctx, TH_SYN) == false) { // wait for SYN packet
            fprintf(stderr, "transport_init: waiting for SYN packet failed\n");
            return;
        }
        //printf("Connection state: %s\n", state[ctx->connection_state]);
        if (send_packet(sd, ctx, (TH_SYN | TH_ACK), NULL, 0) == false) { // send SYNACK packet
            fprintf(stderr, "transport_init: sending SYNACK packet failed\n");
            return;
        }
        ctx->connection_state = CSTATE_SYN_RCVD; // SYN_RCVD
        //printf("Connection state: %s\n", state[ctx->connection_state]);
        if (wait_for_packet(sd, ctx, TH_ACK) == false) { // wait for ACK packet
            fprintf(stderr, "transport_init: waiting for ACK packet failed\n");
            return;
        }
        ctx->connection_state = CSTATE_ESTABLISHED;
        //printf("Connection state: %s\n", state[ctx->connection_state]);
    }
    stcp_unblock_application(sd);
    
    if (ctx->connection_state == CSTATE_ESTABLISHED) {
        control_loop(sd, ctx);
    }

    /* do any cleanup here */
    free(ctx);
}

// DO NOT MODIFY THIS FUNCTION
/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->initial_sequence_num = 1;
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* TODO: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        
        // Handle the cases where the events are APP_DATA, APP_CLOSE_REQUESTED, NETWORK_DATA
        if (event == APP_DATA) {
            if (app_data(sd, ctx) == false) {
                return;
            }
        }
        
        else if (event == NETWORK_DATA) {
            if (network_data(sd, ctx) == false) {
                return;
            }
        }
        
        else if (event == APP_CLOSE_REQUESTED) {
            if (app_close_requested(sd, ctx) == false) {
                return;
            }
        }
        
        else {
            fprintf(stderr, "control_loop failed\n");
        }
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}


