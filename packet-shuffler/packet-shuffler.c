#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <error.h>
#include <errno.h>

#include "sxe-log.h"
#include "option-parse.h"
#include "ev.h"
#include "exs-pool.h"

#define BUFFER_SIZE 1500

// LOG LEVELS
// 1 - Fatal - Exit or Assert
// 2 - Serious Issue - Still Running
// 3 - Syscall Errors
// 4 - Per-Second Stats (Transactions too?)
// 5 - Release Level Warnings
// 6 - Debug function calls
// 7 - Debug Internals

// Defaults
unsigned short port_external   = 1337;
const char*    ip_external     = "127.0.0.1";
unsigned short port_internal   = 1338;
const char*    ip_internal     = "127.0.0.1";
unsigned       max_connections = 100000;

unsigned       timeout_connecting_state = 2;
unsigned       timeout_idle_state       = 60;

// Counters
unsigned count_connects_sec = 0;
unsigned count_in_close_sec = 0;
unsigned count_ex_close_sec = 0;
unsigned count_in_reads_sec = 0;
unsigned count_ex_reads_sec = 0;
unsigned count_in_cnct_timeouts_sec = 0;
unsigned count_idle_timeouts_sec = 0;

typedef struct external_connection_pool {
    unsigned char  buf[BUFFER_SIZE];
    unsigned char* remaining_buf;
    unsigned       remaining_buf_len;
    ev_io          io;
    int            sock;
    unsigned       internal_id;
} external_connection_pool;

typedef struct internal_connection_pool {
    unsigned char  buf[BUFFER_SIZE];
    unsigned char* remaining_buf;
    unsigned       remaining_buf_len;
    ev_io          io;
    int            sock;
    unsigned       external_id;
} internal_connection_pool;

typedef enum EXTERNAL_CONNECTION_POOL_STATE {
    EXT_CON_POOL_STATE_FREE = 0,
    EXT_CON_POOL_STATE_WAIT_INTERNAL_CONNECT,
    EXT_CON_POOL_STATE_CONNECTED,
    EXT_CON_POOL_NUMBER_OF_STATES
} EXTERNAL_CONNECTION_POOL_STATE;

typedef enum INTERNAL_CONNECTION_POOL_STATE {
    INT_CON_POOL_STATE_FREE = 0,
    INT_CON_POOL_STATE_WAIT_CONNECT,
    INT_CON_POOL_STATE_CONNECTED,
    INT_CON_POOL_NUMBER_OF_STATES
} INTERNAL_CONNECTION_POOL_STATE;

external_connection_pool* external_connections;
internal_connection_pool* internal_connections;

ev_timer per_second_timer;

// foward declarations
static void internal_read_cb(EV_P_ ev_io* read_ev_io, int revents);
static void external_read_cb(EV_P_ ev_io* read_ev_io, int revents);

static void
set_socket_options(int sock)
{
    int ret;
    int flags = 1;

    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    SXEA1(ret != -1, "setsocketopt() failed to set reuse address flag: (errno=%i) %s", errno, strerror(errno));

    struct linger linger_option;
    linger_option.l_onoff  = 0;
    linger_option.l_linger = 0;
    ret = setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger_option, sizeof(linger_option));
    SXEA1(ret != -1, "setsocketopt() failed to set linger options: (errno=%i) %s", errno, strerror(errno));

    ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
    SXEA1(ret != -1, "setsocketopt() failed to set TCP no delay flag: (errno=%i) %s", errno, strerror(errno));

    if ((flags = fcntl(sock, F_GETFL)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        SXEA1(0, "fcntl() failed to set O_NONBLOCK: (errno=%i) %s", errno, strerror(errno));
    }
}

static int // -1 = failed, 0 = incomplete send, 1 = complete send
send_data(const char* type, int sock, unsigned char ** data, unsigned *size)
{
    int result = 1;
    int ret;
    (void)type;
    SXEE6("(%s)", type);

    if ((ret = send(sock, *data, *size, MSG_NOSIGNAL)) != (int)*size) {
        if (ret >= 0) {
            SXEL6("send_data(%s): Only %d of %u bytes written", type, ret, *size);
            result = 0;
            *size = *size - (unsigned)ret;
            data = data + ret;
        }
        else {
            SXEL6("send_data(%s): Error writing to socket: (errno=%i) %s", type, errno, strerror(errno));
            result = 1;
        }
    }

    SXER6("return %d", result);
    return result;
}

static void
shutdown_connections(unsigned internal_id, unsigned external_id)
{
    // Close external
    ev_io_stop(EV_DEFAULT, &(external_connections[external_id].io));
    close(external_connections[external_id].sock);
    exs_pool_set_indexed_element_state(external_connections, external_id,
                                       exs_pool_index_to_state(external_connections, external_id),
                                       EXT_CON_POOL_STATE_FREE);
    // Close internal
    ev_io_stop(EV_DEFAULT, &(internal_connections[internal_id].io));
    close(internal_connections[internal_id].sock);
    exs_pool_set_indexed_element_state(internal_connections, internal_id,
                                       exs_pool_index_to_state(internal_connections, internal_id),
                                       INT_CON_POOL_STATE_FREE);
}

static void
internal_writable_cb(EV_P_ ev_io* read_ev_io, int revents)
{
    (void)loop;
    (void)revents;
    SXEE6("()");

    unsigned internal_id = (unsigned)(uintptr_t)read_ev_io->data;
    unsigned external_id = internal_connections[internal_id].external_id;
    SXEL6("int_id=%u, ext_id=%u", internal_id, external_id);

    int ret = send_data("internal", internal_connections[internal_id].sock, &external_connections[external_id].remaining_buf,
                                                                            &external_connections[external_id].remaining_buf_len);
    switch (ret) {
    case -1:
        shutdown_connections(internal_id, external_id);
        break;
    case 0:
        break;
    case 1:
        ev_io_stop(EV_DEFAULT, &(internal_connections[internal_id].io));
        ev_io_init(&(internal_connections[internal_id].io), internal_read_cb, internal_connections[internal_id].sock, EV_READ);
        ev_io_start(EV_DEFAULT, &(internal_connections[internal_id].io));
        ev_io_stop(EV_DEFAULT, &(external_connections[external_id].io));
        ev_io_init(&(external_connections[external_id].io), external_read_cb, external_connections[external_id].sock, EV_READ);
        ev_io_start(EV_DEFAULT, &(external_connections[external_id].io));
    }

    SXER6("return");
    return;
}

static void
external_writable_cb(EV_P_ ev_io* read_ev_io, int revents)
{
    (void)loop;
    (void)revents;
    SXEE6("()");

    unsigned external_id = (unsigned)(uintptr_t)read_ev_io->data;
    unsigned internal_id = external_connections[external_id].internal_id;
    SXEL6("int_id=%u, ext_id=%u", internal_id, external_id);

    int ret = send_data("external", external_connections[external_id].sock, &internal_connections[internal_id].remaining_buf,
                                                                            &internal_connections[internal_id].remaining_buf_len);
    switch (ret) {
    case -1:
        shutdown_connections(internal_id, external_id);
        break;
    case 0:
        break;
    case 1:
        ev_io_stop(EV_DEFAULT, &(internal_connections[internal_id].io));
        ev_io_init(&(internal_connections[internal_id].io), internal_read_cb, internal_connections[internal_id].sock, EV_READ);
        ev_io_start(EV_DEFAULT, &(internal_connections[internal_id].io));
        ev_io_stop(EV_DEFAULT, &(external_connections[external_id].io));
        ev_io_init(&(external_connections[external_id].io), external_read_cb, external_connections[external_id].sock, EV_READ);
        ev_io_start(EV_DEFAULT, &(external_connections[external_id].io));
    }

    SXER6("return");
    return;
}

static void
internal_read_cb(EV_P_ ev_io* read_ev_io, int revents)
{
    (void)loop;
    (void)revents;
    SXEE6("()");

    int ret;

    unsigned internal_id = (unsigned)(uintptr_t)read_ev_io->data;
    unsigned external_id = internal_connections[internal_id].external_id;
    exs_pool_touch_indexed_element(external_connections, external_id);
    SXEL6("int_id=%u, ext_id=%u", internal_id, external_id);

    int length = recv(internal_connections[internal_id].sock, internal_connections[internal_id].buf, BUFFER_SIZE, 0);

    if (length > 0) {
        count_in_reads_sec++;
        SXED6(internal_connections[internal_id].buf, length);
        internal_connections[internal_id].remaining_buf_len = length;
        internal_connections[internal_id].remaining_buf = internal_connections[internal_id].buf;

        ret = send_data("external", external_connections[external_id].sock, &internal_connections[internal_id].remaining_buf,
                                                                            &internal_connections[internal_id].remaining_buf_len);
        switch (ret) {
        case -1:
            goto ERROR_OUT;
        case 0:
            ev_io_stop(EV_DEFAULT, &(internal_connections[internal_id].io));
            ev_io_stop(EV_DEFAULT, &(external_connections[external_id].io));
            ev_io_init(&(external_connections[external_id].io), external_writable_cb, external_connections[external_id].sock, EV_WRITE);
            ev_io_start(EV_DEFAULT, &(external_connections[external_id].io));
        case 1:
            goto EARLY_OUT;
        }
    }
    else {
        if (length < 0) {
            switch (errno) {
            case EWOULDBLOCK:
                SXEL6("sock would block");
                goto EARLY_OUT;
            case ECONNRESET:
                SXEL6("Failed to read from socket (errno=%i) %s", errno, strerror(errno));
                break;
            default:
                SXEL2("Failed to read from socket (errno=%i) %s", errno, strerror(errno));
            }
        }
        else {
            SXEL6("Read zero bytes from socket (no error) closing");
            count_in_close_sec++;
        }
        goto ERROR_OUT;
    }

ERROR_OUT:
    shutdown_connections(internal_id, external_id);

EARLY_OUT:
    SXER6("return");
    return;
}

static void
internal_connect_cb(EV_P_ ev_io* connect_ev_io, int revents)
{
    (void)loop;
    (void)revents;
    SXEE6("()");

    int       sock_error;
    socklen_t sock_error_length = sizeof(sock_error);
    unsigned internal_id = (unsigned)(uintptr_t)connect_ev_io->data;
    unsigned external_id = internal_connections[internal_id].external_id;
    SXEL6("int_id=%u, ext_id=%u", internal_id, external_id);

    if (getsockopt(internal_connections[internal_id].sock, SOL_SOCKET, SO_ERROR, (void*)&sock_error, &sock_error_length) == -1) {
        SXEL3("getsockopt(): failed (errno=%i) %s", errno, strerror(errno));
        goto ERROR_OUT;
    }

    SXEA6(sock_error_length == sizeof(sock_error), "Unexpected size of result returned by getsockopt(): %d bytes", sock_error_length);

    if (sock_error != 0) {
        SXEL5("Internal connection failed! (%s:%hu): %s", ip_internal, port_internal, strerror(sock_error));
        goto ERROR_OUT;
    }

    // init internal
    ev_io_stop(EV_DEFAULT, connect_ev_io);
    ev_io_init(connect_ev_io, internal_read_cb, internal_connections[internal_id].sock, EV_READ);
    ev_io_start(EV_DEFAULT, connect_ev_io);
    exs_pool_set_indexed_element_state(internal_connections, internal_id, INT_CON_POOL_STATE_WAIT_CONNECT, INT_CON_POOL_STATE_CONNECTED);

    // finish external init
    exs_pool_set_indexed_element_state(external_connections, external_id, EXT_CON_POOL_STATE_WAIT_INTERNAL_CONNECT, EXT_CON_POOL_STATE_CONNECTED);
    ev_io_start(EV_DEFAULT, &external_connections[external_id].io);

    goto DONE;

ERROR_OUT:
    ev_io_stop(EV_DEFAULT, connect_ev_io);
    close(internal_connections[internal_id].sock);

DONE:
    SXER6("return");
    return;
}

static void
external_read_cb(EV_P_ ev_io* read_ev_io, int revents)
{
    (void)loop;
    (void)revents;
    SXEE6("()");

    int ret;

    unsigned external_id = (unsigned)(uintptr_t)read_ev_io->data;
    unsigned internal_id = external_connections[external_id].internal_id;
    exs_pool_touch_indexed_element(external_connections, external_id);
    SXEL6("int_id=%u, ext_id=%u", internal_id, external_id);

    int length = recv(external_connections[external_id].sock, external_connections[external_id].buf, BUFFER_SIZE, 0);
    SXEL6("Read %d bytes", length);

    if (length > 0) {
        count_ex_reads_sec++;
        SXED6(external_connections[external_id].buf, length);
        external_connections[external_id].remaining_buf_len = length;
        external_connections[external_id].remaining_buf = external_connections[external_id].buf;

        ret = send_data("internal", internal_connections[internal_id].sock, &external_connections[external_id].remaining_buf,
                                                                          &external_connections[external_id].remaining_buf_len);
        switch (ret) {
        case -1:
            goto ERROR_OUT;
        case 0:
            ev_io_stop(EV_DEFAULT, &(internal_connections[internal_id].io));
            ev_io_stop(EV_DEFAULT, &(external_connections[external_id].io));
            ev_io_init(&(internal_connections[internal_id].io), internal_writable_cb, internal_connections[internal_id].sock, EV_WRITE);
            ev_io_start(EV_DEFAULT, &(internal_connections[internal_id].io));
        case 1:
            goto EARLY_OUT;
        }
    }
    else {
        if (length < 0) {
            switch (errno) {
            case EWOULDBLOCK:
                SXEL6("sock would block");
                goto EARLY_OUT;
            case ECONNRESET:
                SXEL6("Failed to read from socket (errno=%i) %s", errno, strerror(errno));
                break;
            default:
                SXEL2("Failed to read from socket (errno=%i) %s", errno, strerror(errno));
            }
        }
        else {
            SXEL6("Read zero bytes from socket (no error) closing");
            count_ex_close_sec++;
        }
        goto ERROR_OUT;
    }

ERROR_OUT:
    shutdown_connections(internal_id, external_id);

EARLY_OUT:
    SXER6("return");
    return;
}

static int // 0 = failed, 1 = success
make_internal_connection(unsigned external_id)
{
    int ret = 1;
    SXEE6("()");

    unsigned internal_id = exs_pool_set_newest_element_state(internal_connections, INT_CON_POOL_STATE_FREE, INT_CON_POOL_STATE_WAIT_CONNECT);
    SXEA1(internal_id != POOL_NO_INDEX, "internal connection pool has no free elements?");
    external_connections[external_id].internal_id = internal_id;
    internal_connections[internal_id].external_id = external_id;
    SXEL6("int_id=%u, ext_id=%u", internal_id, external_id);

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    SXEA1(sock != -1, "socket() failed: (errno=%i) %s", errno, strerror(errno));
    set_socket_options(sock);
    internal_connections[internal_id].sock = sock;

    ev_io_init(&(internal_connections[internal_id].io), internal_connect_cb, sock, EV_WRITE);
    internal_connections[internal_id].io.data = (void*)(uintptr_t)internal_id;
    ev_io_start(EV_DEFAULT, &internal_connections[internal_id].io);

    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_internal);
    if (strcmp(ip_internal, "INADDR_ANY") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(ip_internal);
    }

    if ((connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) && (errno != EINPROGRESS)) {
        SXEL3("connect(): failed (errno=%i) %s, addr=%s:%u", errno, strerror(errno), inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ev_io_stop(EV_DEFAULT, &internal_connections[internal_id].io);
        exs_pool_set_indexed_element_state(internal_connections, internal_id, INT_CON_POOL_STATE_WAIT_CONNECT, INT_CON_POOL_STATE_FREE);
        ret = 0;
    }

    SXER6("return");
    return ret;
}


static void
external_connect_cb(EV_P_ ev_io* listen_ev_io, int revents)
{
    (void)loop;
    (void)revents;
    SXEE6("()");

    int sock = (int)(intptr_t)listen_ev_io->data;
    int new_sock;
    struct sockaddr_in new_addr;
    socklen_t new_addr_size = sizeof(new_addr);

    while (1) {

        if ((new_sock = accept(sock, (struct sockaddr *)&new_addr, &new_addr_size)) == -1) {
            if (errno == EWOULDBLOCK) {
                SXEL6("No more connections to accept on listening socket");
                goto EARLY_OUT;
            }

            SXEL3("Error accepting on listening socket: (errno=%i) %s", errno, strerror(errno));
            goto EARLY_OUT;
        }

        SXEL6("Accepted connection from ip=%d.%d.%d.%d:%hu",
                (ntohl(new_addr.sin_addr.s_addr) >> 24) & 0xff,
                (ntohl(new_addr.sin_addr.s_addr) >> 16) & 0xff,
                (ntohl(new_addr.sin_addr.s_addr) >> 8 ) & 0xff,
                 ntohl(new_addr.sin_addr.s_addr)        & 0xff,
                 ntohs(new_addr.sin_port));

        set_socket_options(new_sock);

        unsigned external_id = exs_pool_set_newest_element_state(external_connections, EXT_CON_POOL_STATE_FREE, EXT_CON_POOL_STATE_WAIT_INTERNAL_CONNECT);
        if (external_id == POOL_NO_INDEX) {
            close(new_sock);
            SXEL5("No Free External Connections!");
            // Or kill the oldest connection? Whichever has been idle the longest?
            goto EARLY_OUT;
        }

        count_connects_sec++;
        ev_io_init(&(external_connections[external_id].io), external_read_cb, new_sock, EV_READ);
        external_connections[external_id].io.data = (void*)(uintptr_t)external_id;
        external_connections[external_id].sock = new_sock;
        // the external io is ready, but we don't want read events until we have an internal connection
        // so we don't ev_io_start(...) here, we do it in internal connect_cb()

        if (!make_internal_connection(external_id)) {
            close(new_sock);
            exs_pool_set_indexed_element_state(external_connections, external_id, EXT_CON_POOL_STATE_WAIT_INTERNAL_CONNECT, EXT_CON_POOL_STATE_FREE);
        }

        SXEL6("paired int_id=%u, ext_id=%u", external_connections[external_id].internal_id, external_id);

    } // while(1)

EARLY_OUT:
    SXER6("return");
    return;
}

static void
add_listener(ev_io* listen_ev_io)
{
    int ret;
    struct sockaddr_in addr;

    SXEL6("add_listener(ip=%s, port=%u)", ip_external, port_external);

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    SXEA1(sock != -1, "socket() failed: (errno=%i) %s", errno, strerror(errno));
    set_socket_options(sock);

    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_external);
    if (strcmp(ip_external, "INADDR_ANY") == 0) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(ip_external);
    }
    ret = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    SXEA1(ret != -1, "bind(): (errno=%i) %s, addr=%s:%u", errno, strerror(errno), inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    // SOMAXCONN is probably too small... 128?
    ret = listen(sock, SOMAXCONN);
    SXEA1(ret != -1, "listen(): (errno=%i) %s", errno, strerror(errno));

    ev_io_init(listen_ev_io, external_connect_cb, sock, EV_READ);
    listen_ev_io->data = (void*)(intptr_t)sock;
    ev_io_start(EV_DEFAULT, listen_ev_io);
}

static void
check_timeouts(void)
{
    unsigned id;

    while ((id = exs_pool_index_if_older(internal_connections, INT_CON_POOL_STATE_WAIT_CONNECT,
                                          count_in_cnct_timeouts_sec)) != POOL_NO_INDEX)
    {
        SXEL6("Timing out: int_id=%u, ext_id=%u", id, internal_connections[id].external_id);
        shutdown_connections(id, internal_connections[id].external_id);
        count_in_cnct_timeouts_sec++;
    }

    while ((id = exs_pool_index_if_older(external_connections, EXT_CON_POOL_STATE_CONNECTED,
                                          timeout_idle_state)) != POOL_NO_INDEX)
    {
        SXEL6("Timing out: int_id=%u, ext_id=%u", external_connections[id].internal_id, id);
        shutdown_connections(external_connections[id].internal_id, id);
        count_idle_timeouts_sec++;
    }
}

static void
timer_cb(EV_P_ ev_timer* timer_ev_io, int revents)
{
    (void)loop;
    (void)revents;
    (void)timer_ev_io;

    check_timeouts();

    static int banner_count = 0;
    if (!(banner_count++ % 20)) {
        SXEL4("|ActiveCon|NewConcts|Int Close|Ext Close|Int Reads|Ext Reads|IntCnctTmOut|IdleTmOut|");
    }

    SXEL4("|%9u|%9u|%9u|%9u|%9u|%9u|%11u|%10u|",
        exs_pool_get_number_in_state(external_connections, EXT_CON_POOL_STATE_CONNECTED),
        count_connects_sec,
        count_in_close_sec,
        count_ex_close_sec,
        count_in_reads_sec,
        count_ex_reads_sec,
        count_in_cnct_timeouts_sec,
        count_idle_timeouts_sec
    );

    count_connects_sec = 0;
    count_in_close_sec = 0;
    count_ex_close_sec = 0;
    count_in_reads_sec = 0;
    count_ex_reads_sec = 0;
    count_in_cnct_timeouts_sec = 0;
    count_idle_timeouts_sec = 0;
}

int
main(int argc, char * argv[])
{
    op_add('a', "port-external",   OP_UNSIGNED_SHORT, &port_external);
    op_add('b', "ip-external",     OP_CONST_CHAR_PTR, &ip_external);
    op_add('c', "port-internal",   OP_UNSIGNED_SHORT, &port_internal);
    op_add('d', "ip-internal",     OP_CONST_CHAR_PTR, &ip_internal);
    op_add('e', "max-connections", OP_UNSIGNED,       &max_connections);

    op_run(argc, argv, stdout);

    struct ev_loop *loop = ev_default_loop(0);
    external_connections = (external_connection_pool*) exs_pool_new("external_connections", max_connections,
                                                                    sizeof(external_connection_pool),
                                                                    EXT_CON_POOL_NUMBER_OF_STATES);
    internal_connections = (internal_connection_pool*) exs_pool_new("internal_connections", max_connections,
                                                                    sizeof(internal_connection_pool),
                                                                    INT_CON_POOL_NUMBER_OF_STATES);
    ev_timer_init(&per_second_timer, timer_cb, 1.0, 1.0);
    ev_timer_start(EV_DEFAULT, &per_second_timer);

    ev_io listen_io;
    add_listener(&listen_io);
    SXEL6("ev_loop, run");
    ev_loop(loop, 0);

    return 0;
}
