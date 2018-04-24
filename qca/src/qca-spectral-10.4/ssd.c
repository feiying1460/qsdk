/*
 * =====================================================================================
 *
 *       Filename:  ssd.c
 *
 *    Description:  Spectral Scan Daemon
 *
 *        Version:  1.0
 *        Created:  11/21/2011 11:23:05 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  S.Karthikeyan (), 
 *        Company:  Qualcomm Atheros
 *
 *        Copyright (c) 2012 Qualcomm Atheros, Inc.
 *        All Rights Reserved
 *        Qualcomm Atheros Confidential and Proprietary
 *
 * =====================================================================================
 */


#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ssd_defs.h"
#include "ssd_data.h"
#include "ssd_proto.h"
#include "ssd_utils.h"


/* main spectral daemon info */
static ssd_info_t ssdinfo;
static ssd_info_t* pinfo = &ssdinfo;


/*
 * Function     : print_usage
 * Description  : print the ssd usage
 * Input params : void
 * Return       : void
 *
 */

void print_usage(void)
{
    printf("ssd - usage\n");
    printf("----------------------------------------------------------------------------------\n");
    printf("channels        - use with AirDefense GUI (switches the between channels 5 and 11)\n");
    printf("userssi         - use RSSI in the power calculations\n");
    //printf("classify        - run classifier on the current channel (stand alone option)\n");
    //printf("eacs            - run the EACS algorithm (stand alone option)\n");
    printf("rawfft          - report raw FFT data as is to the GUI, (debug only)\n");
    printf("minpwr <value>  - threshold for reporting power\n");
    printf("maxhold <value> - set the max hold interval\n");
    printf("athui           - support Atheros GUI\n");
    //printf("debug <1/2/3>   - set the debug level\n");
}


/*
 * Function     : get_args
 * Description  : validates user input values for ssd
 * Input params : pointer to user arguments and argument count
 * Return       : 0 for valid arguments, -1 for error
 *
 */
int get_args(int argc, char* argv[])
{
    int i = 1;
    int status = 0;
    ssd_config_t *p = &ssdinfo.config;

    while (i < argc) {

        if (streq(argv[i], "rawfft")) {
            set_config(p, raw_fft, 1);
        }

        if (streq(argv[i], "scale")) {
            set_config(p, scale, 1);
        }

        if (streq(argv[i], "userssi")) {
            set_config(p, use_rssi, 1);
        }

        if (streq(argv[i], "flip")) {
            set_config(p, flip, 1);
        }

        if (streq(argv[i], "rssi_only")) {
            set_config(p, rssi_only, 1);
        }

        if (streq(argv[i], "pwrperbin")) {
            set_config(p, power_per_bin, 1);
        }

        if (streq(argv[i], "athui")) {
            set_config(p, atheros_ui, 1);
        }

#ifdef  SSD_EXPERIMENTAL
        if (streq(argv[i], "eacs")) {
            set_config(p, eacs, 1);
            if (argc > 1) {
              printf("err : eacs should not be used with other settings\n");
              status = -1;
            }
        }
#endif  /* SSD_EXPERIMENTAL */

        if (streq(argv[i], "channels")) {
            set_config(p, change_channel, 1);
        }

#ifdef  SSD_EXPERIMENTAL
        if (streq(argv[i], "classify")) {
            set_config(p, classify, 1);
            if (argc > 2) {
               printf("err : classify should not be used with other settings\n");
               status = -1;
            }
        }
#endif  /* SSD_EXPERIMENTAL */

        if (streq(argv[i], "minpwr")) {
            int val = atoi(argv[i + 1]);
            set_config(p, minpower, val);
            i++;
        }

        if (streq(argv[i], "maxhold")) {
            int val = atoi(argv[i + 1]);
            set_config(p, maxhold_interval, val);
            i++;
        }

        if (streq(argv[i], "help")) {
            print_usage();
            exit(0);
        }

        i++;
    }

    return status;
}

/*
 * Function     : ssd_alarm_handler
 * Description  : signal handler (TODO : Replace with timer function?)
 * Input params : signal type
 * Return       : void
 *
 */
static void ssd_alarm_handler(int sig)
{
    pinfo->stats.alarm++;
    ualarm(SSD_USEC_ALARM_VAL, 0);
}

/*
 * Function     : ssd_start_eacs_monitor_scan
 * Description  : TBD
 * Input params :
 * Return       :
 *
 */
void ssd_start_eacs_monitor_scan(void)
{
    not_yet();
}

/*
 * Function     : ssd_init_config
 * Description  : initializes the default configuration for ssc
 * Input params : pointer to ssdinfo
 * Return       : void
 *
 */
void ssd_init_config(ssd_info_t* p)
{
    ssd_config_t* pconfig = GET_CONFIG_PTR(p);

    pconfig->current_freq   = CHANNEL_11_FREQ;
    pconfig->prev_freq      = CHANNEL_11_FREQ;
    pconfig->minpower       = DEFAULT_MINPOWER;
    pconfig->use_rssi       = TRUE;
    pconfig->maxhold_interval = DEFAULT_MAXHOLD_INT;
    pconfig->eacs = FALSE;
    pconfig->atheros_ui = FALSE;
}

/*
 * Function     : main
 * Description  : entry point for ssd program
 * Input params : user input
 * Return       :
 *
 */
int main(int argc, char* argv[])
{

    /* inet socket */
    int listener;
    int app_fd;
    int on=1;

    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    socklen_t addrlen;

    /* netlink socket */
    struct sockaddr_nl  src_addr;
    struct sockaddr_nl  dst_addr;
    struct nlmsghdr     *nlh;
    struct msghdr       msg;
    struct iovec        iov;
    int nl_spectral_fd;

    int     fdmax;      /* maximum fd number */
    fd_set  master;     /* Master FD set */
    fd_set  read_fds;   /* Read FD set */

    /* Init sample info pointer */
    ssd_samp_info_t *psinfo = GET_SAMP_INFO_PTR(pinfo);

    /* init receive buffer */
    u_int8_t recv_buf[MAX_PAYLOAD] = {'\0'};


    /* initialize default settings */
    ssd_init_config(pinfo);
    ssd_init_silent_samp_msg(pinfo);
    ssd_init_ssd_samp_msg_buffers(pinfo);

    /* validate user settings */
    if (get_args(argc, argv) != 0) {
        printf("configuration error\n");
        return 1;
    }

    print_args(pinfo);

    /* init socket interface */
    listener = socket(PF_INET, SOCK_STREAM, 0);

    if (listener < 0) {
        perror("err : unable to open socket\n");
        exit(EXIT_FAILURE);
    }

    /* set socket options */
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        perror("err : socket option failed\n");
        close(listener);
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(ATHPORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    /* bind the listener socket */
    if (bind(listener, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("err : bind error\n");
        close(listener);
        exit(EXIT_FAILURE);
    }

    /* start listening */
    if (listen(listener, BACKLOG) == -1) {
        perror("err : listen fail\n");
        close(listener);
        exit(EXIT_FAILURE);
    }

    /* init netlink connection to spectral driver */
    nl_spectral_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ATHEROS);

    if (nl_spectral_fd < 0) {
        perror("err : unable to open netlink_atheros socket\n");
        close(listener);
        exit(EXIT_FAILURE);
    }

    /* init netlink socket */
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family  = PF_NETLINK;
    src_addr.nl_pid     = getpid();
    src_addr.nl_groups  = 1;

    if (bind(nl_spectral_fd, (struct sockaddr *) &src_addr, sizeof(src_addr)) < 0) {
        perror("err : unable to bind (netlink)");
        close(nl_spectral_fd);
        close(listener);
        exit(EXIT_FAILURE);
    }


    /* alloc space nlmsg */
    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(sizeof(SPECTRAL_SAMP_MSG)));

    nlh->nlmsg_len      = NLMSG_SPACE(sizeof(SPECTRAL_SAMP_MSG));
    nlh->nlmsg_pid      = getpid();
    nlh->nlmsg_flags    = 0;

    iov.iov_base    = (void*)nlh;
    iov.iov_len     = nlh->nlmsg_len;

    memset(&dst_addr, 0, sizeof(dst_addr));

    dst_addr.nl_family  = PF_NETLINK;
    dst_addr.nl_pid     = 0;
    dst_addr.nl_groups  = 1;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(nl_spectral_fd, &master);
    FD_SET(listener, &master);

    fdmax = ((listener > nl_spectral_fd)?listener:nl_spectral_fd);

    /* register alarm handler */
    if (!pinfo->config.eacs) 
        signal(SIGALRM, ssd_alarm_handler);
    else
        ssd_start_eacs_monitor_scan();

    /* init the state */
    set_state(pinfo, IDLE);

    for (;;) {

        int recvd_bytes = 0;
        int i = 0;

        read_fds = master;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {

            if (errno == EINTR) {

                /*
                 * We got interrupted by signal handler
                 * - In classify mode send stored spectral data to gui
                 * - In non classify mode send a silent data to the gui
                 */

                ssd_config_t    *pconfig = GET_CONFIG_PTR(pinfo);

                if (!pinfo->config.classify) {
                    ssd_update_silent_samp_msg(pinfo, pconfig->current_freq);
                    ssd_send_normal_spectral_data_to_client(pinfo, &pinfo->silent_msg, app_fd);
                } else {
                    if (psinfo->total_channel_switches > 1) {
                        ssd_send_classified_spectral_data_to_client(pinfo, NULL, app_fd);
                    }
                }
            } else {
                perror("select");
                exit(EXIT_FAILURE);
            }
            continue;
        }


        /*
         * Loop through all the FD set and receive relevant data 
         * - Data can be received from gui application
         * - Data can be received from spectral driver
         * - Data can be received from listener port
         */

        for (i = 0; i <= fdmax; i++) {

            /* We have data to handle */
            if (FD_ISSET(i, &read_fds)) {

                if (i == listener) {
                    /* Accept new connection 
                     * TODO : Make sure only one connection is accepted
                     */
                    addrlen = sizeof(client_addr);

                    if ((app_fd = accept(listener, (struct sockaddr*)&client_addr, &addrlen)) == -1) {
                        perror("err: unable to accept connections");
                    } else {
                        FD_SET(app_fd, &master);

                        fdmax = (app_fd > fdmax)?app_fd:fdmax;

                        printf("ssd: new connection from %s on socket %d\n",
                                inet_ntoa(client_addr.sin_addr), app_fd);

                        set_state(pinfo, CONNECTED_TO_GUI);
                    }

                } else {

                    if (i == nl_spectral_fd) {
                        /*
                         * Received data from spectral driver, parse the 
                         * spectral data 
                         */

                        ssd_handle_spectral_data(pinfo, recv_buf, &recvd_bytes, app_fd, nl_spectral_fd);
                        continue;
                    }

                    if ((recvd_bytes = recv(i, recv_buf, sizeof(recv_buf), 0)) <= 0)  {

                        /*
                         * Receive error :
                         */
                        if (recvd_bytes == 0) {
                            printf("ssd : socket %d hung up\n", i);
                            set_state(pinfo, IDLE);
                        } else {
                            perror("err: recv");
                        }

                        close(i);
                        FD_CLR(i, &master);

                    } else {
                        /*
                         * Received data form gui
                         * Handle the request commands
                         */
                        set_state(pinfo, SCAN_INIT);
                        ssd_handle_client_request_msg(pinfo, recv_buf, &recvd_bytes);
                        continue;
                    }
                }
            } /* if read_fds */

        } /* for */

    }   /* forever */

    /* cleanup */
    close(listener);
    close(app_fd);
    free(nlh);
    return 0;
}

