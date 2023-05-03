/*
 * Tiny TTY driver Arkdii Kozlov <arkadiikozlov@gmail.com
 *
 *  Copyright (C) 2023
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2 of the License.
 *
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/serial.h>
#include <linux/slab.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/wait.h>

#define DRIVER_VERSION "v1.0"
#define DRIVER_AUTHOR "Arkdii Kozlov <arkadiikozlov@gmail.com>"
#define DRIVER_DESC "nport over udp serial driver"

/* Module information */
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");

#define DELAY_TIME (HZ * 2) /* 2 seconds per character */
#define NPORTUDP_DATA_CHARACTER 't'

#define NPORTUDP_TTY_MAJOR 240 /* experimental range */
#define NPORTUDP_TTY_MINORS 4  /* only have 4 devices */

#define MODULE_NAME "vega nport udp"

struct nportudp_serial {
    struct tty_struct *tty; /* pointer to the tty for this device */
    int open_count;         /* number of times this port has been opened */
    struct mutex mutex;     /* locks this structure */
    struct timer_list timer;

    /* for tiocmget and tiocmset functions */
    int msr; /* MSR shadow */
    int mcr; /* MCR shadow */

    /* for ioctl fun */
    struct serial_struct serial;
    wait_queue_head_t wait;
    struct async_icount icount;
};

static struct tty_driver *nportudp_tty_driver;

static struct nportudp_serial *nportudp_table[NPORTUDP_TTY_MINORS]; /* initially all NULL */
static struct tty_port nportudp_tty_port[NPORTUDP_TTY_MINORS];

struct kthread_t {
    struct task_struct *thread;
    //  struct socket *sock;
    struct sockaddr_in addr;
    struct socket *sock_send;
    struct sockaddr_in addr_send;
    int running;
};
struct kthread_t *kthread;

int ksocket_init(void);
void ksocket_exit(void);
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);
int ksocket_receive(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);

DECLARE_WAIT_QUEUE_HEAD(wait_queue_etx);

static void nportudp_timer(struct timer_list *t) {
    struct nportudp_serial *nportudp = from_timer(nportudp, t, timer);
    struct tty_struct *tty;
    struct tty_port *port;
    int i;
    char data[1] = {NPORTUDP_DATA_CHARACTER};
    int data_size = 1;

    if (!nportudp)
        return;

    tty = nportudp->tty;
    port = tty->port;

    /* send the data to the tty layer for users to read.  This doesn't
     * actually push the data through unless tty->low_latency is set */
    for (i = 0; i < data_size; ++i) {
        if (!tty_buffer_request_room(port, 1))
            tty_flip_buffer_push(port);
        tty_insert_flip_char(port, data[i], TTY_NORMAL);
    }
    tty_flip_buffer_push(port);

    /* resubmit the timer again */
    nportudp->timer.expires = jiffies + DELAY_TIME;
    add_timer(&nportudp->timer);
}

static int nportudp_open(struct tty_struct *tty, struct file *file) {
    struct nportudp_serial *nportudp;
    int index;

    /* initialize the pointer in case something fails */
    tty->driver_data = NULL;

    /* get the serial object associated with this tty pointer */
    index = tty->index;
    nportudp = nportudp_table[index];
    if (nportudp == NULL) {
        /* first time accessing this device, let's create it */
        nportudp = kmalloc(sizeof(*nportudp), GFP_KERNEL);
        if (!nportudp)
            return -ENOMEM;

        mutex_init(&nportudp->mutex);
        nportudp->open_count = 0;

        nportudp_table[index] = nportudp;
    }

    mutex_lock(&nportudp->mutex);

    /* save our structure within the tty structure */
    tty->driver_data = nportudp;
    nportudp->tty = tty;

    ++nportudp->open_count;
    if (nportudp->open_count == 1) {
        /* this is the first time this port is opened */
        /* do any hardware initialization needed here */

        /* create our timer and submit it */
        /*timer_setup(&nportudp->timer, nportudp_timer, 0);
        nportudp->timer.expires = jiffies + DELAY_TIME;
        add_timer(&nportudp->timer); */
    }

    mutex_unlock(&nportudp->mutex);
    return 0;
}

static void do_close(struct nportudp_serial *nportudp) {
    mutex_lock(&nportudp->mutex);

    if (!nportudp->open_count) {
        /* port was never opened */
        goto exit;
    }

    --nportudp->open_count;
    if (nportudp->open_count <= 0) {
        /* The port is being closed by the last user. */
        /* Do any hardware specific stuff here */

        /* shut down our timer */
        del_timer(&nportudp->timer);
    }
exit:
    mutex_unlock(&nportudp->mutex);
}

static void nportudp_close(struct tty_struct *tty, struct file *file) {
    struct nportudp_serial *nportudp = tty->driver_data;

    if (nportudp)
        do_close(nportudp);
}
void read_udp_answer(void) {
    unsigned char buf[255];
    unsigned char sbuf[1000];
    int size = 0;
    int data_size = 0;
    int bufsize = 255;
    struct tty_struct *tty;
    struct tty_port *port;
    int i = 0;
    wait_event_timeout(wait_queue_etx, false, 100);
    memset(&buf, 0, bufsize);
    while ((size = ksocket_receive(kthread->sock_send, &kthread->addr, buf, bufsize)) > 0) {
        if (size < 0)
            printk(KERN_INFO MODULE_NAME ": error getting datagram, sock_recvmsg error = %d\n", size);
        else {
            for (i = 0; i < size; i++)
                sprintf(sbuf + i * 3, "|%02x", buf[i]);
            printk("received data: %s, size: %d\n", sbuf, size);
        }
        data_size = size;
    }
    tty = nportudp_table[0]->tty;
    port = tty->port;

    /* send the data to the tty layer for users to read.  This doesn't
     * actually push the data through unless tty->low_latency is set */
    for (i = 0; i < data_size; ++i) {
        if (!tty_buffer_request_room(port, 1))
            tty_flip_buffer_push(port);
        tty_insert_flip_char(port, buf[i], TTY_NORMAL);
    }
    tty_flip_buffer_push(port);
}

static int nportudp_write(struct tty_struct *tty,
                          const unsigned char *buffer, int count) {
    struct nportudp_serial *nportudp = tty->driver_data;
    int i;
    int retval = -EINVAL;
    char buf[255];
    int bufsize = 255;

    if (!nportudp)
        return -ENODEV;

    mutex_lock(&nportudp->mutex);

    if (!nportudp->open_count)
        /* port was not opened */
        goto exit;

    /* fake sending the data out a hardware port by
     * writing it to the kernel debug log.
     */
    /*pr_debug("%s - ", __func__);
    for (i = 0; i < count; ++i)
            //pr_info("%02x ", buffer[i]);
    printk("%02x count %d", buffer[i], count);
    pr_info("\n");
    */

exit:
    mutex_unlock(&nportudp->mutex);
    // read garbage from socket

    // while ((ksocket_receive(kthread->sock_send, &kthread->addr, buf, bufsize)) > 0) {
    //     printk("have garbage from socket\n");
    // }
    ksocket_send(kthread->sock_send, &kthread->addr_send, buffer, count);
    // try to get answer
    // read_udp_answer();
    return count;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0))
static int nportudp_write_room(struct tty_struct *tty)
#else
static unsigned int nportudp_write_room(struct tty_struct *tty)
#endif
{
    struct nportudp_serial *nportudp = tty->driver_data;
    int room = -EINVAL;

    if (!nportudp)
        return -ENODEV;

    mutex_lock(&nportudp->mutex);

    if (!nportudp->open_count) {
        /* port was not opened */
        goto exit;
    }

    /* calculate how much room is left in the device */
    room = 255;

exit:
    mutex_unlock(&nportudp->mutex);
    return room;
}

#define RELEVANT_IFLAG(iflag) ((iflag) & (IGNBRK | BRKINT | IGNPAR | PARMRK | INPCK))

static void nportudp_set_termios(struct tty_struct *tty, struct ktermios *old_termios) {
    unsigned int cflag;

    cflag = tty->termios.c_cflag;

    /* check that they really want us to change something */
    if (old_termios) {
        if ((cflag == old_termios->c_cflag) &&
            (RELEVANT_IFLAG(tty->termios.c_iflag) ==
             RELEVANT_IFLAG(old_termios->c_iflag))) {
            pr_debug(" - nothing to change...\n");
            return;
        }
    }

    /* get the byte size */
    switch (cflag & CSIZE) {
        case CS5:
            pr_debug(" - data bits = 5\n");
            break;
        case CS6:
            pr_debug(" - data bits = 6\n");
            break;
        case CS7:
            pr_debug(" - data bits = 7\n");
            break;
        default:
        case CS8:
            pr_debug(" - data bits = 8\n");
            break;
    }

    /* determine the parity */
    if (cflag & PARENB)
        if (cflag & PARODD)
            pr_debug(" - parity = odd\n");
        else
            pr_debug(" - parity = even\n");
    else
        pr_debug(" - parity = none\n");

    /* figure out the stop bits requested */
    if (cflag & CSTOPB)
        pr_debug(" - stop bits = 2\n");
    else
        pr_debug(" - stop bits = 1\n");

    /* figure out the hardware flow control settings */
    if (cflag & CRTSCTS)
        pr_debug(" - RTS/CTS is enabled\n");
    else
        pr_debug(" - RTS/CTS is disabled\n");

    /* determine software flow control */
    /* if we are implementing XON/XOFF, set the start and
     * stop character in the device */
    if (I_IXOFF(tty) || I_IXON(tty)) {
        unsigned char stop_char = STOP_CHAR(tty);
        unsigned char start_char = START_CHAR(tty);

        /* if we are implementing INBOUND XON/XOFF */
        if (I_IXOFF(tty))
            pr_debug(
                " - INBOUND XON/XOFF is enabled, "
                "XON = %2x, XOFF = %2x",
                start_char, stop_char);
        else
            pr_debug(" - INBOUND XON/XOFF is disabled");

        /* if we are implementing OUTBOUND XON/XOFF */
        if (I_IXON(tty))
            pr_debug(
                " - OUTBOUND XON/XOFF is enabled, "
                "XON = %2x, XOFF = %2x",
                start_char, stop_char);
        else
            pr_debug(" - OUTBOUND XON/XOFF is disabled");
    }

    /* get the baud rate wanted */
    pr_debug(" - baud rate = %d", tty_get_baud_rate(tty));
}

/* Our fake UART values */
#define MCR_DTR 0x01
#define MCR_RTS 0x02
#define MCR_LOOP 0x04
#define MSR_CTS 0x08
#define MSR_CD 0x10
#define MSR_RI 0x20
#define MSR_DSR 0x40

static int nportudp_tiocmget(struct tty_struct *tty) {
    struct nportudp_serial *nportudp = tty->driver_data;

    unsigned int result = 0;
    unsigned int msr = nportudp->msr;
    unsigned int mcr = nportudp->mcr;

    result = ((mcr & MCR_DTR) ? TIOCM_DTR : 0) |   /* DTR is set */
             ((mcr & MCR_RTS) ? TIOCM_RTS : 0) |   /* RTS is set */
             ((mcr & MCR_LOOP) ? TIOCM_LOOP : 0) | /* LOOP is set */
             ((msr & MSR_CTS) ? TIOCM_CTS : 0) |   /* CTS is set */
             ((msr & MSR_CD) ? TIOCM_CAR : 0) |    /* Carrier detect is set*/
             ((msr & MSR_RI) ? TIOCM_RI : 0) |     /* Ring Indicator is set */
             ((msr & MSR_DSR) ? TIOCM_DSR : 0);    /* DSR is set */

    return result;
}

static int nportudp_tiocmset(struct tty_struct *tty, unsigned int set,
                             unsigned int clear) {
    struct nportudp_serial *nportudp = tty->driver_data;
    unsigned int mcr = nportudp->mcr;

    if (set & TIOCM_RTS)
        mcr |= MCR_RTS;
    if (set & TIOCM_DTR)
        mcr |= MCR_RTS;

    if (clear & TIOCM_RTS)
        mcr &= ~MCR_RTS;
    if (clear & TIOCM_DTR)
        mcr &= ~MCR_RTS;

    /* set the new MCR value in the device */
    nportudp->mcr = mcr;
    return 0;
}

static int nportudp_proc_show(struct seq_file *m, void *v) {
    struct nportudp_serial *nportudp;
    int i;

    seq_printf(m, "nportudpserinfo:1.0 driver:%s\n", DRIVER_VERSION);
    for (i = 0; i < NPORTUDP_TTY_MINORS; ++i) {
        nportudp = nportudp_table[i];
        if (nportudp == NULL)
            continue;

        seq_printf(m, "%d\n", i);
    }

    return 0;
}

#define nportudp_ioctl nportudp_ioctl_tiocgserial
static int nportudp_ioctl(struct tty_struct *tty, unsigned int cmd,
                          unsigned long arg) {
    struct nportudp_serial *nportudp = tty->driver_data;

    if (cmd == TIOCGSERIAL) {
        struct serial_struct tmp;

        if (!arg)
            return -EFAULT;

        memset(&tmp, 0, sizeof(tmp));

        tmp.type = nportudp->serial.type;
        tmp.line = nportudp->serial.line;
        tmp.port = nportudp->serial.port;
        tmp.irq = nportudp->serial.irq;
        tmp.flags = ASYNC_SKIP_TEST | ASYNC_AUTO_IRQ;
        tmp.xmit_fifo_size = nportudp->serial.xmit_fifo_size;
        tmp.baud_base = nportudp->serial.baud_base;
        tmp.close_delay = 5 * HZ;
        tmp.closing_wait = 30 * HZ;
        tmp.custom_divisor = nportudp->serial.custom_divisor;
        tmp.hub6 = nportudp->serial.hub6;
        tmp.io_type = nportudp->serial.io_type;

        if (copy_to_user((void __user *)arg, &tmp, sizeof(struct serial_struct)))
            return -EFAULT;
        return 0;
    }
    return -ENOIOCTLCMD;
}
#undef nportudp_ioctl

#define nportudp_ioctl nportudp_ioctl_tiocmiwait
static int nportudp_ioctl(struct tty_struct *tty, unsigned int cmd,
                          unsigned long arg) {
    struct nportudp_serial *nportudp = tty->driver_data;

    if (cmd == TIOCMIWAIT) {
        DECLARE_WAITQUEUE(wait, current);
        struct async_icount cnow;
        struct async_icount cprev;

        cprev = nportudp->icount;
        while (1) {
            add_wait_queue(&nportudp->wait, &wait);
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();
            remove_wait_queue(&nportudp->wait, &wait);

            /* see if a signal woke us up */
            if (signal_pending(current))
                return -ERESTARTSYS;

            cnow = nportudp->icount;
            if (cnow.rng == cprev.rng && cnow.dsr == cprev.dsr &&
                cnow.dcd == cprev.dcd && cnow.cts == cprev.cts)
                return -EIO; /* no change => error */
            if (((arg & TIOCM_RNG) && (cnow.rng != cprev.rng)) ||
                ((arg & TIOCM_DSR) && (cnow.dsr != cprev.dsr)) ||
                ((arg & TIOCM_CD) && (cnow.dcd != cprev.dcd)) ||
                ((arg & TIOCM_CTS) && (cnow.cts != cprev.cts))) {
                return 0;
            }
            cprev = cnow;
        }
    }
    return -ENOIOCTLCMD;
}
#undef nportudp_ioctl

#define nportudp_ioctl nportudp_ioctl_tiocgicount
static int nportudp_ioctl(struct tty_struct *tty, unsigned int cmd,
                          unsigned long arg) {
    struct nportudp_serial *nportudp = tty->driver_data;

    if (cmd == TIOCGICOUNT) {
        struct async_icount cnow = nportudp->icount;
        struct serial_icounter_struct icount;

        icount.cts = cnow.cts;
        icount.dsr = cnow.dsr;
        icount.rng = cnow.rng;
        icount.dcd = cnow.dcd;
        icount.rx = cnow.rx;
        icount.tx = cnow.tx;
        icount.frame = cnow.frame;
        icount.overrun = cnow.overrun;
        icount.parity = cnow.parity;
        icount.brk = cnow.brk;
        icount.buf_overrun = cnow.buf_overrun;

        if (copy_to_user((void __user *)arg, &icount, sizeof(icount)))
            return -EFAULT;
        return 0;
    }
    return -ENOIOCTLCMD;
}
#undef nportudp_ioctl

/* the real nportudp_ioctl function.  The above is done to get the small functions in the book */
static int nportudp_ioctl(struct tty_struct *tty, unsigned int cmd,
                          unsigned long arg) {
    switch (cmd) {
        case TIOCGSERIAL:
            return nportudp_ioctl_tiocgserial(tty, cmd, arg);
        case TIOCMIWAIT:
            return nportudp_ioctl_tiocmiwait(tty, cmd, arg);
        case TIOCGICOUNT:
            return nportudp_ioctl_tiocgicount(tty, cmd, arg);
    }

    return -ENOIOCTLCMD;
}

static const struct tty_operations serial_ops = {
    .open = nportudp_open,
    .close = nportudp_close,
    .write = nportudp_write,
    .write_room = nportudp_write_room,
    .set_termios = nportudp_set_termios,
    //.proc_show = nportudp_proc_show,
    .tiocmget = nportudp_tiocmget,
    .tiocmset = nportudp_tiocmset,
    .ioctl = nportudp_ioctl,
};

static int __init nportudp_init(void) {
    int retval;
    int i;

    /* allocate the tty driver */
    nportudp_tty_driver = alloc_tty_driver(NPORTUDP_TTY_MINORS);
    if (!nportudp_tty_driver)
        return -ENOMEM;

    /* initialize the tty driver */
    nportudp_tty_driver->owner = THIS_MODULE;
    nportudp_tty_driver->driver_name = "nportudp";
    nportudp_tty_driver->name = "ttyr";
    nportudp_tty_driver->major = NPORTUDP_TTY_MAJOR,
    nportudp_tty_driver->type = TTY_DRIVER_TYPE_SERIAL,
    nportudp_tty_driver->subtype = SERIAL_TYPE_NORMAL,
    nportudp_tty_driver->flags = TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV,
    nportudp_tty_driver->init_termios = tty_std_termios;
    nportudp_tty_driver->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
    tty_set_operations(nportudp_tty_driver, &serial_ops);
    for (i = 0; i < NPORTUDP_TTY_MINORS; i++) {
        tty_port_init(nportudp_tty_port + i);
        tty_port_link_device(nportudp_tty_port + i, nportudp_tty_driver, i);
    }

    /* register the tty driver */
    retval = tty_register_driver(nportudp_tty_driver);
    if (retval) {
        pr_err("failed to register nportudp tty driver");
        put_tty_driver(nportudp_tty_driver);
        return retval;
    }

    for (i = 0; i < NPORTUDP_TTY_MINORS; ++i)
        tty_register_device(nportudp_tty_driver, i, NULL);

    pr_info(DRIVER_DESC " " DRIVER_VERSION);
    ksocket_init();
    return retval;
}

static void __exit nportudp_exit(void) {
    struct nportudp_serial *nportudp;
    int i;
    ksocket_exit();
    for (i = 0; i < NPORTUDP_TTY_MINORS; ++i) {
        tty_unregister_device(nportudp_tty_driver, i);
        tty_port_destroy(nportudp_tty_port + i);
    }
    tty_unregister_driver(nportudp_tty_driver);

    /* shut down all of the timers and free the memory */
    for (i = 0; i < NPORTUDP_TTY_MINORS; ++i) {
        nportudp = nportudp_table[i];
        if (nportudp) {
            /* close the port */
            while (nportudp->open_count)
                do_close(nportudp);

            /* shut down our timer and free the memory */
            //		del_timer(&nportudp->timer);
            //		kfree(nportudp);
            nportudp_table[i] = NULL;
        }
    }
}
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len) {
    struct msghdr msg;
    // struct iovec iov;
    struct kvec iov = {.iov_base = buf, .iov_len = len};
    mm_segment_t oldfs;
    int size = 0;

    if (sock->sk == NULL)
        return 0;

    // iov.iov_base = buf;
    // iov.iov_len = len;
    iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, &iov, 1, len);

    msg.msg_flags = 0;
    msg.msg_name = addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    // msg.msg_iov = &iov;
    // msg.msg_iovlen = 1;
    msg.msg_control = NULL;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    // size = sock_sendmsg(sock,&msg,len);
    size = sock_sendmsg(sock, &msg);
    set_fs(oldfs);
    return size;
}
int ksocket_receive(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len) {
    struct msghdr msg;
    // struct iovec iov;
    struct kvec iov = {.iov_base = buf, .iov_len = len};
    mm_segment_t oldfs;
    int size = 0;

    if (sock->sk == NULL) return 0;

    // iov.iov_base = buf;
    // iov.iov_len = len;
    iov_iter_kvec(&msg.msg_iter, READ | ITER_KVEC, &iov, 1, len);

    msg.msg_flags = 0;
    msg.msg_name = addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    // msg.msg_iov = &iov;
    // msg.msg_iovlen = 1;
    msg.msg_control = NULL;

    oldfs = get_fs();
    set_fs(KERNEL_DS);
    size = sock_recvmsg(sock, &msg, msg.msg_flags);
    // size = sock_recvmsg(sock, &msg, MSG_DONTWAIT);
    set_fs(oldfs);

    return size;
}
// 192.168.127.254
#define INADDR_SEND 0xc0a87ffe  // INADDR_LOOPBACK
#define DEFAULT_PORT 2325
// #define CONNECT_PORT 23
#define CONNECT_PORT 4001

static void ksocket_start(void) {
    int size, err;
    int bufsize = 20;
    int counter = 0;
    unsigned char buf[bufsize + 1];
    unsigned char sbuf[100];
    int i = 0;

    /* kernel thread initialization */
    // lock_kernel();
    // struct kthread_t *kthread = npvar_net_nodes[0].kthread;
    kthread->running = 1;

    current->flags |= PF_NOFREEZE;

    /* daemonize (take care with signals, after daemonize() they are disabled) */
    // daemonize(MODULE_NAME);
    allow_signal(SIGKILL);
    // unlock_kernel();

    /* main loop */
    for (;;) {
        memset(&buf, 0, bufsize + 1);
        while ((size = ksocket_receive(kthread->sock_send, &kthread->addr, buf, bufsize)) > 0) {
            if (size < 0)
                printk(KERN_INFO MODULE_NAME ": error getting datagram, sock_recvmsg error = %d\n", size);
            else {
                // printk(KERN_INFO MODULE_NAME ": received %d bytes: %d\n", size);

                // printk("received data: %s, size: %d\n", buf, size);
                for (i = 0; i < size; i++)
                    sprintf(sbuf + i * 3, "|%02x", buf[i]);
                printk("received data: %s, size: %d\n", sbuf, size);
            }
            memset(&buf, 0, bufsize + 1);
        }

        // printk ("call\n");
        wait_event_timeout(wait_queue_etx, false, HZ);

        memset(&buf, 0, bufsize + 1);
        sprintf(buf, "message: %d", counter++);

        printk("sending: %s bytes: %d\n", buf, strlen(buf) + 1);
        ksocket_send(kthread->sock_send, &kthread->addr_send, buf, strlen(buf) + 1);

        if (signal_pending(current))
            break;

        wait_event_timeout(wait_queue_etx, false, 100);
    }

close_and_out:
    // sock_release(kthread->sock);
    sock_release(kthread->sock_send);
    // kthread->sock = NULL;
    kthread->sock_send = NULL;

out:
    kthread->thread = NULL;
    kthread->running = 0;
}

static void ksocket_start2(void) {
    int size;
    int bufsize = 255;
    unsigned char buf[255];
    unsigned char sbuf[900];
    int i = 0;
    struct tty_struct *tty;
    struct tty_port *port;

    kthread->running = 1;

    current->flags |= PF_NOFREEZE;

    allow_signal(SIGKILL);
    // unlock_kernel();

    memset(&buf, 0, bufsize);
    // printk("befor cycle\n");
    for (;;) {
        //  printk("in cycle\n");
        size = ksocket_receive(kthread->sock_send, &kthread->addr, buf, bufsize);
        if (size > 0) {
            // printk("size more then 0\n");
            tty = nportudp_table[0]->tty;
            port = tty->port;
            /*
                        for (i = 0; i < size; i++)
                            sprintf(sbuf + i * 3, "|%02x", buf[i]);
                        printk("received data: %s, size: %d\n", sbuf, size);
            */
            for (i = 0; i < size; ++i) {
                if (!tty_buffer_request_room(port, 1))
                    tty_flip_buffer_push(port);
                tty_insert_flip_char(port, buf[i], TTY_NORMAL);
            }
            tty_flip_buffer_push(port);

            memset(&buf, 0, bufsize);
        }
        if (signal_pending(current))
            break;
    }

close_and_out:
    sock_release(kthread->sock_send);
    kthread->sock_send = NULL;

out:
    kthread->thread = NULL;
    kthread->running = 0;
}

int ksocket_init(void) {
    kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
    memset(kthread, 0, sizeof(struct kthread_t));

    int err;

    /* create a socket */
    if (((err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock_send)) < 0))  // ||
                                                                                           //             ( (err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock)) < 0 ))
    {
        printk(KERN_INFO MODULE_NAME ": Could not create a datagram socket, error = %d\n", -ENXIO);
        //        goto out;
    }

    memset(&kthread->addr, 0, sizeof(struct sockaddr));
    memset(&kthread->addr_send, 0, sizeof(struct sockaddr));
    kthread->addr.sin_family = AF_INET;
    kthread->addr_send.sin_family = AF_INET;

    kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
    kthread->addr_send.sin_addr.s_addr = htonl(INADDR_SEND);

    // kthread->addr.sin_port = htons(DEFAULT_PORT);
    kthread->addr.sin_port = htons(CONNECT_PORT);
    kthread->addr_send.sin_port = htons(CONNECT_PORT);

    if (((err = kthread->sock_send->ops->bind(kthread->sock_send, (struct sockaddr *)&kthread->addr, sizeof(struct sockaddr))) < 0))  //||
                                                                                                                                      //(err = kthread->sock_send->ops->connect(kthread->sock_send, (struct sockaddr *)&kthread->addr_send, sizeof(struct sockaddr), 0) < 0 ))
    {
        printk(KERN_INFO MODULE_NAME ": Could not bind or connect to socket, error = %d\n", -err);
        //      goto close_and_out;
    }
    printk(KERN_INFO MODULE_NAME ": listening on port %d\n", CONNECT_PORT);
    //printk(KERN_INFO MODULE_NAME ": listening on port %d\n", DEFAULT_PORT);
    /* start kernel thread */

    kthread->thread = kthread_run((void *)ksocket_start2, NULL, MODULE_NAME);
    if (IS_ERR(kthread->thread)) {
        printk(KERN_INFO MODULE_NAME ": unable to start kernel thread\n");
        kfree(kthread);
        kthread = NULL;
        return -ENOMEM;
    }

    return 0;
}
void ksocket_exit(void) {
    int err;
    
    if (kthread->thread == NULL)
        printk(KERN_INFO MODULE_NAME ": no kernel thread to kill\n");
    else {
        //                lock_kernel();
        // err = kill_proc(kthread->thread->pid, SIGKILL, 1);
    
        err = kill_pid(task_pid(kthread->thread), SIGKILL, 1);
        
    //    kthread_stop(task_pid(kthread->thread));
        // kthread_stop(kthread->thread);
        //                 unlock_kernel();

        /* wait for kernel thread to die */
        if (err < 0)
            printk(KERN_INFO MODULE_NAME ": unknown error %d while trying to terminate kernel thread\n", -err);
        else {
            while (kthread->running == 1)
                msleep(10);
            printk(KERN_INFO MODULE_NAME ": succesfully killed kernel thread!\n");
        }	
    }

    /* free allocated resources before exit */
    if (kthread->sock_send != NULL) {
        sock_release(kthread->sock_send);
        kthread->sock_send = NULL;
    }
    kfree(kthread);
    kthread = NULL;

}
module_init(nportudp_init);
module_exit(nportudp_exit);