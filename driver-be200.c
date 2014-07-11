/*
 * Copyright 2013-2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2013 Xiangfu <xiangfu@openmobilefree.com>
 * Copyright 2012 Luke Dashjr
 * Copyright 2012 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#ifndef WIN32
  #include <sys/select.h>
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
  #endif
#else
  #include "compat.h"
  #include <windows.h>
  #include <io.h>
#endif

#include "elist.h"
#include "miner.h"
#include "usbutils.h"
#include "driver-be200.h"
#include "hexdump.c"
#include "util.h"

int opt_be200_temp = BE200_TEMP_TARGET;
int opt_be200_overheat = BE200_TEMP_OVERHEAT;
int opt_be200_fan_min = BE200_DEFAULT_FAN_MIN_PWM;
int opt_be200_fan_max = BE200_DEFAULT_FAN_MAX_PWM;
int opt_be200_freq_min = BE200_MIN_FREQUENCY;
int opt_be200_freq_max = BE200_MAX_FREQUENCY;
int opt_bitburner_core_voltage = BITBURNER_DEFAULT_CORE_VOLTAGE;
int opt_bitburner_fury_core_voltage = BITBURNER_FURY_DEFAULT_CORE_VOLTAGE;
bool opt_be200_auto;

static int option_offset = -1;
static int bbf_option_offset = -1;

static inline void be200_create_task(struct be200_task *at,
				      struct work *work)
{
	memcpy(at->midstate, work->midstate, 32);
	memcpy(at->mshit, work->data+ 64, 4);
	memcpy(at->ntime, work->data+ 68, 4);
	memcpy(at->ndiff, work->data+ 72, 4);
}

static int be200_write(struct cgpu_info *be200, char *buf, ssize_t len, int ep)
{
	int err, amount;

	err = usb_write(be200, buf, len, &amount, ep);
	applog(LOG_DEBUG, "%s%i: usb_write got err %d", be200->drv->name,
	       be200->device_id, err);

	if (unlikely(err != 0)) {
		applog(LOG_WARNING, "usb_write error on be200_write");
		return BE200_SEND_ERROR;
	}
	if (amount != len) {
		applog(LOG_WARNING, "usb_write length mismatch on be200_write");
		return BE200_SEND_ERROR;
	}

	return BE200_SEND_OK;
}

static int be200_send_task(const struct be200_task *at, struct cgpu_info *be200,
			    struct be200_info *info)

{
	uint8_t buf[BE200_WRITE_SIZE + 1];
	int delay, ret, i, ep = C_BE200_TASK;
	uint32_t nonce_range;
	size_t nr_len;

	nr_len = 1+ BE200_WRITE_SIZE;

        buf[0] = C_JOB;
	memcpy(buf + 1, at, BE200_WRITE_SIZE);

	delay = nr_len * 10 * 1000000;
	//delay = delay / info->baud;
	delay += 4000;

	if (opt_debug) {
		applog(LOG_DEBUG, "BE200: Sent(%u):", (unsigned int)nr_len);
		hexdump(buf, nr_len);
	}
	/* Sleep from the last time we sent data */
	cgsleep_us_r(&info->cgsent, info->send_delay);

	cgsleep_prepare_r(&info->cgsent);
	ret = be200_write(be200, (char *)buf, nr_len, ep);

	applog(LOG_DEBUG, "BE200: Sent: Buffer delay: %dus", info->send_delay);
	info->send_delay = delay;

	return ret;
}


static bool be200_decode_nonce(struct thr_info *thr, struct cgpu_info *be200,
				struct be200_info *info, struct be200_result *ar,
				struct work *work)
{
	uint32_t nonce;

	info = be200->device_data;
	//info->matching_work[work->subid]++;
	nonce = htole32(ar->nonce);

	applog(LOG_DEBUG, "Avalon: nonce = %0x08x", nonce);
	return submit_nonce(thr, work, nonce);
}

/* Wait until the ftdi chip returns a CTS saying we can send more data. */
static void wait_be200_ready(struct cgpu_info *be200)
{
	while (be200_buffer_full(be200)) {
		cgsleep_ms(40);
	}
}

#define BE200_CTS    (1 << 4)

static inline bool be200_cts(char c)
{
	return (c & BE200_CTS);
}

static int be200_read(struct cgpu_info *be200, char *buf, size_t bufsize, int ep)
{
	size_t total = 0, readsize = bufsize + 2;
	char readbuf[BE200_READBUF_SIZE];
	int err, amount, ofs = 2, cp;

	err = usb_read_once(be200, readbuf, readsize, &amount, ep);
	applog(LOG_DEBUG, "%s%i: Get be200 read got err %d",
	       be200->drv->name, be200->device_id, err);
	if (err && err != LIBUSB_ERROR_TIMEOUT)
		return err;

	memcpy(buf, readbuf, readsize);

	return amount;
}

static int be200_reset(struct cgpu_info *be200, bool initial)
{
	struct be200_result ar;
	int ret, i, spare;
	struct be200_task at;
	uint8_t *buf, *tmp;
	struct timespec p;
	struct be200_info *info = be200->device_data;


	wait_be200_ready(be200);
	ret = be200_send_task(&at, be200, info);
	if (unlikely(ret == BE200_SEND_ERROR))
		return -1;

	if (!initial) {
		applog(LOG_ERR, "%s%d reset sequence sent", be200->drv->name, be200->device_id);
		return 0;
	}

	ret = be200_read(be200, (char *)&ar, BE200_READ_SIZE, C_GET_BE200_RESET);

	/* What do these sleeps do?? */
	p.tv_sec = 0;
	p.tv_nsec = BE200_RESET_PITCH;
	nanosleep(&p, NULL);

	/* Look for the first occurrence of 0xAA, the reset response should be:
	 * AA 55 AA 55 00 00 00 00 00 00 */
	spare = ret - 10;
	buf = tmp = (uint8_t *)&ar;
	if (opt_debug) {
		applog(LOG_DEBUG, "%s%d reset: get:", be200->drv->name, be200->device_id);
		hexdump(tmp, BE200_READ_SIZE);
	}

	for (i = 0; i <= spare; i++) {
		buf = &tmp[i];
		if (buf[0] == 0xAA)
			break;
	}
	i = 0;

	if (buf[0] == 0xAA && buf[1] == 0x55 &&
	    buf[2] == 0xAA && buf[3] == 0x55) {
		for (i = 4; i < 11; i++)
			if (buf[i] != 0)
				break;
	}

	if (i != 11) {
		applog(LOG_ERR, "%s%d: Reset failed! not an Avalon?"
		       " (%d: %02x %02x %02x %02x)", be200->drv->name, be200->device_id,
		       i, buf[0], buf[1], buf[2], buf[3]);
		/* FIXME: return 1; */
	} else {
		/* buf[44]: minor
		 * buf[45]: day
		 * buf[46]: year,month, d6: 201306
		info->ctlr_ver = ((buf[46] >> 4) + 2000) * 1000000 +
			(buf[46] & 0x0f) * 10000 +
			buf[45] * 100 +	buf[44];
		applog(LOG_WARNING, "%s%d: Reset succeeded (Controller version: %d)",
		       be200->drv->name, be200->device_id, info->ctlr_ver);		 */

	}

	return 0;
}

static int be200_calc_timeout(int frequency)
{
	return BE200_TIMEOUT_FACTOR / frequency;
}

static bool get_options(int this_option_offset, int *baud, int *miner_count,
			int *asic_count, int *timeout, int *frequency, int *asic,
			char *options)
{
	char buf[BUFSIZ+1];
	char *ptr, *comma, *colon, *colon2, *colon3, *colon4, *colon5;
	bool timeout_default;
	size_t max;
	int i, tmp;

	if (options == NULL)
		buf[0] = '\0';
	else {
		ptr = options;
		for (i = 0; i < this_option_offset; i++) {
			comma = strchr(ptr, ',');
			if (comma == NULL)
				break;
			ptr = comma + 1;
		}

		comma = strchr(ptr, ',');
		if (comma == NULL)
			max = strlen(ptr);
		else
			max = comma - ptr;

		if (max > BUFSIZ)
			max = BUFSIZ;
		strncpy(buf, ptr, max);
		buf[max] = '\0';
	}

	if (!(*buf))
		return false;

	colon = strchr(buf, ':');
	if (colon)
		*(colon++) = '\0';

	tmp = atoi(buf);
	switch (tmp) {
	case 115200:
		*baud = 115200;
		break;
	case 57600:
		*baud = 57600;
		break;
	case 38400:
		*baud = 38400;
		break;
	case 19200:
		*baud = 19200;
		break;
	default:
		quit(1, "Invalid be200-options for baud (%s) "
			"must be 115200, 57600, 38400 or 19200", buf);
	}

	if (colon && *colon) {
		colon2 = strchr(colon, ':');
		if (colon2)
			*(colon2++) = '\0';

		if (*colon) {
			tmp = atoi(colon);
			if (tmp > 0 && tmp <= BE200_MAX_MINER_NUM) {
				*miner_count = tmp;
			} else {
				quit(1, "Invalid be200-options for "
					"miner_count (%s) must be 1 ~ %d",
					colon, BE200_MAX_MINER_NUM);
			}
		}

		if (colon2 && *colon2) {
			colon3 = strchr(colon2, ':');
			if (colon3)
				*(colon3++) = '\0';

			tmp = atoi(colon2);
			if (tmp > 0 && tmp <= BE200_DEFAULT_ASIC_NUM)
				*asic_count = tmp;
			else {
				quit(1, "Invalid be200-options for "
					"asic_count (%s) must be 1 ~ %d",
					colon2, BE200_DEFAULT_ASIC_NUM);
			}

			timeout_default = false;
			if (colon3 && *colon3) {
				colon4 = strchr(colon3, ':');
				if (colon4)
					*(colon4++) = '\0';

				if (tolower(*colon3) == 'd')
					timeout_default = true;
				else {
					tmp = atoi(colon3);
					if (tmp > 0 && tmp <= 0xff)
						*timeout = tmp;
					else {
						quit(1, "Invalid be200-options for "
							"timeout (%s) must be 1 ~ %d",
							colon3, 0xff);
					}
				}
				if (colon4 && *colon4) {
					colon5 = strchr(colon4, ':');
					if (colon5)
						*(colon5++) = '\0';

					tmp = atoi(colon4);
					if (tmp < BE200_MIN_FREQUENCY || tmp > BE200_MAX_FREQUENCY) {
						quit(1, "Invalid be200-options for frequency, must be %d <= frequency <= %d",
						     BE200_MIN_FREQUENCY, BE200_MAX_FREQUENCY);
					}
					*frequency = tmp;
					if (timeout_default)
						*timeout = be200_calc_timeout(*frequency);
					if (colon5 && *colon5) {
						tmp = atoi(colon5);
						if (tmp != BE200_A3256 && tmp != BE200_A3255)
							quit(1, "Invalid be200-options for asic, must be 110 or 55");
						*asic = tmp;
					}
				}
			}
		}
	}
	return true;
}

char *set_be200_fan(char *arg)
{
	int val1, val2, ret;

	ret = sscanf(arg, "%d-%d", &val1, &val2);
	if (ret < 1)
		return "No values passed to be200-fan";
	if (ret == 1)
		val2 = val1;

	if (val1 < 0 || val1 > 100 || val2 < 0 || val2 > 100 || val2 < val1)
		return "Invalid value passed to be200-fan";

	opt_be200_fan_min = val1 * BE200_PWM_MAX / 100;
	opt_be200_fan_max = val2 * BE200_PWM_MAX / 100;

	return NULL;
}

char *set_be200_freq(char *arg)
{
	int val1, val2, ret;

	ret = sscanf(arg, "%d-%d", &val1, &val2);
	if (ret < 1)
		return "No values passed to be200-freq";
	if (ret == 1)
		val2 = val1;

	if (val1 < BE200_MIN_FREQUENCY || val1 > BE200_MAX_FREQUENCY ||
	    val2 < BE200_MIN_FREQUENCY || val2 > BE200_MAX_FREQUENCY ||
	    val2 < val1)
		return "Invalid value passed to be200-freq";

	opt_be200_freq_min = val1;
	opt_be200_freq_max = val2;

	return NULL;
}


#define transfer(icarus, request_type, bRequest, wValue, wIndex, cmd) \
		_transfer(icarus, request_type, bRequest, wValue, wIndex, NULL, 0, cmd)


static void _transfer(struct cgpu_info *icarus, uint8_t request_type, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t *data, int siz, enum usb_cmds cmd)
{
	int err;

	err = usb_transfer_data(icarus, request_type, bRequest, wValue, wIndex, data, siz, cmd);

	applog(LOG_DEBUG, "%s: cgid %d %s got err %d",
			icarus->drv->name, icarus->cgminer_id,
			usb_cmdname(cmd), err);
}


static void be200_initialise(struct cgpu_info *be200)
{
	int err, interface;

	if (be200->usbinfo.nodev)
		return;

	interface = usb_interface(be200);

    // Enable the UART
    transfer(be200, CP210X_TYPE_OUT, CP210X_REQUEST_IFC_ENABLE,
         CP210X_VALUE_UART_ENABLE,
         interface, C_ENABLE_UART);

    if (be200->usbinfo.nodev)
        return;
    
    // Set line control
    transfer(be200, CP210X_TYPE_OUT, BE200_CP210X_SET_LINE_CTL, BE200_CP210X_LINE_CTL_VALUE,
         interface, C_SETFLOW);
    
    if (be200->usbinfo.nodev)
        return;

    // Set data control
    transfer(be200, CP210X_TYPE_OUT, CP210X_REQUEST_DATA, BE200_CP210X_VALUE_DATA,
         interface, C_SETDATA);
    
    if (be200->usbinfo.nodev)
        return;
    
    // Set the baud
    uint32_t data = BE200_CP210X_DATA_BAUD;
    _transfer(be200, CP210X_TYPE_OUT, CP210X_REQUEST_BAUD, 0,
         interface, &data, sizeof(data), C_SETBAUD);

    /*
	// Reset
	err = usb_transfer(be200, FTDI_TYPE_OUT, FTDI_REQUEST_RESET,
				FTDI_VALUE_RESET, interface, C_RESET);

	applog(LOG_DEBUG, "%s%i: reset got err %d",
		be200->drv->name, be200->device_id, err);

	if (be200->usbinfo.nodev)
		return;

	// Set latency
	err = usb_transfer(be200, FTDI_TYPE_OUT, FTDI_REQUEST_LATENCY,
			   BE200_LATENCY, interface, C_LATENCY);

	applog(LOG_DEBUG, "%s%i: latency got err %d",
		be200->drv->name, be200->device_id, err);

	if (be200->usbinfo.nodev)
		return;

	// Set data
	err = usb_transfer(be200, FTDI_TYPE_OUT, FTDI_REQUEST_DATA,
				FTDI_VALUE_DATA_BE200, interface, C_SETDATA);

	applog(LOG_DEBUG, "%s%i: data got err %d",
		be200->drv->name, be200->device_id, err);

	if (be200->usbinfo.nodev)
		return;

	// Set the baud
	err = usb_transfer(be200, FTDI_TYPE_OUT, FTDI_REQUEST_BAUD, FTDI_VALUE_BAUD_BE200,
				(FTDI_INDEX_BAUD_BE200 & 0xff00) | interface,
				C_SETBAUD);

	applog(LOG_DEBUG, "%s%i: setbaud got err %d",
		be200->drv->name, be200->device_id, err);

	if (be200->usbinfo.nodev)
		return;

	// Set Modem Control
	err = usb_transfer(be200, FTDI_TYPE_OUT, FTDI_REQUEST_MODEM,
				FTDI_VALUE_MODEM, interface, C_SETMODEM);

	applog(LOG_DEBUG, "%s%i: setmodemctrl got err %d",
		be200->drv->name, be200->device_id, err);

	if (be200->usbinfo.nodev)
		return;

	// Set Flow Control
	err = usb_transfer(be200, FTDI_TYPE_OUT, FTDI_REQUEST_FLOW,
				FTDI_VALUE_FLOW, interface, C_SETFLOW);

	applog(LOG_DEBUG, "%s%i: setflowctrl got err %d",
		be200->drv->name, be200->device_id, err);
*/

}


static struct cgpu_info *be200_detect_one(libusb_device *dev, struct usb_find_devices *found)
{
	int baud, miner_count, asic_count, timeout, frequency, asic;
	int this_option_offset;
	struct be200_info *info;
	struct cgpu_info *be200;
	bool configured;
	int ret, i;
        uint8_t cmd_char, out_char;
        char buf[128];

	be200 = usb_alloc_cgpu(&be200_drv, BE200_MINER_THREADS);

	baud = BE200_IO_SPEED;
	miner_count = BE200_DEFAULT_MINER_NUM;
	asic_count = BE200_DEFAULT_ASIC_NUM;
	timeout = BE200_DEFAULT_TIMEOUT;
	frequency = BE200_DEFAULT_FREQUENCY;

	if (!usb_init(be200, dev, found))
		goto shin;


	/* Even though this is an FTDI type chip, we want to do the parsing
	 * all ourselves so set it to std usb type */
	be200->usbdev->usb_type = USB_TYPE_STD;

	/* We have a real Avalon! */
	be200_initialise(be200);

	be200->device_data = calloc(sizeof(struct be200_info), 1);
	if (unlikely(!(be200->device_data)))
		quit(1, "Failed to calloc be200_info data");
	info = be200->device_data;

        info->miner_count = 1;
        info->asic_count = 24;
        info->timeout = 50;
        info->frequency = 17;

        for (i = 0; i < BE200_MAX_BOARD_NUM; i++) {
            cmd_char = C_ASK + i;
            ret = be200_write(be200, (char *)&cmd_char, 1, C_BE200_INIT);
            
            applog(LOG_DEBUG, "BE200 init board: %x", cmd_char);

            cgsleep_ms(1000);
            ret = be200_read(be200, &out_char, 1, C_BE200_READ);
            
            applog(LOG_DEBUG, "BE200 init board return: %x", out_char);
            if (out_char == A_WAL) {
                applog(LOG_DEBUG, "BE200 board found %d ......................................", i);
                info->board_id = i;
                break;
            }
        }

        
        cmd_char = C_TRS + info->board_id;
        ret = be200_write(be200, (char *)&cmd_char, 1, C_BE200_INIT);
        cgsleep_ms(1000);
        ret = be200_read(be200, buf, 67, C_BE200_READ);
        applog(LOG_DEBUG, "BE200 send: %x", cmd_char);
        hexdump((uint8_t *)buf, ret);
  

	if (!add_cgpu(be200))
		goto unshin;

/*
	ret = be200_reset(be200, true);
	if (ret && !configured)
		goto unshin;
*/

	update_usb_stats(be200);

	//be200_idle(be200, info);


	return be200;

unshin:

	usb_uninit(be200);

shin:

	free(be200->device_data);
	be200->device_data = NULL;

	be200 = usb_free_cgpu(be200);

	return NULL;
}

static void be200_detect(bool __maybe_unused hotplug)
{
	applog(LOG_INFO, "be200_detect");
	usb_detect(&be200_drv, be200_detect_one);
}

static void be200_init(struct cgpu_info *be200)
{
	applog(LOG_INFO, "BE200: Opened on %s", be200->device_path);
}

static void be200_update_temps(struct cgpu_info *be200, struct be200_info *info,
				struct be200_result *ar);


static void be200_parse_results(struct cgpu_info *be200, struct be200_info *info,
				 struct thr_info *thr, char *buf, int *offset)
{

}

static void be200_running_reset(struct cgpu_info *be200,
				   struct be200_info *info)
{
	be200_reset(be200, false);
	be200->results = 0;
}

static void *be200_get_results(void *userdata)
{
	struct cgpu_info *be200 = (struct cgpu_info *)userdata;
	struct be200_info *info = be200->device_data;
	const int rsize = BE200_FTDI_READSIZE;
	char readbuf[BE200_READBUF_SIZE];
	struct thr_info *thr = info->thr;
	int offset = 0, ret = 0;
	char threadname[16];

	snprintf(threadname, sizeof(threadname), "%d/AvaRecv", be200->device_id);
	RenameThread(threadname);

	while (likely(!be200->shutdown)) {
		char buf[rsize];

                //todo: send a7 to query the status
                

		if (offset >= (int)BE200_READ_SIZE)
			be200_parse_results(be200, info, thr, readbuf, &offset);

		if (unlikely(offset + rsize >= BE200_READBUF_SIZE)) {
			/* This should never happen */
			applog(LOG_ERR, "Avalon readbuf overflow, resetting buffer");
			offset = 0;
		}

		ret = be200_read(be200, buf, rsize, C_BE200_READ);

		if (unlikely(ret < 0))
			break;

		if (ret < 1)
			continue;

		if (opt_debug) {
			applog(LOG_DEBUG, "Avalon: get:");
			hexdump((uint8_t *)buf, ret);
		}

		memcpy(&readbuf[offset], &buf, ret);
		offset += ret;
	}
	return NULL;
}

static void be200_rotate_array(struct cgpu_info *be200, struct be200_info *info)
{
	mutex_lock(&info->qlock);
	be200->queued = 0;
	if (++be200->work_array >= BE200_ARRAY_SIZE)
		be200->work_array = 0;
	mutex_unlock(&info->qlock);
}

static void be200_set_timeout(struct be200_info *info)
{
	info->timeout = be200_calc_timeout(info->frequency);
}

static void *be200_send_tasks(void *userdata)
{
	struct cgpu_info *be200 = (struct cgpu_info *)userdata;
	struct be200_info *info = be200->device_data;
	const int be200_get_work_count = info->miner_count;
	char threadname[16];

	snprintf(threadname, sizeof(threadname), "%d/BE200Send", be200->device_id);
	RenameThread(threadname);

	while (likely(!be200->shutdown)) {
		int start_count, end_count, i, j, ret;
		cgtimer_t ts_start;
		struct be200_task at;
		bool idled = false;
		int64_t us_timeout;

		/* A full nonce range */
		us_timeout = 0x100000000ll / info->asic_count / info->frequency;
		cgsleep_prepare_r(&ts_start);

		start_count = be200->work_array * be200_get_work_count;
		end_count = start_count + be200_get_work_count;
		for (i = start_count, j = 0; i < end_count; i++, j++) {

                        be200_create_task(&at, be200->works[i]);

			ret = be200_send_task(&at, be200, info);

			if (unlikely(ret == BE200_SEND_ERROR)) {
				/* Send errors are fatal */
				applog(LOG_ERR, "%s%i: Comms error(buffer)",
				       be200->drv->name, be200->device_id);
				dev_error(be200, REASON_DEV_COMMS_ERROR);
				goto out;
			}
		}

		be200_rotate_array(be200, info);

		cgsem_post(&info->qsem);

		if (unlikely(idled)) {
			applog(LOG_WARNING, "%s%i: Idled %d miners",
			       be200->drv->name, be200->device_id, idled);
		}

		/* Sleep how long it would take to complete a full nonce range
		 * at the current frequency using the clock_nanosleep function
		 * timed from before we started loading new work so it will
		 * fall short of the full duration. */
		cgsleep_us_r(&ts_start, us_timeout);
	}
out:
	return NULL;
}

static bool be200_prepare(struct thr_info *thr)
{
	struct cgpu_info *be200 = thr->cgpu;
	struct be200_info *info = be200->device_data;
	int array_size = BE200_ARRAY_SIZE;
	void *(*write_thread_fn)(void *) = be200_send_tasks;

	free(be200->works);
	be200->works = calloc(info->miner_count * sizeof(struct work *),
			       array_size);
	if (!be200->works)
		quit(1, "Failed to calloc be200 works in be200_prepare");

	info->thr = thr;
	mutex_init(&info->lock);
	mutex_init(&info->qlock);
	cgsem_init(&info->qsem);

	if (pthread_create(&info->read_thr, NULL, be200_get_results, (void *)be200))
		quit(1, "Failed to create be200 read_thr");

	if (pthread_create(&info->write_thr, NULL, write_thread_fn, (void *)be200))
		quit(1, "Failed to create be200 write_thr");

	be200_init(be200);

	return true;
}


/* We use a replacement algorithm to only remove references to work done from
 * the buffer when we need the extra space for new work. */
static bool be200_fill(struct cgpu_info *be200)
{
	struct be200_info *info = be200->device_data;
	int subid, slot, mc;
	struct work *work;
	bool ret = true;

	mc = info->miner_count;
	mutex_lock(&info->qlock);
	if (be200->queued >= mc)
		goto out_unlock;
	work = get_queued(be200);
	if (unlikely(!work)) {
		ret = false;
		goto out_unlock;
	}
	subid = be200->queued++;
	work->subid = subid;
	slot = be200->work_array * mc + subid;
	if (likely(be200->works[slot]))
		work_completed(be200, be200->works[slot]);
	be200->works[slot] = work;
	if (be200->queued < mc)
		ret = false;
out_unlock:
	mutex_unlock(&info->qlock);

	return ret;
}

static int64_t be200_scanhash(struct thr_info *thr)
{
	struct cgpu_info *be200 = thr->cgpu;
	struct be200_info *info = be200->device_data;
	const int miner_count = info->miner_count;
	int64_t hash_count, ms_timeout;

	/* Half nonce range */
	ms_timeout = 0x80000000ll / info->asic_count / info->frequency / 1000;

	/* Wait until be200_send_tasks signals us that it has completed
	 * sending its work or a full nonce range timeout has occurred. We use
	 * cgsems to never miss a wakeup. */
	cgsem_mswait(&info->qsem, ms_timeout);

	mutex_lock(&info->lock);
    /*
	hash_count = 0xffffffffull * (uint64_t)info->nonces;
	be200->results += info->nonces;
	if (be200->results > miner_count || info->idle)
		be200->results = miner_count;

	info->nonces = info->idle = 0;
	*/
	mutex_unlock(&info->lock);



	if (unlikely(be200->usbinfo.nodev)) {
		applog(LOG_ERR, "%s%d: Device disappeared, shutting down thread",
		       be200->drv->name, be200->device_id);
		hash_count = -1;
	}

	/* This hashmeter is just a utility counter based on returned shares */
	return hash_count;
}

static void be200_flush_work(struct cgpu_info *be200)
{
	struct be200_info *info = be200->device_data;

	/* Will overwrite any work queued. Do this unlocked since it's just
	 * changing a single non-critical value and prevents deadlocks */
	be200->queued = 0;

	/* Signal main loop we need more work */
	cgsem_post(&info->qsem);
}

static struct api_data *be200_api_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;
	struct be200_info *info = cgpu->device_data;
	char buf[64];
	int i;
	double hwp = (cgpu->hw_errors + cgpu->diff1) ?
		     (double)(cgpu->hw_errors) / (double)(cgpu->hw_errors + cgpu->diff1) : 0;

	root = api_add_int(root, "baud", &(info->baud), false);
	root = api_add_int(root, "miner_count", &(info->miner_count),false);
	root = api_add_int(root, "asic_count", &(info->asic_count), false);

	return root;
}

static void be200_shutdown(struct thr_info *thr)
{
	struct cgpu_info *be200 = thr->cgpu;
	struct be200_info *info = be200->device_data;

	pthread_join(info->read_thr, NULL);
	pthread_join(info->write_thr, NULL);
	be200_running_reset(be200, info);
	cgsem_destroy(&info->qsem);
	mutex_destroy(&info->qlock);
	mutex_destroy(&info->lock);
	free(be200->works);
	be200->works = NULL;
}

static char *be200_set_device(struct cgpu_info *be200, char *option, char *setting, char *replybuf)
{
	int val;

	if (strcasecmp(option, "help") == 0) {
		sprintf(replybuf, "freq: range %d-%d millivolts: range %d-%d",
					BE200_MIN_FREQUENCY, BE200_MAX_FREQUENCY,
					BITBURNER_MIN_COREMV, BITBURNER_MAX_COREMV);
		return replybuf;
	}

	if (strcasecmp(option, "millivolts") == 0 || strcasecmp(option, "mv") == 0) {
		if (!is_bitburner(be200)) {
			sprintf(replybuf, "%s cannot set millivolts", be200->drv->name);
			return replybuf;
		}

		if (!setting || !*setting) {
			sprintf(replybuf, "missing millivolts setting");
			return replybuf;
		}

		val = atoi(setting);
		if (val < BITBURNER_MIN_COREMV || val > BITBURNER_MAX_COREMV) {
			sprintf(replybuf, "invalid millivolts: '%s' valid range %d-%d",
						setting, BITBURNER_MIN_COREMV, BITBURNER_MAX_COREMV);
			return replybuf;
		}

		if (bitburner_set_core_voltage(be200, val))
			return NULL;
		else {
			sprintf(replybuf, "Set millivolts failed");
			return replybuf;
		}
	}

	if (strcasecmp(option, "freq") == 0) {
		if (!setting || !*setting) {
			sprintf(replybuf, "missing freq setting");
			return replybuf;
		}

		val = atoi(setting);
		if (val < BE200_MIN_FREQUENCY || val > BE200_MAX_FREQUENCY) {
			sprintf(replybuf, "invalid freq: '%s' valid range %d-%d",
						setting, BE200_MIN_FREQUENCY, BE200_MAX_FREQUENCY);
			return replybuf;
		}

		be200_set_freq(be200, val);
		return NULL;
	}

	sprintf(replybuf, "Unknown option: %s", option);
	return replybuf;
}

struct device_drv be200_drv = {
	.drv_id = DRIVER_be200,
	.dname = "be200",
	.name = "BE200",
	.drv_detect = be200_detect,
	.thread_prepare = be200_prepare,
	.hash_work = hash_queued_work,
	.queue_full = be200_fill,
	.scanwork = be200_scanhash,
	.flush_work = be200_flush_work,
	//.get_api_stats = be200_api_stats,
	//.get_statline_before = get_be200_statline_before,
	//.set_device = be200_set_device,
	.reinit_device = be200_init,
	.thread_shutdown = be200_shutdown,
};
