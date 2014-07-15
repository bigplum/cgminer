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

void be200_create_task(struct be200_task *at,
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
	//applog(LOG_DEBUG, "%s%i: usb_write got err %d", be200->drv->name,
	//       be200->device_id, err);

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


static int be200_read_one(struct cgpu_info *be200, char *buf, size_t bufsize, int ep)
{
	size_t total = 0, readsize = bufsize;
	char readbuf[BE200_READBUF_SIZE];
	int err, amount, ofs = 2, cp;

	err = usb_read_once(be200, readbuf, readsize, &amount, ep);
	//applog(LOG_DEBUG, "%s%i: Get be200 read got err %d",
	//       be200->drv->name, be200->device_id, err);
	if (err && err != LIBUSB_ERROR_TIMEOUT)
		return err;

	memcpy(buf, readbuf, readsize);

	return amount;
}

static int be200_read(struct cgpu_info *be200, char *buf, size_t bufsize, int ep)
{
	size_t total = 0, readsize = bufsize + 2;
	char readbuf[BE200_READBUF_SIZE];
	int err, amount, ofs = 2, cp;

	err = usb_read_once(be200, readbuf, readsize, &amount, ep);
	//applog(LOG_DEBUG, "%s%i: Get be200 read got err %d",
	//       be200->drv->name, be200->device_id, err);
	if (err && err != LIBUSB_ERROR_TIMEOUT)
		return err;

	memcpy(buf, readbuf, readsize);

	return amount;
}


#define transfer(be200, request_type, bRequest, wValue, wIndex, cmd) \
		_transfer(be200, request_type, bRequest, wValue, wIndex, NULL, 0, cmd)


static void _transfer(struct cgpu_info *be200, uint8_t request_type, uint8_t bRequest, 
                    uint16_t wValue, uint16_t wIndex, uint32_t *data, int siz, enum usb_cmds cmd)
{
	int err;

	err = usb_transfer_data(be200, request_type, bRequest, wValue, wIndex, data, siz, cmd);

	applog(LOG_DEBUG, "%s: cgid %d %s got err %d",
			be200->drv->name, be200->cgminer_id,
			usb_cmdname(cmd), err);
}

void be200_reset(struct cgpu_info *be200)
{
	uint8_t cmd_char, out_char;
        int ret;
        cmd_char = C_RES;

        
        ret = be200_write(be200, (char *)&cmd_char, 1, C_BE200_INIT);

        applog(LOG_DEBUG, "BE200: Sent reset cmd: %x", cmd_char);
        
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

}


static void be200_data_mode(struct cgpu_info *be200)
{
	int err, interface;

	if (be200->usbinfo.nodev)
		return;

	interface = usb_interface(be200);

    // Set line control
    transfer(be200, CP210X_TYPE_OUT, BE200_CP210X_SET_LINE_CTL, BE200_CP210X_DATA_LINE_CTL_VALUE,
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

}


static void be200_cmd_mode(struct cgpu_info *be200)
{
	int err, interface;

	if (be200->usbinfo.nodev)
		return;

	interface = usb_interface(be200);

    // Set line control
    transfer(be200, CP210X_TYPE_OUT, BE200_CP210X_SET_LINE_CTL, BE200_CP210X_CMD_LINE_CTL_VALUE,
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
        char buf[1024];

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

	be200_initialise(be200);
	be200_cmd_mode(be200);

    be200_reset(be200);

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

            cgsleep_ms(3000);
            ret = be200_read(be200, (char *)&out_char, 1, C_BE200_READ);
            
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
        applog(LOG_DEBUG, "BE200 send: %x, get %d", cmd_char, ret);
        hexdump((uint8_t *)buf, ret);
  
  applog(LOG_DEBUG, "======ok=====");

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

static bool be200_prepare(struct thr_info *thr)
{
	struct cgpu_info *be200 = thr->cgpu;
	struct be200_info *info = be200->device_data;
	int array_size = BE200_ARRAY_SIZE;
	//void *(*write_thread_fn)(void *) = be200_send_tasks;

	free(be200->works);
	be200->works = calloc(info->miner_count * sizeof(struct work *),
			       array_size);
	if (!be200->works)
		quit(1, "Failed to calloc be200 works in be200_prepare");

	info->thr = thr;
    info->first = true;

	mutex_init(&info->lock);
	mutex_init(&info->qlock);
	cgsem_init(&info->qsem);
    /*

	if (pthread_create(&info->read_thr, NULL, be200_get_results, (void *)be200))
		quit(1, "Failed to create be200 read_thr");
	if (pthread_create(&info->write_thr, NULL, write_thread_fn, (void *)be200))
		quit(1, "Failed to create be200 write_thr");
*/
	be200_init(be200);

	return true;
}


static int be200_send_task(const struct be200_task *at, struct cgpu_info *be200,
			    struct be200_info *info)

{
	uint8_t buf[BE200_WRITE_SIZE], cmd_char, out_char;
	int delay, ret, i, ep = C_BE200_TASK;
	uint32_t nonce_range;
	size_t nr_len;


	unsigned char target[32];
        struct pool *pool;

        

        buf[0] = 0x61;
        buf[1] = 0x2b;
        buf[2] = 0x40 + opt_set_be200_freq/10 -1;    //320m
        ret = be200_write(be200, (char *)buf, 3, ep);
        applog(LOG_DEBUG, "BE200: set diff and freq:");
        hexdump(buf, 3);
        
        cmd_char = C_JOB + info->board_id;
        
        ret = be200_write(be200, (char *)&cmd_char, 1, ep);

        applog(LOG_DEBUG, "BE200: Sent task cmd: %x", cmd_char);

        
        be200_data_mode(be200);

    nr_len = BE200_WRITE_SIZE;
	memcpy(buf, at, BE200_WRITE_SIZE);

	delay = nr_len * 10 * 1000000;
	//delay = delay / info->baud;
	delay += 4000;

	if (opt_debug) {
		applog(LOG_DEBUG, "BE200: Sent task data(%u):", (unsigned int)nr_len);
		hexdump(buf, nr_len);
	}
    

	/* Sleep from the last time we sent data */
	//cgsleep_us_r(&info->cgsent, info->send_delay);

	//cgsleep_prepare_r(&info->cgsent);
	ret = be200_write(be200, (char *)buf, nr_len, ep);

	applog(LOG_DEBUG, "BE200: Sent task: Buffer delay: %dus", info->send_delay);
	info->send_delay = delay;


    //cgsleep_ms(500);
    ret = be200_read_one(be200, (char *)&out_char, 1, ep);
    
    applog(LOG_DEBUG, "====BE200 send task return: %x", out_char);

    be200_cmd_mode(be200);

	return ret;
}


static int64_t be200_scanhash(struct thr_info *thr)
{
	struct cgpu_info *be200 = thr->cgpu;
	struct be200_info *info = be200->device_data;
	const int miner_count = info->miner_count;
	int64_t hash_count = 0, ms_timeout;

	struct work *work;
        struct be200_task at;
        int ret;
        uint8_t cmd_char, out_char;
        uint8_t buf[128];
        bool bret;
        uint32_t nonce, ntime, test_nonce;

	if (thr->work_restart || thr->work_update ||
	    info->first) {
		//info->new_stratum = true;
		applog(LOG_DEBUG, "BE200: New stratum: restart: %d, update: %d, first: %d",
		       thr->work_restart, thr->work_update, info->first);
		thr->work_update = false;
		thr->work_restart = false;
		if (unlikely(info->first))
			info->first = false;

            work = get_work(thr, thr->id);
            be200->works[0] = work;
            be200_create_task(&at, work);
            ret = be200_send_task(&at, be200, info);

            if (unlikely(be200->usbinfo.nodev)) {
                applog(LOG_ERR, "%s%d: Device disappeared, shutting down thread",
                   be200->drv->name, be200->device_id);
                hash_count = -1;
            }
       }

    
    cmd_char = C_ASK + info->board_id;
    ret = be200_write(be200, (char *)&cmd_char, 1, C_BE200_INIT);
    
    //applog(LOG_DEBUG, "BE200 getresult cmd: %x", cmd_char);
    
    //cgsleep_ms(500);
    ret = be200_read_one(be200, (char *)&out_char, 1, C_BE200_READ);
    
    //applog(LOG_DEBUG, "BE200 getresult %x, return %d, rest %d", out_char, ret, be200->usbdev->bufamt);

    int nonce_test_array[8] = {-3, -2, -1, 0, 2, 3, 4, 5};
    int i = 0;

    if (out_char == A_YES) {


        // returns midstate[32+4], ntime[4], ndiff[4], exnonc2[4], nonce[4], mj_ID[1], chipID[1] 
	if (be200->usbdev->bufamt == 54) {
		memcpy(buf, be200->usbdev->buffer, 54);
		be200->usbdev->bufamt = 0;
        } else {
                ret = be200_read(be200, (char *)buf, 54, C_BE200_READ);
        }
        applog(LOG_DEBUG, "BE200: Get Result data(%u):", (unsigned int)54);
        hexdump(buf, 54);

        memcpy(&nonce, buf + 48, 4);
        memcpy(&ntime, buf + 36, 4);
        nonce = htole32(nonce);
        ntime = htobe32(ntime);

        applog(LOG_DEBUG, "==== Found! (%08x) (%08x)",
        	        nonce, ntime);
        hexdump((uint8_t *)be200->works[0] + 128, 96);

        set_work_ntime(be200->works[0], ntime);
        test_nonce = nonce + 1;
        bret = submit_nonce(thr, be200->works[0], test_nonce);

        i = 0;
        while (!bret && i < 8) {
            test_nonce = nonce + nonce_test_array[i];
            i++;
            applog(LOG_DEBUG, "BE200 test nonce (%08x) (%08x)",
                            test_nonce, ntime);
            bret = submit_nonce(thr, be200->works[0], test_nonce);
        }
        if (!bret) {
            hash_count = 0;
        } else {
            hash_count = 0xffffffff * test_nonce;
        }
    }else if (out_char == A_WAL) {
        info->first = true;
    }

    /* This hashmeter is just a utility counter based on returned shares */
    return hash_count;
}


static void be200_shutdown(struct thr_info *thr)
{
	struct cgpu_info *be200 = thr->cgpu;

    applog(LOG_DEBUG, "BE200 shutdown ..............................");

	free(be200->works);
	be200->works = NULL;
}


struct device_drv be200_drv = {
	.drv_id = DRIVER_be200,
	.dname = "be200",
	.name = "BE200",
	.drv_detect = be200_detect,
	.thread_prepare = be200_prepare,
	.hash_work = hash_driver_work,
	//.queue_full = be200_fill,
	.scanwork = be200_scanhash,
	.reinit_device = be200_init,
	.thread_shutdown = be200_shutdown,
};
