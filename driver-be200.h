/*
 * Copyright 2013 Avalon project
 * Copyright 2013-2014 Con Kolivas <kernel@kolivas.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef BE200_H
#define BE200_H

#ifdef USE_BE200

#include "util.h"
#define BE200_MINER_THREADS 1
#define BE200_READBUF_SIZE 1024

#define BE200_FAN_FACTOR 120
#define BE200_PWM_MAX 0xA0
#define BE200_DEFAULT_FAN_MIN 20
#define BE200_DEFAULT_FAN_MAX 100
#define BE200_DEFAULT_FAN_MAX_PWM 0xA0 /* 100% */
#define BE200_DEFAULT_FAN_MIN_PWM 0x20 /*  20% */

#define BE200_TEMP_TARGET 50
#define BE200_TEMP_HYSTERESIS 3
#define BE200_TEMP_OVERHEAT 60

#define BE200_DEFAULT_TIMEOUT 0x2D
#define BE200_MIN_FREQUENCY 160
#define BE200_MAX_FREQUENCY 360
#define BE200_DEFAULT_FREQUENCY 320
#define BE200_MAX_MINER_NUM 32
#define BE200_MAX_ASIC_NUM 24

// modes of C_CLK
#define M_OFF	0xff
#define M_ALCK	(0 << 5)	// sets clock for all chips
#define M_LCLK	(1 << 5)	// sets clock for local selected chip
#define M_LRST	(2 << 5)	// reset only the selectd by C_CLK chip

// commands global for all boards
#define C_RES	(0 << 5)	// resets all the mega88s on all boards, returns silence
#define C_LPO	(1 << 5)	// LongPoll - stop the jobs, clear the FIFO pojnters, returns silence, the BoardID contains future/10 - 1 value, eg v=2 -> fu=10*(2+1) = 30 seconds
#define C_GCK	(2 << 5)	// global clock for all boards, on the BoardID place & 0x0f
#define C_DIF	(3 << 5)	// the BoardID replacedby last LSB 2 bits the difficulty

// commands board specified ones

#define C_JOB	(4 << 5)	//80 followed by WL[44] + exnc2[4] + MJOB_IDx[1] in 8N1, returns 0x58= confirmation that the Job has been gotten, good for sync also
#define C_ASK	(5 << 5)	//A0 see below
#define C_TRS	(6 << 5)	//C0 returns 32 bytes status of the core test + 32 bytes clocks + 1 byte = g_dif + (InFuture/10)-1)[1]  ... total 66 bytes
#define C_CLK	(7 << 5)	//E0 resets mega88 on the selected board, returns silence

// answers on C_ASK:b
#define A_WAL	0x56	// ready to take a new master job :)
#define A_NO	0xa6	// nothing, means the chips are working/busy
#define A_YES	0x5A	// there is a nonce in the FIFO
#define A_STR	0x6c	// send a string or data followed by termination zero to the host, the host will print it.
// A_YES is followed by ... see below in the function AnswerIT();
// ------------------------


struct be200_task {
    uint8_t midstate[32];
    uint8_t mshit[4];
    uint8_t ntime[4];
    uint8_t ndiff[4];
    uint8_t exnc2[4];
    uint8_t mj_ID;
}; //__attribute__((packed, aligned(4)));

struct be200_result {
    uint8_t midstate[32];
    uint32_t diff;
    uint32_t nonce;
    uint32_t job_id;

    uint8_t chip_num;
}; //__attribute__((packed, aligned(4)));

struct miner_info {
    int id;
    int freq;
    int asic_count;
    uint64_t asic_hash_done[BE200_MAX_ASIC_NUM];
};

struct be200_info {

    bool first;
    int device_diff;

    int miner_count;
    struct miner_info miner[BE200_MAX_MINER_NUM];


    struct thr_info *thr;
    pthread_t read_thr;
    pthread_t write_thr;
    pthread_mutex_t lock;
    pthread_mutex_t qlock;
    cgsem_t qsem;
    cgtimer_t cgsent;

};


#define BE200_WRITE_SIZE (sizeof(struct be200_task))
#define BE200_READ_SIZE (sizeof(struct be200_result))
#define BE200_ARRAY_SIZE 3

#define BE200_GETS_ERROR -1
#define BE200_GETS_OK 0

#define BE200_SEND_ERROR -1
#define BE200_SEND_OK 0

extern struct be200_info **be200_info;
extern int opt_be200_temp;
extern int opt_be200_overheat;
extern int opt_be200_fan_min;
extern int opt_be200_fan_max;
extern int opt_be200_freq_min;
extern int opt_be200_freq_max;
extern bool opt_be200_auto;
extern int opt_bitburner_core_voltage;
extern int opt_bitburner_fury_core_voltage;

#endif /* USE_BE200 */
#endif	/* BE200_H */
