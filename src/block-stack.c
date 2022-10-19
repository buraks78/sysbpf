//
//     SysBPF is a system analysis tool built on the BPF Compiler Collection (BCC) toolkit.
//     Copyright (C) 2022 Burak Seydioglu
//
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

#include <uapi/linux/ptrace.h>

#include <linux/sched.h>

# define TRACK_LOG_LEVEL_ERROR  40
# define TRACK_LOG_LEVEL_WARN   30
# define TRACK_LOG_LEVEL_INFO   20
# define TRACK_LOG_LEVEL_DEBUG  10
# define TRACK_LOG_LEVEL_NOTSET 0

# define TRACK_STACK_MAX 8

# define TRACK_TYPE_NONE         (1U << 0)
# define TRACK_TYPE_READ         (1U << 1)
# define TRACK_TYPE_AHEAD        (1U << 2)
# define TRACK_TYPE_WRITE        (1U << 3)
# define TRACK_TYPE_DISCARD      (1U << 4)
# define TRACK_TYPE_FUA          (1U << 5)
# define TRACK_TYPE_SYNC         (1U << 6)
# define TRACK_TYPE_META         (1U << 7)
# define TRACK_TYPE_SUBMISSION   (1U << 20)
# define TRACK_TYPE_COMPLETION   (1U << 21)
# define TRACK_TYPE_FS           (1U << 22)
# define TRACK_TYPE_DEVICE       (1U << 23)
# define TRACK_TYPE_QUEUE        (1U << 24)
# define TRACK_TYPE_DRIVER       (1U << 25)
# define TRACK_TYPE_MERGE        (1U << 27)
# define TRACK_TYPE_SPLIT        (1U << 28)

# define TRACK_STAT_R_CT         (1U << 0)
# define TRACK_STAT_R_ST         (1U << 1)
# define TRACK_STAT_R_SZ         (1U << 2)
# define TRACK_STAT_RA_CT        (1U << 3)
# define TRACK_STAT_RA_ST        (1U << 4)
# define TRACK_STAT_RA_SZ        (1U << 5)
# define TRACK_STAT_RM_CT        (1U << 6)
# define TRACK_STAT_RM_ST        (1U << 7)
# define TRACK_STAT_RM_SZ        (1U << 8)
# define TRACK_STAT_RS_CT        (1U << 9)
# define TRACK_STAT_RS_ST        (1U << 10)
# define TRACK_STAT_RS_SZ        (1U << 11)
# define TRACK_STAT_W_CT         (1U << 12)
# define TRACK_STAT_W_ST         (1U << 13)
# define TRACK_STAT_W_SZ         (1U << 14)
# define TRACK_STAT_WM_CT        (1U << 15)
# define TRACK_STAT_WM_ST        (1U << 16)
# define TRACK_STAT_WM_SZ        (1U << 17)
# define TRACK_STAT_WS_CT        (1U << 18)
# define TRACK_STAT_WS_ST        (1U << 19)
# define TRACK_STAT_WS_SZ        (1U << 20)
# define TRACK_STAT_D_CT         (1U << 21)
# define TRACK_STAT_D_ST         (1U << 22)
# define TRACK_STAT_D_SZ         (1U << 23)
# define TRACK_STAT_DM_CT        (1U << 24)
# define TRACK_STAT_DM_ST        (1U << 25)
# define TRACK_STAT_DM_SZ        (1U << 26)
# define TRACK_STAT_DS_CT        (1U << 27)
# define TRACK_STAT_DS_ST        (1U << 28)
# define TRACK_STAT_DS_SZ        (1U << 29)

BPF_ARRAY(configs, u32, 2);
BPF_HASH(pids, u32, u32, 256);
BPF_HASH(dm_devices, u32, u32, 256);
BPF_HASH(partition_holders, u32, u32, 256);
BPF_HASH(partition_overrides, u64, u32, 256);

static int match_log_level(u32 log_level) {

    u32 config_key = 0;
    u32 *config_log_level = configs.lookup(&config_key);

    if (config_log_level) {
        if (log_level < *config_log_level) {
            return 0;
        }
    }

    return 1;

}

static int filter_pid() {

    u32 config_key = 1;
    u32 *config_pid = configs.lookup(&config_key);

    if (config_pid && *config_pid) {
        return 1;
    }

    return 0;
}

static int match_pid() {

    u32 pid = (bpf_get_current_pid_tgid() >> 32);
    u32 *matched_pid = pids.lookup(&pid);

    if (matched_pid) {
        return 1;
    }

    return 0;
}

static u32 get_type(char *rwbs) {

    u32 type = TRACK_TYPE_NONE;

    char s[8];
    bpf_probe_read_kernel_str(s, 8, rwbs);

    for (int i = 0; i < 8; ++i) {

        char c = s[i];

        if (c == '\0') {
            break;
        }

        if (i == 0 && c == 'F') {
            // Flush requests are broken into separate requests.
            // Flush request will be nr_sectors = 0 and ignored during size check.
            // To capture the other submission we will skip the flush flag and process the remaining flags.
            continue;
        }

        if (c == 'R') {
            type |= TRACK_TYPE_READ;
            continue;
        } else if (c == 'A') {
            type |= TRACK_TYPE_AHEAD;
            continue;
        } else if (c == 'W') {
            type |= TRACK_TYPE_WRITE;
            continue;
        } else if (c == 'D') {
            type |= TRACK_TYPE_DISCARD;
            continue;
//        } else if (c == 'F') {
            // Don't track fua flags since they get dropped at the queue layer and break type standard required for lookups
            // Also:
            // bpf: Argument list too long. Program  too large (1067 insns), at most 4096 insns
            // type |= TRACK_TYPE_FUA;
        } else if (c == 'S') {
            type |= TRACK_TYPE_SYNC;
            continue;
        } else if (c == 'M') {
            type |= TRACK_TYPE_META;
            continue;
        }

    }

    return type;

}

static int match_type(u32 type) {

    if (type == TRACK_TYPE_NONE) {
        return 0;
    }

    return 1;

}

struct track_key {
    u32 dev;
    u64 sector;
    u32 type;
};

typedef struct track_key track_key_t;

struct track_item {
    u32 dev;
    u64 sector;
};

typedef struct track_item track_item_t;

struct track_io {
    u32 dev;
    u64 sector;
    u32 type;
    u32 nr_sector;
    u64 start_ns;
    u32 old_dev;
    u64 old_sector;
    u32 old_nr_sector;
    u64 old_start_ns;
    u32 top;
    track_item_t stack[TRACK_STACK_MAX];
};

typedef struct track_io track_io_t;

struct track_bmrq_key {
    u32 dev;
    u64 end_sector;
    u32 type;
};

typedef struct track_bmrq_key track_bmrq_key_t;

struct track_bmrq_val {
    u64 sector;
    u64 start_ns;
};

typedef struct track_bmrq_val track_bmrq_val_t;

struct track_split_key {
    u32 dev;
    u64 sector;
    u32 type;
};

typedef struct track_split_key track_split_key_t;

struct track_split_val {
    u32 remaining_nr_sector;
    u32 split_nr_sector;
    u64 start_ns;
    u32 top;
    track_item_t stack[TRACK_STACK_MAX];
};

typedef struct track_split_val track_split_val_t;

struct track_stat {
    u32 dev;
    u32 type;
    u64 st; // service time
    u32 sz; // size in nr_sectors
};

typedef struct track_stat track_stat_t;

struct track_log {
    u32 log_level;
    u32 cpu;
    u64 timestamp;
    char message[32];
    u32 dev;
    u64 sector;
    u32 nr_sector;
    char rwbs[8];
    u32 type;
    u32 old_dev;
    u64 old_sector;
    u32 top;
};

typedef struct track_log track_log_t;

BPF_RINGBUF_OUTPUT(logs, 8192);
BPF_HASH(submissions, track_key_t, track_io_t, 2000000);
BPF_HASH(completions, track_key_t, track_io_t, 2000000);
BPF_HASH(bmrqs, track_bmrq_key_t, track_bmrq_val_t, 2000000);
BPF_HASH(splits, track_split_key_t, track_split_val_t, 2000000);
BPF_HASH(submission_stats_fs, u64, u64, 256);
BPF_HASH(submission_stats_dev, u64, u64, 256);
BPF_HASH(submission_stats_q, u64, u64, 256);
BPF_HASH(submission_stats_drv, u64, u64, 256);
BPF_HASH(completion_stats_fs, u64, u64, 256);
BPF_HASH(completion_stats_dev, u64, u64, 256);
BPF_HASH(completion_stats_q, u64, u64, 256);
BPF_HASH(completion_stats_drv, u64, u64, 256);

static void atomic_increment(u64 key, u64 val, track_stat_t *s) {
    if ((s->type & TRACK_TYPE_FS) == TRACK_TYPE_FS) {
        if ((s->type & TRACK_TYPE_COMPLETION) == TRACK_TYPE_COMPLETION) {
            completion_stats_fs.atomic_increment(key, val);
        } else {
            submission_stats_fs.atomic_increment(key, val);
        }
    } else if ((s->type & TRACK_TYPE_DEVICE) == TRACK_TYPE_DEVICE) {
        if ((s->type & TRACK_TYPE_COMPLETION) == TRACK_TYPE_COMPLETION) {
            completion_stats_dev.atomic_increment(key, val);
        } else {
            submission_stats_dev.atomic_increment(key, val);
        }
    } else if ((s->type & TRACK_TYPE_QUEUE) == TRACK_TYPE_QUEUE) {
        if ((s->type & TRACK_TYPE_COMPLETION) == TRACK_TYPE_COMPLETION) {
            completion_stats_q.atomic_increment(key, val);
        } else {
            submission_stats_q.atomic_increment(key, val);
        }
    } else if ((s->type & TRACK_TYPE_DRIVER) == TRACK_TYPE_DRIVER) {
        if ((s->type & TRACK_TYPE_COMPLETION) == TRACK_TYPE_COMPLETION) {
            completion_stats_drv.atomic_increment(key, val);
        } else {
            submission_stats_drv.atomic_increment(key, val);
        }
    }
}

static void push_stat(track_stat_t *s) {

    u64 key = ((u64) s->dev << 32);

    if ((s->type & TRACK_TYPE_READ) == TRACK_TYPE_READ) {

        if((s->type & TRACK_TYPE_AHEAD) == TRACK_TYPE_AHEAD) {

            u64 key_ra_ct = key | TRACK_STAT_RA_CT;
            u64 key_ra_st = key | TRACK_STAT_RA_ST;
            u64 key_ra_sz = key | TRACK_STAT_RA_SZ;

            atomic_increment(key_ra_ct, 1, s);
            atomic_increment(key_ra_st, s->st, s);
            atomic_increment(key_ra_sz, s->sz, s);

        } else if ((s->type & TRACK_TYPE_MERGE) == TRACK_TYPE_MERGE) {

            u64 key_rm_ct = key | TRACK_STAT_RM_CT;
            u64 key_rm_st = key | TRACK_STAT_RM_ST;
            u64 key_rm_sz = key | TRACK_STAT_RM_SZ;

            atomic_increment(key_rm_ct, 1, s);
            atomic_increment(key_rm_st, s->st, s);
            atomic_increment(key_rm_sz, s->sz, s);

        } else if ((s->type & TRACK_TYPE_SPLIT) == TRACK_TYPE_SPLIT) {

            u64 key_rs_ct = key | TRACK_STAT_RS_CT;
            u64 key_rs_st = key | TRACK_STAT_RS_ST;
            u64 key_rs_sz = key | TRACK_STAT_RS_SZ;

            atomic_increment(key_rs_ct, 1, s);
            atomic_increment(key_rs_st, s->st, s);
            atomic_increment(key_rs_sz, s->sz, s);

        } else {

            u64 key_r_ct = key | TRACK_STAT_R_CT;
            u64 key_r_st = key | TRACK_STAT_R_ST;
            u64 key_r_sz = key | TRACK_STAT_R_SZ;

            atomic_increment(key_r_ct, 1, s);
            atomic_increment(key_r_st, s->st, s);
            atomic_increment(key_r_sz, s->sz, s);

        }

    } else if ((s->type & TRACK_TYPE_WRITE) == TRACK_TYPE_WRITE) {

        if ((s->type & TRACK_TYPE_MERGE) == TRACK_TYPE_MERGE) {

            u64 key_wm_ct = key | TRACK_STAT_WM_CT;
            u64 key_wm_st = key | TRACK_STAT_WM_ST;
            u64 key_wm_sz = key | TRACK_STAT_WM_SZ;
            
            atomic_increment(key_wm_ct, 1, s);
            atomic_increment(key_wm_st, s->st, s);
            atomic_increment(key_wm_sz, s->sz, s);

        } else if ((s->type & TRACK_TYPE_SPLIT) == TRACK_TYPE_SPLIT) {

            u64 key_ws_ct = key | TRACK_STAT_WS_CT;
            u64 key_ws_st = key | TRACK_STAT_WS_ST;
            u64 key_ws_sz = key | TRACK_STAT_WS_SZ;

            atomic_increment(key_ws_ct, 1, s);
            atomic_increment(key_ws_st, s->st, s);
            atomic_increment(key_ws_sz, s->sz, s);

        } else {

            u64 key_w_ct = key | TRACK_STAT_W_CT;
            u64 key_w_st = key | TRACK_STAT_W_ST;
            u64 key_w_sz = key | TRACK_STAT_W_SZ;

            atomic_increment(key_w_ct, 1, s);
            atomic_increment(key_w_st, s->st, s);
            atomic_increment(key_w_sz, s->sz, s);

        }

    } else if ((s->type & TRACK_TYPE_DISCARD) == TRACK_TYPE_DISCARD) {

        if ((s->type & TRACK_TYPE_MERGE) == TRACK_TYPE_MERGE) {

            u64 key_dm_ct = key | TRACK_STAT_DM_CT;
            u64 key_dm_st = key | TRACK_STAT_DM_ST;
            u64 key_dm_sz = key | TRACK_STAT_DM_SZ;
            
            atomic_increment(key_dm_ct, 1, s);
            atomic_increment(key_dm_st, s->st, s);
            atomic_increment(key_dm_sz, s->sz, s);

        } else if ((s->type & TRACK_TYPE_SPLIT) == TRACK_TYPE_SPLIT) {

            u64 key_ds_ct = key | TRACK_STAT_DS_CT;
            u64 key_ds_st = key | TRACK_STAT_DS_ST;
            u64 key_ds_sz = key | TRACK_STAT_DS_SZ;

            atomic_increment(key_ds_ct, 1, s);
            atomic_increment(key_ds_st, s->st, s);
            atomic_increment(key_ds_sz, s->sz, s);

        } else {

            u64 key_d_ct = key | TRACK_STAT_D_CT;
            u64 key_d_st = key | TRACK_STAT_D_ST;
            u64 key_d_sz = key | TRACK_STAT_D_SZ;

            atomic_increment(key_d_ct, 1, s);
            atomic_increment(key_d_st, s->st, s);
            atomic_increment(key_d_sz, s->sz, s);

        }

    }

}


static void log(u32 log_level, char message[32], u32 dev, u64 sector, u32 nr_sector, char rwbs[8], u32 old_dev, u64 old_sector, u32 top) {

    if (!match_log_level(log_level)) {
        return;
    }

    track_log_t d = {};
    d.log_level = log_level;
    d.cpu = bpf_get_smp_processor_id();
    d.timestamp = bpf_ktime_get_ns();
    d.dev = dev;
    d.sector = sector;
    d.nr_sector = nr_sector;
    strncpy(d.message, message, (sizeof(char) * 32));
    bpf_probe_read_kernel_str(&d.rwbs, 8, rwbs);
    d.type = get_type(d.rwbs);
    d.old_dev = old_dev;
    d.old_sector = old_sector;
    d.top = top;
    logs.ringbuf_output(&d, sizeof(d), 0);

}

static void log_debug(char message[32], u32 dev, u64 sector, u32 nr_sector, char rwbs[8], u32 old_dev, u64 old_sector, u32 top) {
    log(TRACK_LOG_LEVEL_DEBUG, message, dev, sector, nr_sector, rwbs, old_dev, old_sector, top);
}

static void log_info(char message[32], u32 dev, u64 sector, u32 nr_sector, char rwbs[8], u32 old_dev, u64 old_sector, u32 top) {
    log(TRACK_LOG_LEVEL_INFO, message, dev, sector, nr_sector, rwbs, old_dev, old_sector, top);
}

static void log_warn(char message[32], u32 dev, u64 sector, u32 nr_sector, char rwbs[8], u32 old_dev, u64 old_sector, u32 top) {
    log(TRACK_LOG_LEVEL_WARN, message, dev, sector, nr_sector, rwbs, old_dev, old_sector, top);
}

static void log_error(char message[32], u32 dev, u64 sector, u32 nr_sector, char rwbs[8], u32 old_dev, u64 old_sector, u32 top) {
    log(TRACK_LOG_LEVEL_ERROR, message, dev, sector, nr_sector, rwbs, old_dev, old_sector, top);
}

//
// Tracing implementation
//

struct block_bio_queue {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    char rwbs[8];
//    char comm[TASK_COMM_LEN];
};

typedef struct block_bio_queue block_bio_queue_t;
typedef struct block_bio_queue block_bio_frontmerge_t;
typedef struct block_bio_queue block_bio_backmerge_t;
typedef struct block_bio_queue block_bio_bounce_t;

struct block_bio_remap {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    u32 old_dev;
    u64 old_sector;
    char rwbs[8];
};

typedef struct block_bio_remap block_bio_remap_t;

struct block_bio_complete {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    int error;
    char rwbs[8];
};

typedef struct block_bio_complete block_bio_complete_t;

struct block_split {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u64 new_sector;
    char rwbs[8];
    // char comm[TASK_COMM_LEN];
};

typedef struct block_split block_split_t;

struct block_getrq {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    char rwbs[8];
    // char comm[TASK_COMM_LEN];
    //    __data_loc char[]; // for requeue
};

typedef struct block_getrq block_getrq_t;
typedef struct block_getrq block_rq_requeue_t;

struct block_rq_insert {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    u32 bytes;
    char rwbs[8];
    char comm[TASK_COMM_LEN];
//    __data_loc char[];
};

typedef struct block_rq_insert block_rq_insert_t;
typedef struct block_rq_insert block_rq_issue_t;
typedef struct block_rq_insert block_rq_merge_t;

struct block_rq_complete {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    int error;
    char rwbs[8];
//    __data_loc char[];
};

typedef struct block_rq_complete block_rq_complete_t;
typedef struct block_rq_complete block_rq_error_t;

struct block_rq_remap {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    u32 old_dev;
    u64 old_sector;
    u32 nr_bios;
    char rwbs[8];
};

typedef struct block_rq_remap block_rq_remap_t;

struct block_buffer {
    u64 __unused__;
    u32 dev;
    u64 sector;
    u64 size;
};

typedef struct block_buffer block_dirty_buffer_t;
typedef struct block_buffer block_touch_buffer_t;

int trace_block_bio_queue(block_bio_queue_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("bio_queue: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t key = {};
    key.dev = args->dev;
    key.sector = args->sector;
    key.type = type;
    key.type |= TRACK_TYPE_DEVICE;

    track_io_t *io = submissions.lookup(&key);

    if (!io) {

        if (filter_pid() && !match_pid()) {
            return 0;
        }

        // no io found means no remap happened before this queue action

        track_io_t io = {};
        io.dev = args->dev;
        io.sector = args->sector;
        io.type = type;
        io.nr_sector = args->nr_sector;
        io.start_ns = bpf_ktime_get_ns();
        io.top = 0;

        submissions.update(&key, &io);

        // when backmerge happens before getrq

        track_bmrq_key_t bmrq_key = {};
        bmrq_key.dev = args->dev;
        bmrq_key.end_sector = args->sector + (u64) args->nr_sector;
        bmrq_key.type = type;

        track_bmrq_val_t bmrq_val = {};
        bmrq_val.sector = args->sector;
        bmrq_val.start_ns = bpf_ktime_get_ns();

        bmrqs.insert(&bmrq_key, &bmrq_val);

        log_debug("bio_queue: new submission", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

        return 1;
    }

    // if there is an io already, it was queued during remap
    // update start time with the correct timestamp
    io->start_ns = bpf_ktime_get_ns();

    if (io->old_dev && io->old_sector && io->old_nr_sector && io->old_start_ns) {

        track_stat_t s = {};
        s.dev = io->old_dev;
        s.type = type;
        s.type |= TRACK_TYPE_DEVICE;
        s.st = bpf_ktime_get_ns() - io->old_start_ns;
        s.sz = io->old_nr_sector;
        push_stat(&s);

        io->old_dev = 0;
        io->old_sector = 0;
        io->old_nr_sector = 0;
        io->old_start_ns = 0;

    }

    return 1;

}

// second remap operation does not happen for flush requests (rwbs starting with F). In addition, rwbs changes on completion as well.

int trace_block_bio_remap(block_bio_remap_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("bio_remap: enter", args->dev, args->sector, args->nr_sector, args->rwbs, args->old_dev, args->old_sector, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->old_dev;
    prev_key.sector = args->old_sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_DEVICE;

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {
        if (filter_pid()) {
            return 0;
        }
        log_error("bio_remap: no prev_io", args->old_dev, args->old_sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;
    }

    // Here is the problem when partitions are concerned. Note the target device in the second line.
    //
    //     jbd2/dm-3-8  5767 [014] 50143.817445:      block:block_bio_queue: 253,0 WS 449129680 + 8 [jbd2/dm-3-8]
    // dmcrypt_write/2  5141 [012] 50143.817501:      block:block_bio_remap: 259,0 WS 449133776 + 8 <- (253,0) 449129680
    // dmcrypt_write/2  5141 [012] 50143.817501:      block:block_bio_remap: 259,0 WS 451642576 + 8 <- (259,3) 449133776
    // dmcrypt_write/2  5141 [012] 50143.817502:      block:block_bio_queue: 259,0 WS 451642576 + 8 [dmcrypt_write/2]

    u32 dev = args->dev;
    u32 old_dev = args->old_dev;

    u64 key = (((u64) old_dev) << 32) | dev;
    u32 *partition_override = partition_overrides.lookup(&key);

    if (partition_override) {
//        log_debug("bio_remap: partition override", *partition_override, args->sector, args->nr_sector, args->rwbs, args->old_dev, args->old_sector, 0);
    }

    // Register new io for new device.

    track_key_t next_key = {};
    next_key.dev = args->dev;
    if (partition_override) {
        next_key.dev = *partition_override;
    }
    next_key.sector = args->sector;
    next_key.type = type;
    next_key.type |= TRACK_TYPE_DEVICE;

    track_io_t next_io = {};
    next_io.dev = args->dev;
    if (partition_override) {
        next_io.dev = *partition_override;
    }
    next_io.sector = args->sector;
    next_io.type = type;
    next_io.nr_sector = args->nr_sector;
    // this value is updated when io is sent to the next component
    next_io.start_ns = bpf_ktime_get_ns();
    // carry over previous io information so trace_block_bio_queue can submit accurate stats
    next_io.old_dev = prev_io->dev;
    next_io.old_sector = prev_io->sector;
    next_io.old_nr_sector = args->nr_sector;
    next_io.old_start_ns = prev_io->start_ns;

    // In the case of a partition override, there will not be a queue call until after the second remap.
    // This block matches the first remap operation when a partition override is performed.
    if (partition_override) {

        track_stat_t s = {};
        s.dev = prev_io->dev;
        s.type = type;
        s.type |= TRACK_TYPE_DEVICE;
        s.st = bpf_ktime_get_ns() - prev_io->start_ns;
        s.sz = args->nr_sector; // use reported value for accuracy
        push_stat(&s);

    }

    next_io.top = prev_io->top;
    memcpy(next_io.stack, prev_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

    track_item_t item = {};
    item.dev = prev_io->dev;
    item.sector = prev_io->sector;

    u32 *partition_holder = partition_holders.lookup(&prev_io->dev);

    if (!partition_holder) {

        if (prev_io->top >= TRACK_STACK_MAX - 1) {
//            log_error("bio_remap: stack bounds check", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, prev_io->top);
            submissions.delete(&prev_key);
            return 0;
        }

        next_io.top = prev_io->top + 1;
        next_io.stack[next_io.top] = item;

//        log_debug("bio_remap: push stack item", item.dev, item.sector, 0, 0, 0, 0, next_io.top);

    }

    submissions.update(&next_key, &next_io);
    submissions.delete(&prev_key);

    // If args->nr_sector is smaller, that signals an upcoming dm split.
    // This block matches the first remap + split operation
    if (args->nr_sector < prev_io->nr_sector) {

        // all this is needed due to stack limitations, loop limitations, split format and behavior.

        track_split_key_t split_key = {};
        split_key.dev = prev_io->dev;
        split_key.sector = prev_io->sector + (u64) args->nr_sector;
        split_key.type = type;

        track_split_val_t split_val = {};
        split_val.remaining_nr_sector = prev_io->nr_sector - args->nr_sector;
        split_val.split_nr_sector = args->nr_sector;
        split_val.start_ns = bpf_ktime_get_ns();

        split_val.top = prev_io->top;
        memcpy(split_val.stack, prev_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

        splits.update(&split_key, &split_val);

        track_stat_t s = {};
        s.dev = prev_io->dev;
        s.type = type;
        s.type |= TRACK_TYPE_DEVICE;
        s.type |= TRACK_TYPE_SPLIT;
        s.st = bpf_ktime_get_ns() - prev_io->start_ns;
        s.sz = args->nr_sector; // use reported value for accuracy
        push_stat(&s);

    }

    // when backmerge happens before getrq

    track_bmrq_key_t bmrq_prev_key = {};
    bmrq_prev_key.dev = prev_io->dev;
    bmrq_prev_key.end_sector = prev_io->sector + (u64) args->nr_sector;
    bmrq_prev_key.type = type;
    bmrqs.delete(&bmrq_prev_key);

    track_bmrq_key_t bmrq_next_key = {};
    bmrq_next_key.dev = next_io.dev;
    bmrq_next_key.end_sector = next_io.sector + (u64) args->nr_sector;
    bmrq_next_key.type = type;

    track_bmrq_val_t bmrq_next_val = {};
    bmrq_next_val.sector = next_io.sector;
    bmrq_next_val.start_ns = bpf_ktime_get_ns();

    bmrqs.insert(&bmrq_next_key, &bmrq_next_val);

    return 1;
}

int trace_block_bio_frontmerge(block_bio_frontmerge_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("bio_frontmerge: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_DEVICE;

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {
        if (filter_pid()) {
            return 0;
        }
        log_error("bio_frontmerge: no prev_io", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;
    }

    track_key_t target_key = {};
    target_key.dev = args->dev;
    target_key.sector = args->sector + (u64) args->nr_sector;
    target_key.type = type;
    target_key.type |= TRACK_TYPE_QUEUE;

    track_io_t *target_io = submissions.lookup(&target_key);

    if (!target_io) {

        // query the block layer in case backmerge occurs before getrq
        target_key.type = type;
        target_key.type |= TRACK_TYPE_DEVICE;
        target_io = submissions.lookup(&target_key);

        if (!target_io) {

            if (filter_pid()) {
                return 0;
            }
            log_error("bio_frontmerge: no target_io", target_key.dev, target_key.sector, 0, args->rwbs, 0, 0, 0);
            return 0;

        }

    }

    // Shortcircuit target stack to completion queue for bio_complete handling later
    if (target_io->top) {

        track_key_t next_key = {};
        next_key.type = type;
        next_key.type |= TRACK_TYPE_DEVICE;

        track_io_t next_io = {};
        next_io.type = type;
        next_io.nr_sector = target_io->nr_sector;
        next_io.start_ns = bpf_ktime_get_ns(); // TODO: This impacts completion latency accuracy
        next_io.top = target_io->top;
        memcpy(next_io.stack, target_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

        if (next_io.top >= TRACK_STACK_MAX) {
            submissions.delete(&target_key);
            log_error("bio_frontmerge: stack bounds check", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, next_io.top);
            return 0;
        }

        // pop item from stack to identify upper layer bio
        track_item_t item = next_io.stack[next_io.top];

        next_key.dev = item.dev;
        next_key.sector = item.sector;
        next_io.dev = item.dev;
        next_io.sector = item.sector;

        log_debug("bio_frontmerge: pop stack item", item.dev, item.sector, 0, 0, 0, 0, next_io.top);

        completions.update(&next_key, &next_io);

    }

    track_stat_t s = {};
    s.dev = prev_io->dev;
    s.type = type;
    s.type |= TRACK_TYPE_DEVICE;
    s.st = bpf_ktime_get_ns() - prev_io->start_ns;
    s.sz = args->nr_sector; // use reported value for accuracy
    push_stat(&s);

    track_stat_t sm = {};
    memcpy(&sm, &s, sizeof(track_stat_t));
    sm.type = type;
    sm.type |= TRACK_TYPE_QUEUE;
    sm.type |= TRACK_TYPE_MERGE;
    push_stat(&sm);

    prev_io->nr_sector += target_io->nr_sector;

    submissions.delete(&target_key);

    return 1;
}

int trace_block_bio_backmerge(block_bio_backmerge_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("bio_backmerge: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_DEVICE;

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {
        if (filter_pid()) {
            return 0;
        }
        log_error("bio_backmerge: no prev_io", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;
    }

    u64 start_sector = 0;

    track_bmrq_key_t bmrq_key = {};
    bmrq_key.dev = args->dev;
    bmrq_key.end_sector = args->sector;
    bmrq_key.type = type;

    track_bmrq_val_t *bmrq_val = bmrqs.lookup(&bmrq_key);

    if (!bmrq_val) {

        submissions.delete(&prev_key);
        log_error("bio_backmerge: no merge target", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;

    } else {

        // this "else" block is a workaround for:
        //
        // error: /virtual/main.c:0:0: in function trace_block_bio_backmerge i32 (%struct.block_bio_queue*):
        // Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.

        // replace backmerge target since repetitive merges are possible until rq_issue

        start_sector = bmrq_val->sector;

        track_bmrq_key_t bmrq_new_key = {};
        bmrq_new_key.dev = args->dev;
        bmrq_new_key.end_sector = args->sector + (u64) args->nr_sector;
        bmrq_new_key.type = type;

        track_bmrq_val_t bmrq_new_val = {};
        bmrq_new_val.sector = start_sector;
        bmrq_new_val.start_ns = bpf_ktime_get_ns();

        // we must use update here to overwrite the bmrq request previously created for this backmerge request
        bmrqs.update(&bmrq_new_key, &bmrq_new_val);
        bmrqs.delete(&bmrq_key);

    }

    track_key_t target_key = {};
    target_key.dev = args->dev;
    target_key.sector = start_sector;
    target_key.type = type;
    target_key.type |= TRACK_TYPE_QUEUE;

    track_io_t *target_io = submissions.lookup(&target_key);

    if (!target_io) {

        // query the block layer in case backmerge occurs before getrq
        target_key.type = type;
        target_key.type |= TRACK_TYPE_DEVICE;
        target_io = submissions.lookup(&target_key);

        if (!target_io) {

            submissions.delete(&prev_key);
            if (filter_pid()) {
                return 0;
            }
            log_error("bio_backmerge: no target_io", target_key.dev, target_key.sector, 0, args->rwbs, 0, 0, 0);
            return 0;

        }

    }

    // Shortcircuit prev stack to completion queue for bio_complete handling later
    if (prev_io->top) {

        track_key_t next_key = {};
        next_key.type = type;
        next_key.type |= TRACK_TYPE_DEVICE;

        track_io_t next_io = {};
        next_io.type = type;
        next_io.nr_sector = args->nr_sector; // use reported value for accuracy
        next_io.start_ns = bpf_ktime_get_ns(); // TODO: This impacts completion latency accuracy
        next_io.top = prev_io->top;
        memcpy(next_io.stack, prev_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

        if (next_io.top >= TRACK_STACK_MAX) {
            submissions.delete(&prev_key);
            log_error("bio_backmerge: stack bounds check", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, next_io.top);
            return 0;
        }

        // pop item from stack to identify upper layer bio
        track_item_t item = next_io.stack[next_io.top];

        next_key.dev = item.dev;
        next_key.sector = item.sector;
        next_io.dev = item.dev;
        next_io.sector = item.sector;

        log_debug("bio_backmerge: pop stack item", item.dev, item.sector, 0, 0, 0, 0, next_io.top);

        completions.update(&next_key, &next_io);

    }

    track_stat_t s = {};
    s.dev = prev_io->dev;
    s.type = type;
    s.type |= TRACK_TYPE_DEVICE;
    s.st = bpf_ktime_get_ns() - prev_io->start_ns;
    s.sz = args->nr_sector; // use reported value for accuracy
    push_stat(&s);

    track_stat_t sm = {};
    memcpy(&sm, &s, sizeof(track_stat_t));
    sm.type = type;
    sm.type |= TRACK_TYPE_QUEUE;
    sm.type |= TRACK_TYPE_MERGE;
    push_stat(&sm);

    target_io->nr_sector += prev_io->nr_sector;

    submissions.delete(&prev_key);

    return 1;

}

int trace_block_bio_bounce(block_bio_bounce_t *args) {
    // High memory IO wizardry
    log_debug("bio_bounce: enter", args->dev, args->sector, 0, args->rwbs, 0, 0, 0);
    return 1;
}

int trace_block_split(block_split_t *args) {

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("split: enter", args->dev, args->new_sector, 0, args->rwbs, args->dev, args->sector, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_DEVICE;

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {

        u32 dev = args->dev;
        u32 *dm_device = dm_devices.lookup(&dev);

        if (dm_device) {

            log_debug("split: dm split", args->dev, args->new_sector, 0, args->rwbs, args->dev, args->sector, 0);

            // create split io entry in submissions
            track_key_t next_key = {};
            next_key.dev = args->dev;
            next_key.sector = args->new_sector;
            next_key.type = type;
            next_key.type |= TRACK_TYPE_DEVICE;

            track_io_t next_io = {};
            next_io.dev = args->dev;
            next_io.sector = args->new_sector;
            next_io.type = type;
            next_io.nr_sector = 1; // We don't know the actual size. We will correct it during remap.
            next_io.start_ns = bpf_ktime_get_ns();
            next_io.top = 0;

            track_split_key_t split_key = {};
            split_key.dev = args->dev;
            split_key.sector = args->new_sector;
            split_key.type = type;

            track_split_val_t *split_val = splits.lookup(&split_key);

            if (split_val) {

                if (split_val->split_nr_sector >= split_val->remaining_nr_sector) {

//                    log_debug("split: dm split last", args->dev, args->new_sector, 0, args->rwbs, args->dev, args->sector, split_val->top);

                    // this is last split
                    next_io.top = split_val->top;
                    memcpy(next_io.stack, split_val->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

                    splits.delete(&split_key);

                } else {

//                    log_debug("split: dm split item", args->dev, args->new_sector, 0, args->rwbs, args->dev, args->sector, split_val->top);

                    // more splits are expected

                    track_split_key_t split_new_key = {};
                    split_new_key.dev = args->dev;
                    split_new_key.sector = args->new_sector + (u64) split_val->split_nr_sector;
                    split_new_key.type = type;

                    track_split_val_t split_new_val = {};
                    split_new_val.remaining_nr_sector = split_val->remaining_nr_sector - (u64) split_val->split_nr_sector;
                    split_new_val.split_nr_sector = split_val->split_nr_sector;
                    split_new_val.start_ns = bpf_ktime_get_ns();
                    split_new_val.top = split_val->top;
                    memcpy(split_new_val.stack, split_val->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

                    splits.update(&split_new_key, &split_new_val);
                    splits.delete(&split_key);

                }

                track_stat_t s = {};
                s.dev = args->dev;
                s.type = type;
                s.type |= TRACK_TYPE_DEVICE;
                s.type |= TRACK_TYPE_SPLIT;
                s.st = bpf_ktime_get_ns() - split_val->start_ns;
                if (split_val->split_nr_sector >= split_val->remaining_nr_sector) {
                    s.sz = split_val->remaining_nr_sector;
                } else {
                    s.sz = split_val->split_nr_sector;
                }
                push_stat(&s);

            }

            submissions.insert(&next_key, &next_io);

            return 1;

        }

        if (filter_pid()) {
            return 0;
        }
        log_error("split: no prev_io", args->dev, args->new_sector, 0, args->rwbs, args->dev, args->sector, 0);
        return 0;
    }

    u32 nr_sector1 = args->new_sector - args->sector;
    u32 nr_sector2 = prev_io->nr_sector - nr_sector1;

    // update prev io size
    prev_io->nr_sector = nr_sector1;

    // create split io entry in submissions
    track_key_t next_key = {};
    next_key.dev = args->dev;
    next_key.sector = args->new_sector;
    next_key.type = type;
    next_key.type |= TRACK_TYPE_DEVICE;

    track_io_t next_io = {};
    next_io.dev = args->dev;
    next_io.sector = args->new_sector;
    next_io.type = type;
    next_io.nr_sector = nr_sector2;
    next_io.start_ns = bpf_ktime_get_ns();
    next_io.top = 0; // split io does not trigger bio_complete

    submissions.update(&next_key, &next_io);

    return 1;
}

int trace_block_getrq(block_getrq_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("getrq: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_DEVICE;

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {
        if (filter_pid()) {
            return 0;
        }
        log_error("getrq: no prev_io", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;
    }

    track_key_t next_key = {};
    next_key.dev = args->dev;
    next_key.sector = args->sector;
    next_key.type = type;
    next_key.type |= TRACK_TYPE_QUEUE;

    track_io_t next_io = {};
    next_io.dev = args->dev;
    next_io.sector = args->sector;
    next_io.type = type;
    next_io.nr_sector = args->nr_sector; // use reported value for accuracy
    next_io.start_ns = bpf_ktime_get_ns();
    next_io.top = prev_io->top;
    memcpy(next_io.stack, prev_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

    track_item_t item = {};
    item.dev = prev_io->dev;
    item.sector = prev_io->sector;

    if (prev_io->top >= TRACK_STACK_MAX - 1) {
        log_error("getrq: stack bounds check", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, prev_io->top);
        submissions.delete(&prev_key);
        return 0;
    }

    next_io.top = prev_io->top + 1;
    next_io.stack[next_io.top] = item;

    log_debug("getrq: push stack item", item.dev, item.sector, 0, 0, 0, 0, next_io.top);

    submissions.update(&next_key, &next_io);

    track_bmrq_key_t bmrq_key = {};
    bmrq_key.dev = args->dev;
    bmrq_key.end_sector = args->sector + (u64) args->nr_sector;
    bmrq_key.type = type;

    track_bmrq_val_t bmrq_val = {};
    bmrq_val.sector = args->sector;
    bmrq_val.start_ns = bpf_ktime_get_ns();

    bmrqs.insert(&bmrq_key, &bmrq_val);

    track_stat_t s = {};
    s.dev = prev_io->dev;
    s.type = type;
    s.type |= TRACK_TYPE_DEVICE;
    s.st = bpf_ktime_get_ns() - prev_io->start_ns;
    s.sz = args->nr_sector; // use reported value for accuracy
    push_stat(&s);

    submissions.delete(&prev_key);

    return 1;
}

int trace_block_rq_insert(block_rq_insert_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("rq_insert: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_QUEUE;

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {
        if (filter_pid()) {
            return 0;
        }
        log_error("rq_insert: no prev_io", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;
    }

    // rq_insert is not hit consistently. Update start time of prev_io if it does.
    prev_io->start_ns = bpf_ktime_get_ns();

    return 1;
}

int trace_block_rq_issue(block_rq_issue_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("rq_issue: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_QUEUE;

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {

        if (filter_pid()) {
            return 0;
        }

        log_debug("rq_issue: direct submission", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

        track_key_t next_key = {};
        next_key.dev = args->dev;
        next_key.sector = args->sector;
        next_key.type = type;
        next_key.type |= TRACK_TYPE_DRIVER;

        track_io_t next_io = {};
        next_io.dev = args->dev;
        next_io.sector = args->sector;
        next_io.type = type;
        next_io.nr_sector = args->nr_sector;
        next_io.start_ns = bpf_ktime_get_ns();
        next_io.top = 0;

        submissions.update(&next_key, &next_io);

        return 1;
    }

    track_key_t next_key = {};
    next_key.dev = prev_io->dev;
    next_key.sector = prev_io->sector;
    next_key.type = type;
    next_key.type |= TRACK_TYPE_DRIVER;

    track_io_t next_io = {};
    next_io.dev = prev_io->dev;
    next_io.sector = prev_io->sector;
    next_io.type = type;
    next_io.nr_sector = args->nr_sector; // use reported value for accuracy
    next_io.start_ns = bpf_ktime_get_ns();
    next_io.top = prev_io->top;
    memcpy(next_io.stack, prev_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

    submissions.update(&next_key, &next_io);

    track_bmrq_key_t bmrq_key = {};
    bmrq_key.dev = args->dev;
    bmrq_key.end_sector = args->sector + (u64) args->nr_sector;
    bmrq_key.type = type;

    bmrqs.delete(&bmrq_key);

    track_stat_t s = {};
    s.dev = prev_io->dev;
    s.type = type;
    s.type |= TRACK_TYPE_QUEUE;
    s.st = bpf_ktime_get_ns() - prev_io->start_ns;
    s.sz = args->nr_sector; // use reported value for accuracy
    push_stat(&s);

    submissions.delete(&prev_key);

    return 1;
}

int trace_block_rq_merge(block_rq_merge_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("rq_merge: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    // TODO

    return 1;
}

int trace_block_rq_error(block_rq_error_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("rq_error: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    // TODO

    return 1;
}

int trace_block_rq_remap(block_rq_remap_t *args) {
    // request-based dm-mq?
    log_debug("rq_remap: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
    return 1;
}

int trace_block_rq_requeue(block_rq_requeue_t *args) {
    log_debug("rq_requeue: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
    return 1;
}

int trace_block_rq_complete(block_rq_complete_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("rq_complete: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_DRIVER; // completion of request in driver

    track_io_t *prev_io = submissions.lookup(&prev_key);

    if (!prev_io) {
        if (filter_pid()) {
            return 0;
        }
        log_error("rq_complete: no prev_io", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;
    }

    if (prev_io->top == 0) {
        log_error("rq_complete: stack minimum check", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, prev_io->top);
        submissions.delete(&prev_key);
        return 0;
    }

    track_key_t next_key = {};
    next_key.type = type;
    next_key.type |= TRACK_TYPE_DEVICE; // send back to the block layer

    track_io_t next_io = {};
    next_io.type = type;
    next_io.nr_sector = args->nr_sector; // use reported value for accuracy
    next_io.start_ns = bpf_ktime_get_ns();
    next_io.top = prev_io->top - 1;
    memcpy(next_io.stack, prev_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

    if (next_io.top >= TRACK_STACK_MAX) {
        log_error("rq_complete: stack bounds check", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, next_io.top);
        submissions.delete(&prev_key);
        return 0;
    }

    track_item_t item = next_io.stack[next_io.top];

    next_key.dev = item.dev;
    next_key.sector = item.sector;
    next_io.dev = item.dev;
    next_io.sector = item.sector;

    log_debug("rq_complete: pop stack item", item.dev, item.sector, 0, 0, 0, 0, next_io.top);

    // update calls are preferred because missing rq_complete calls for previous matching ios skew latency values
    // in this way, the latest call overwrites the entry instead of failing silently
    completions.update(&next_key, &next_io);

    // backmerge skews service time
    track_stat_t s = {};
    s.dev = prev_io->dev;
    s.type = type;
    s.type |= TRACK_TYPE_DRIVER;
    s.type |= TRACK_TYPE_COMPLETION;
    s.st = bpf_ktime_get_ns() - prev_io->start_ns;
    s.sz = args->nr_sector; // use reported value for accuracy
    push_stat(&s);

    submissions.delete(&prev_key);

    return 1;
}

int trace_block_bio_complete(block_bio_complete_t *args) {

    if (args->nr_sector == 0) {
        return 0;
    }

    int type = get_type(args->rwbs);

    if (!match_type(type)) {
        return 0;
    }

    log_debug("bio_complete: enter", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);

    track_key_t prev_key = {};
    prev_key.dev = args->dev;
    prev_key.sector = args->sector;
    prev_key.type = type;
    prev_key.type |= TRACK_TYPE_DEVICE; // completion of request in driver is matched here

    track_io_t *prev_io = completions.lookup(&prev_key);

    if (!prev_io) {
        if (filter_pid()) {
            return 0;
        }
        log_error("bio_complete: no prev_io", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, 0);
        return 0;
    }

    if (prev_io->top) {

        track_key_t next_key = {};
        next_key.type = type;
        next_key.type |= TRACK_TYPE_DEVICE;

        track_io_t next_io = {};
        next_io.type = type;
        next_io.nr_sector = args->nr_sector; // use reported value for accuracy
        next_io.start_ns = bpf_ktime_get_ns();
        next_io.top = prev_io->top - 1;
        memcpy(next_io.stack, prev_io->stack, sizeof(track_item_t) * TRACK_STACK_MAX);

        if (next_io.top >= TRACK_STACK_MAX) {
            log_error("bio_complete: stack bounds check", args->dev, args->sector, args->nr_sector, args->rwbs, 0, 0, next_io.top);
            completions.delete(&prev_key);
            return 0;
        }

        track_item_t item = next_io.stack[next_io.top];

        next_key.dev = item.dev;
        next_key.sector = item.sector;
        next_io.dev = item.dev;
        next_io.sector = item.sector;

        log_debug("bio_complete: pop stack item", item.dev, item.sector, 0, 0, 0, 0, next_io.top);

        completions.update(&next_key, &next_io);

    }

    track_stat_t s = {};
    s.dev = prev_io->dev;
    s.type = type;
    s.type |= TRACK_TYPE_DEVICE;
    s.type |= TRACK_TYPE_COMPLETION;
    s.st = bpf_ktime_get_ns() - prev_io->start_ns;
    s.sz = args->nr_sector; // use reported value for accuracy
    push_stat(&s);

    completions.delete(&prev_key);

    return 1;
}

int trace_block_dirty_buffer(block_dirty_buffer_t *args) {
    log_debug("dirty_buffer: enter", args->dev, args->sector, 0, 0, 0, 0, 0);
    return 1;
}

int trace_block_touch_buffer(block_touch_buffer_t *args) {
    log_debug("touch_buffer: enter", args->dev, args->sector, 0, 0, 0, 0, 0);
    return 1;
}