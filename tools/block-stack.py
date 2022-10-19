#!/usr/bin/python
#
#     SysBPF is a system analysis tool built on the BPF Compiler Collection (BCC) toolkit.
#     Copyright (C) 2022 Burak Seydioglu
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

from bcc import BPF
from enum import IntEnum
from collections import OrderedDict, defaultdict
from datetime import datetime
import os
import sys
import ctypes
import time
import argparse
import logging

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from lib.block import BlockHelper, BlockStack


class TrackConfig(IntEnum):
    LOG_LEVEL = 0
    PID       = 1


class TrackLogLevel(IntEnum):
    ERROR  = 40
    WARN   = 30
    INFO   = 20
    DEBUG  = 10
    NOTSET = 0


class TrackKey(ctypes.Structure):
    _fields_ = [
        ("dev", ctypes.c_uint),
        ("sector", ctypes.c_uint64),
        ("type", ctypes.c_uint),
    ]


class TrackBmrqKey(ctypes.Structure):
    _fields_ = [
        ("dev", ctypes.c_uint),
        ("end_sector", ctypes.c_uint64),
        ("type", ctypes.c_uint),
    ]


class TrackSplitKey(ctypes.Structure):
    _fields_ = [
        ("dev", ctypes.c_uint),
        ("end_sector", ctypes.c_uint64),
        ("type", ctypes.c_uint),
    ]


class TrackStat(IntEnum):
    R_CT         = (1 << 0)
    R_ST         = (1 << 1)
    R_SZ         = (1 << 2)
    RA_CT        = (1 << 3)
    RA_ST        = (1 << 4)
    RA_SZ        = (1 << 5)
    RM_CT        = (1 << 6)
    RM_ST        = (1 << 7)
    RM_SZ        = (1 << 8)
    RS_CT        = (1 << 9)
    RS_ST        = (1 << 10)
    RS_SZ        = (1 << 11)
    W_CT         = (1 << 12)
    W_ST         = (1 << 13)
    W_SZ         = (1 << 14)
    WM_CT        = (1 << 15)
    WM_ST        = (1 << 16)
    WM_SZ        = (1 << 17)
    WS_CT        = (1 << 18)
    WS_ST        = (1 << 19)
    WS_SZ        = (1 << 20)
    D_CT         = (1 << 21)
    D_ST         = (1 << 22)
    D_SZ         = (1 << 23)
    DM_CT        = (1 << 24)
    DM_ST        = (1 << 25)
    DM_SZ        = (1 << 26)
    DS_CT        = (1 << 27)
    DS_ST        = (1 << 28)
    DS_SZ        = (1 << 29)


class TrackDerivedStat(IntEnum):
    R_BW         = (1 << 40)
    RA_BW        = (1 << 41)
    RM_BW        = (1 << 42)
    RS_BW        = (1 << 43)
    W_BW         = (1 << 44)
    WM_BW        = (1 << 45)
    WS_BW        = (1 << 46)
    D_BW         = (1 << 47)
    DM_BW        = (1 << 48)
    DS_BW        = (1 << 49)


submission_bitmaps = OrderedDict()
submission_bitmaps[TrackStat.R_CT] = "s_r_ct"
submission_bitmaps[TrackStat.R_ST] = "s_r_st"
submission_bitmaps[TrackStat.R_SZ] = "s_r_sz"
submission_bitmaps[TrackDerivedStat.R_BW] = "s_r_bw"
submission_bitmaps[TrackStat.RA_CT] = "s_ra_ct"
submission_bitmaps[TrackStat.RA_ST] = "s_ra_st"
submission_bitmaps[TrackStat.RA_SZ] = "s_ra_sz"
submission_bitmaps[TrackDerivedStat.RA_BW] = "s_ra_bw"
submission_bitmaps[TrackStat.RM_CT] = "s_rm_ct"
submission_bitmaps[TrackStat.RM_ST] = "s_rm_st"
submission_bitmaps[TrackStat.RM_SZ] = "s_rm_sz"
submission_bitmaps[TrackDerivedStat.RM_BW] = "s_rm_bw"
submission_bitmaps[TrackStat.RS_CT] = "s_rs_ct"
submission_bitmaps[TrackStat.RS_ST] = "s_rs_st"
submission_bitmaps[TrackStat.RS_SZ] = "s_rs_sz"
submission_bitmaps[TrackDerivedStat.RS_BW] = "s_rs_bw"
submission_bitmaps[TrackStat.W_CT] = "s_w_ct"
submission_bitmaps[TrackStat.W_ST] = "s_w_st"
submission_bitmaps[TrackStat.W_SZ] = "s_w_sz"
submission_bitmaps[TrackDerivedStat.W_BW] = "s_w_bw"
submission_bitmaps[TrackStat.WM_CT] = "s_wm_ct"
submission_bitmaps[TrackStat.WM_ST] = "s_wm_st"
submission_bitmaps[TrackStat.WM_SZ] = "s_wm_sz"
submission_bitmaps[TrackDerivedStat.WM_BW] = "s_wm_bw"
submission_bitmaps[TrackStat.WS_CT] = "s_ws_ct"
submission_bitmaps[TrackStat.WS_ST] = "s_ws_st"
submission_bitmaps[TrackStat.WS_SZ] = "s_ws_sz"
submission_bitmaps[TrackDerivedStat.WS_BW] = "s_ws_bw"
submission_bitmaps[TrackStat.D_CT] = "s_d_ct"
submission_bitmaps[TrackStat.D_ST] = "s_d_st"
submission_bitmaps[TrackStat.D_SZ] = "s_d_sz"
submission_bitmaps[TrackDerivedStat.D_BW] = "s_d_bw"
submission_bitmaps[TrackStat.DM_CT] = "s_dm_ct"
submission_bitmaps[TrackStat.DM_ST] = "s_dm_st"
submission_bitmaps[TrackStat.DM_SZ] = "s_dm_sz"
submission_bitmaps[TrackDerivedStat.DM_BW] = "s_dm_bw"
submission_bitmaps[TrackStat.DS_CT] = "s_ds_ct"
submission_bitmaps[TrackStat.DS_ST] = "s_ds_st"
submission_bitmaps[TrackStat.DS_SZ] = "s_ds_sz"
submission_bitmaps[TrackDerivedStat.DS_BW] = "s_ds_bw"

completion_bitmaps = OrderedDict()
completion_bitmaps[TrackStat.R_CT] = "c_r_ct"
completion_bitmaps[TrackStat.R_ST] = "c_r_st"
completion_bitmaps[TrackStat.R_SZ] = "c_r_sz"
completion_bitmaps[TrackDerivedStat.R_BW] = "c_r_bw"
completion_bitmaps[TrackStat.W_CT] = "c_w_ct"
completion_bitmaps[TrackStat.W_ST] = "c_w_st"
completion_bitmaps[TrackStat.W_SZ] = "c_w_sz"
completion_bitmaps[TrackDerivedStat.W_BW] = "c_w_bw"
completion_bitmaps[TrackStat.D_CT] = "c_d_ct"
completion_bitmaps[TrackStat.D_ST] = "c_d_st"
completion_bitmaps[TrackStat.D_SZ] = "c_d_sz"
completion_bitmaps[TrackDerivedStat.D_BW] = "c_d_bw"

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pid", action="store", type=str, default="")
parser.add_argument("-i", "--interval", action="store", type=int, default=1)
parser.add_argument("-l", "--log-level", action="store", type=str.upper, choices=["DEBUG", "INFO", "WARN", "ERROR"], default="NOTSET", help="Do NOT use under load! For debugging purposes only!")
parser.add_argument("--no-header", action="store_true")
args = parser.parse_args()

logger = logging.getLogger("sysbpf")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

b = BPF(src_file="../src/block-stack.c")

configs = dict()

if args.interval <= 0:
    args.interval = 1

if TrackLogLevel[args.log_level] == TrackLogLevel.NOTSET:
    logger.disabled = True
    configs[TrackConfig.LOG_LEVEL] = TrackLogLevel.NOTSET
else:
    logger.setLevel(TrackLogLevel[args.log_level])
    configs[TrackConfig.LOG_LEVEL] = TrackLogLevel[args.log_level]

pids = dict()

if len(args.pid) > 0:

    configs[TrackConfig.PID] = 1

    for pid in args.pid.split(','):
        pids[int(pid)] = int(pid)

    pids_length = len(pids)
    pid_key_t = ctypes.c_uint * pids_length
    pid_val_t = ctypes.c_uint * pids_length

    b["pids"].items_update_batch(pid_key_t(*pids.keys()), pid_val_t(*pids.values()))

configs_length = len(configs)
config_key_t = ctypes.c_uint * configs_length
config_val_t = ctypes.c_uint * configs_length

b["configs"].items_update_batch(config_key_t(*configs.keys()), config_val_t(*configs.values()))

dm_devices = dict()
partition_holders = dict()
partition_overrides = dict()

block_stack = BlockStack()

# not 100% foolproof if a dm device holds multiple partitions on the same block device for some peculiar reason
for device in block_stack.devices.values():
    if device.is_dm:
        dm_devices[device.id] = device.id
    if len(device.slaves) > 0:
        for slave_id in device.slaves:
            slave = block_stack.devices.get(slave_id)
            if slave.is_partition:
                partition_holders[slave_id] = device.id
                key = device.id << 32 | slave.parent
                partition_overrides[key] = slave_id

dm_devices_length = len(dm_devices)
dm_device_key_t = ctypes.c_uint * dm_devices_length
dm_device_val_t = ctypes.c_uint * dm_devices_length

b["dm_devices"].items_update_batch(dm_device_key_t(*dm_devices.keys()), dm_device_val_t(*dm_devices.values()))

partition_holders_length = len(partition_holders)
partition_holder_key_t = ctypes.c_uint * partition_holders_length
partition_holder_val_t = ctypes.c_uint * partition_holders_length

b["partition_holders"].items_update_batch(partition_holder_key_t(*partition_holders.keys()), partition_holder_val_t(*partition_holders.values()))

partition_overrides_length = len(partition_overrides)
partition_override_key_t = ctypes.c_uint64 * partition_overrides_length
partition_override_val_t = ctypes.c_uint * partition_overrides_length

b["partition_overrides"].items_update_batch(partition_override_key_t(*partition_overrides.keys()), partition_override_val_t(*partition_overrides.values()))

# tracepoints

b.attach_tracepoint(tp="block:block_bio_queue", fn_name="trace_block_bio_queue")
b.attach_tracepoint(tp="block:block_bio_remap", fn_name="trace_block_bio_remap")
b.attach_tracepoint(tp="block:block_bio_frontmerge", fn_name="trace_block_bio_frontmerge")
b.attach_tracepoint(tp="block:block_bio_backmerge", fn_name="trace_block_bio_backmerge")
b.attach_tracepoint(tp="block:block_bio_bounce", fn_name="trace_block_bio_bounce")
b.attach_tracepoint(tp="block:block_split", fn_name="trace_block_split")
b.attach_tracepoint(tp="block:block_getrq", fn_name="trace_block_getrq")
b.attach_tracepoint(tp="block:block_rq_insert", fn_name="trace_block_rq_insert")
b.attach_tracepoint(tp="block:block_rq_issue", fn_name="trace_block_rq_issue")
b.attach_tracepoint(tp="block:block_rq_merge", fn_name="trace_block_rq_merge")
b.attach_tracepoint(tp="block:block_rq_error", fn_name="trace_block_rq_error")
b.attach_tracepoint(tp="block:block_rq_remap", fn_name="trace_block_rq_remap")
b.attach_tracepoint(tp="block:block_rq_requeue", fn_name="trace_block_rq_requeue")
b.attach_tracepoint(tp="block:block_rq_complete", fn_name="trace_block_rq_complete")
b.attach_tracepoint(tp="block:block_bio_complete", fn_name="trace_block_bio_complete")
# b.attach_tracepoint(tp="block:block_dirty_buffer", fn_name="trace_block_dirty_buffer")
# b.attach_tracepoint(tp="block:block_touch_buffer", fn_name="trace_block_touch_buffer")

stats_fs = OrderedDict()
stats_dev = OrderedDict()
stats_q = OrderedDict()
stats_drv = OrderedDict()


def reset_stats():

    for device in block_stack.devices.values():
        stats_dev[device.id] = defaultdict(int)

    for queue in block_stack.queues.values():
        stats_q[queue.device.id] = defaultdict(int)

    for driver in block_stack.drivers.values():
        stats_drv[driver.device.id] = defaultdict(int)


def row_format():
    return "{}{}".format("{:>19} {:>12}", "{:>14}" * 49)


# s: submission
# c: completion
# r, w, d: read, write, discard
# ra: read ahead
# rm, wm, dm: read merge, write merge, discard merge
# rs, ws, ds: read split, write split, discard split
# ct: count (request/s)
# st: service time (time/request)
# sz: size (sectors/request)
# bw: bandwidth (sectors/s)
def print_header():
    print(row_format().format(
        "datetime",
        "component",
        *submission_bitmaps.values(),
        *completion_bitmaps.values(),
    ))


def calculate_stat(data, stat_field, divisor_field=None):
    stat_val = float(data.get(stat_field, 0))
    if divisor_field is not None:
        divisor_val = float(data.get(divisor_field, 0))
        if divisor_val > 0:
            stat_val = stat_val / divisor_val
        else:
            stat_val = float(0)
    return round(stat_val, 2)


def calculate_interval_stat(data, stat_field, divisor_field=None):
    stat_val = calculate_stat(data, stat_field, divisor_field)
    return round((stat_val / args.interval), 2)


def convert_to_microseconds(stat):
    return round(float(stat) / 1000, 0)


def print_stats():

    interval = abs(args.interval)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for category_id, category_stats in {"dev": stats_dev, "q": stats_q, "drv": stats_drv}.items():

        for component_id, component_stats in category_stats.items():

            s_r_ct = calculate_interval_stat(component_stats, "s_r_ct")
            s_r_st = convert_to_microseconds(calculate_stat(component_stats, "s_r_st", "s_r_ct"))
            s_r_sz = calculate_stat(component_stats, "s_r_sz", "s_r_ct")
            s_r_bw = calculate_interval_stat(component_stats, "s_r_sz")
            s_ra_ct = calculate_interval_stat(component_stats, "s_ra_ct")
            s_ra_st = convert_to_microseconds(calculate_stat(component_stats, "s_ra_st", "s_ra_ct"))
            s_ra_sz = calculate_stat(component_stats, "s_ra_sz", "s_ra_ct")
            s_ra_bw = calculate_interval_stat(component_stats, "s_ra_sz")
            s_rm_ct = calculate_interval_stat(component_stats, "s_rm_ct")
            s_rm_st = convert_to_microseconds(calculate_stat(component_stats, "s_rm_st", "s_rm_ct"))
            s_rm_sz = calculate_stat(component_stats, "s_rm_sz", "s_rm_ct")
            s_rm_bw = calculate_interval_stat(component_stats, "s_rm_sz")
            s_rs_ct = calculate_interval_stat(component_stats, "s_rs_ct")
            s_rs_st = convert_to_microseconds(calculate_stat(component_stats, "s_rs_st", "s_rs_ct"))
            s_rs_sz = calculate_stat(component_stats, "s_rs_sz", "s_rs_ct")
            s_rs_bw = calculate_interval_stat(component_stats, "s_rs_sz")
            s_w_ct = calculate_interval_stat(component_stats, "s_w_ct")
            s_w_st = convert_to_microseconds(calculate_stat(component_stats, "s_w_st", "s_w_ct"))
            s_w_sz = calculate_stat(component_stats, "s_w_sz", "s_w_ct")
            s_w_bw = calculate_interval_stat(component_stats, "s_w_sz")
            s_wm_ct = calculate_interval_stat(component_stats, "s_wm_ct")
            s_wm_st = convert_to_microseconds(calculate_stat(component_stats, "s_wm_st", "s_wm_ct"))
            s_wm_sz = calculate_stat(component_stats, "s_wm_sz", "s_wm_ct")
            s_wm_bw = calculate_interval_stat(component_stats, "s_wm_sz")
            s_ws_ct = calculate_interval_stat(component_stats, "s_ws_ct")
            s_ws_st = convert_to_microseconds(calculate_stat(component_stats, "s_ws_st", "s_ws_ct"))
            s_ws_sz = calculate_stat(component_stats, "s_ws_sz", "s_ws_ct")
            s_ws_bw = calculate_interval_stat(component_stats, "s_ws_sz")
            s_d_ct = calculate_interval_stat(component_stats, "s_d_ct")
            s_d_st = convert_to_microseconds(calculate_stat(component_stats, "s_d_st", "s_d_ct"))
            s_d_sz = calculate_stat(component_stats, "s_d_sz", "s_d_ct")
            s_d_bw = calculate_interval_stat(component_stats, "s_d_sz")
            s_dm_ct = calculate_interval_stat(component_stats, "s_dm_ct")
            s_dm_st = convert_to_microseconds(calculate_stat(component_stats, "s_dm_st", "s_dm_ct"))
            s_dm_sz = calculate_stat(component_stats, "s_dm_sz", "s_dm_ct")
            s_dm_bw = calculate_interval_stat(component_stats, "s_dm_sz")
            s_ds_ct = calculate_interval_stat(component_stats, "s_ds_ct")
            s_ds_st = convert_to_microseconds(calculate_stat(component_stats, "s_ds_st", "s_ds_ct"))
            s_ds_sz = calculate_stat(component_stats, "s_ds_sz", "s_ds_ct")
            s_ds_bw = calculate_interval_stat(component_stats, "s_ds_sz")
            c_r_ct = calculate_interval_stat(component_stats, "c_r_ct")
            c_r_st = convert_to_microseconds(calculate_stat(component_stats, "c_r_st", "c_r_ct"))
            c_r_sz = calculate_stat(component_stats, "c_r_sz", "c_r_ct")
            c_r_bw = calculate_interval_stat(component_stats, "c_r_sz")
            c_w_ct = calculate_interval_stat(component_stats, "c_w_ct")
            c_w_st = convert_to_microseconds(calculate_stat(component_stats, "c_w_st", "c_w_ct"))
            c_w_sz = calculate_stat(component_stats, "c_w_sz", "c_w_ct")
            c_w_bw = calculate_interval_stat(component_stats, "c_w_sz")
            c_d_ct = calculate_interval_stat(component_stats, "c_d_ct")
            c_d_st = convert_to_microseconds(calculate_stat(component_stats, "c_d_st", "c_d_ct"))
            c_d_sz = calculate_stat(component_stats, "c_d_sz", "c_d_ct")
            c_d_bw = calculate_interval_stat(component_stats, "c_d_sz")

            print(row_format().format(
                now,
                "{}[{}]".format(category_id, BlockHelper.label_from_id(component_id)),
                s_r_ct, s_r_st , s_r_sz, s_r_bw,    # 7
                s_ra_ct, s_ra_st, s_ra_sz, s_ra_bw, # 11
                s_rm_ct, s_rm_st, s_rm_sz, s_rm_bw, # 15
                s_rs_ct, s_rs_st, s_rs_sz, s_rs_bw, # 19
                s_w_ct, s_w_st, s_w_sz, s_w_bw,     # 23
                s_wm_ct, s_wm_st, s_wm_sz, s_wm_bw, # 27
                s_ws_ct, s_ws_st, s_ws_sz, s_ws_bw, # 31
                s_d_ct, s_d_st, s_d_sz, s_d_bw,     # 35
                s_dm_ct, s_dm_st, s_dm_sz, s_dm_bw, # 39
                s_ds_ct, s_ds_st, s_ds_sz, s_ds_bw, # 43
                c_r_ct, c_r_st, c_r_sz, c_r_bw,     # 47
                c_w_ct, c_w_st, c_w_sz, c_w_bw,     # 51
                c_d_ct, c_d_st, c_d_sz, c_d_bw      # 55
            ))


def collect_stats():

    for category_id, category_stats in {"submission_stats_dev": stats_dev, "submission_stats_q": stats_q, "submission_stats_drv": stats_drv}.items():
        for stat_key, stat_val in b[category_id].items_lookup_and_delete_batch():
            stat_dev = stat_key >> 32
            stat_cat = stat_key & ((1 << 32) - 1)
            for subm_bitmap, subm_field in submission_bitmaps.items():
                if stat_cat & subm_bitmap == subm_bitmap:
                    category_stats[stat_dev][subm_field] = stat_val
                    break

    for category_id, category_stats in {"completion_stats_dev": stats_dev, "completion_stats_q": stats_q, "completion_stats_drv": stats_drv}.items():
        for stat_key, stat_val in b[category_id].items_lookup_and_delete_batch():
            stat_dev = stat_key >> 32
            stat_cat = stat_key & ((1 << 32) - 1)
            for comp_bitmap, comp_field in completion_bitmaps.items():
                if stat_cat & comp_bitmap == comp_bitmap:
                    category_stats[stat_dev][comp_field] = stat_val
                    break


def callback_logs(ctx, data, size):
    e = b["logs"].event(data)
    logger.log(e.log_level, "ns:{} cpu:{:02d} {:32.32} {}:{} ({}) <- {}:{} ({}) nr_sector:{} rwbs:{} type:{} top:{}".format(e.timestamp, e.cpu, str(e.message, 'ascii'), e.dev, e.sector, BlockHelper.label_from_id(e.dev), e.old_dev, e.old_sector, BlockHelper.label_from_id(e.old_dev), e.nr_sector, str(e.rwbs, 'ascii'), bin(e.type), e.top))


def track_type(name, key=None):
    if name in ["submissions", "completions"]:
        if key:
            return TrackKey(dev=key.dev, sector=key.sector, type=key.type)
        else:
            return TrackKey
    elif name == "bmrqs":
        if key:
            return TrackBmrqKey(dev=key.dev, end_sector=key.end_sector, type=key.type)
        else:
            return TrackBmrqKey
    elif name == "splits":
        if key:
            return TrackSplitKey(dev=key.dev, end_sector=key.end_sector, type=key.type)
        else:
            return TrackSplitKey
    raise Exception("Unknown type {}".format(name))


def gc():
    uptime_ns = 0
    with open('/proc/uptime', 'r') as f:
        uptime_ns = float(f.read().strip().split(' ')[0]) * 1e9
    if uptime_ns == 0:
        return
    for m in ["submissions", "completions", "bmrqs", "splits"]:
        logger.info("Items in {}: {}".format(m, len(b[m].items())))
        expired_keys = list()
        for key, val in b[m].items_lookup_batch():
            if uptime_ns - val.start_ns > (60 * 1e9):
                expired_keys.append(track_type(m, key))
        len_expired_keys = len(expired_keys)
        if len_expired_keys > 0:
            expired_key_t = track_type(m) * len_expired_keys
            logger.info("Items to delete in {}: {}".format(m, len_expired_keys))
            b[m].items_delete_batch(expired_key_t(*expired_keys))


if TrackLogLevel[args.log_level] != TrackLogLevel.NOTSET:
    b["logs"].open_ring_buffer(callback_logs)

reset_stats()

while True:
    try:
        if TrackLogLevel[args.log_level] != TrackLogLevel.NOTSET:
            b.ring_buffer_poll(200)
        if args.no_header is False:
            print_header()
        collect_stats()
        print_stats()
        reset_stats()
        if int(time.time()) % 60 == 0:
            gc()
        time.sleep(args.interval)
    except KeyboardInterrupt:
        sys.exit()
