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

from collections import OrderedDict
import os
import glob


class BlockStack:

    def __init__(self):
        self._devices = OrderedDict()
        self._queues = OrderedDict()
        self._drivers = OrderedDict()

    @property
    def devices(self):
        if len(self._devices) == 0:
            for path in sorted(glob.glob("/sys/class/block/*"), reverse=True):
                device = BlockDevice(path)
                self._devices[device.id] = device
        return self._devices

    @property
    def queues(self):
        if len(self._queues) == 0:
            for device in self.devices.values():
                if device.is_request:
                    queue = BlockQueue(device)
                    self._queues[device.id] = queue
        return self._queues

    @property
    def drivers(self):
        if len(self._drivers) == 0:
            for device in self.devices.values():
                if device.is_request:
                    driver = BlockDriver(device)
                    self._drivers[device.id] = driver
        return self._drivers


class BlockHelper:

    @staticmethod
    def major(dev: int) -> int:
        return dev >> 20

    @staticmethod
    def minor(dev: int) -> int:
        return dev & ((1 << 20) - 1)

    @staticmethod
    def id(major: int, minor: int) -> int:
        return (major << 20) | minor

    @staticmethod
    def label(path) -> str:
        label = None
        with open(path, 'r') as f:
            label = f.read().strip()
        if len(label) == 0:
            raise Exception("Could not extract label from file: {}".format(path))
        return label

    @staticmethod
    def id_from_label(label) -> int:
        parts = label.split(":")
        if len(parts) != 2:
            raise Exception("Incorrect label format: {}".format(label))
        return BlockHelper.id(int(parts[0]), int(parts[1]))

    @staticmethod
    def label_from_id(id: int) -> str:
        return "{}:{}".format(BlockHelper.major(id), BlockHelper.minor(id))

class BlockComponent:

    def is_device(self):
        return False

    def is_queue(self):
        return False

    def is_driver(self):
        return False


class BlockDevice(BlockComponent):

    def __init__(self, path):
        super()
        self.path = os.path.realpath(path)
        self._name = None
        self._is_dm = None
        self._is_partition = None
        self._is_request = None
        self._label = None
        self._major = None
        self._minor = None
        self._id = None
        self._key = None
        self._slaves = list()
        self._holders = list()
        self._parent = None

    def is_device(self):
        return True

    @property
    def name(self):
        if self._name is None:
            self._name = os.path.basename(self.path)
        return self._name

    @property
    def is_dm(self):
        if self._is_dm is None:
            self._is_dm = os.path.exists(os.path.join(self.path, "dm"))
        return self._is_dm

    @property
    def is_partition(self):
        if self._is_partition is None:
            self._is_partition = False
            p = os.path.join(self.path, "partition")
            if os.path.exists(p):
                self._is_partition = True
        return self._is_partition

    @property
    def is_request(self):
        if self._is_request is None:
            self._is_request = os.path.exists(os.path.join(self.path, "mq"))
        return self._is_request

    @property
    def label(self):
        if self._label is None:
            self._label = BlockHelper.label(os.path.join(self.path, 'dev'))
        return self._label

    @property
    def major(self) -> int:
        if self._major is None:
            self._major = int(self.label.split(":")[0])
        return self._major

    @property
    def minor(self) -> int:
        if self._minor is None:
            self._minor = int(self.label.split(":")[1])
        return self._minor

    @property
    def id(self) -> int:
        if self._id is None:
            self._id = BlockHelper.id(self.major, self.minor)
        return self._id

    @property
    def key(self):
        if self._key is None:
            self._key = "block[{}]".format(self.id)
        return self._key

    @property
    def slaves(self):
        if len(self._slaves) == 0:
            for path in glob.glob(os.path.join(self.path, "slaves", "*", "dev")):
                slave_label = BlockHelper.label(path)
                slave_id = BlockHelper.id_from_label(slave_label)
                self._slaves.append(slave_id)
        return self._slaves

    @property
    def holders(self):
        if len(self._holders) == 0:
            for path in glob.glob(os.path.join(self.path, "holders", "*", "dev")):
                holder_label = BlockHelper.label(path)
                holder_id = BlockHelper.id_from_label(holder_label)
                self._holders.append(holder_id)
        return self._holders

    # partition parent
    @property
    def parent(self):
        if self.is_partition:
            if self._parent is None:
                parent_label = BlockHelper.label(os.path.join(os.path.dirname(self.path), "dev"))
                self._parent = BlockHelper.id_from_label(parent_label)
        return self._parent


class BlockQueue(BlockComponent):

    def __init__(self, device: BlockDevice):
        super()
        self.device = device
        self._key = None

    def is_queue(self) -> bool:
        return True

    @property
    def key(self):
        if self._key is None:
            self._key = "queue[{}]".format(self.device.id)
        return self._key


class BlockDriver(BlockComponent):

    def __init__(self, device: BlockDevice):
        super()
        self.device = device
        self._key = None

    def is_driver(self) -> bool:
        return True

    @property
    def key(self):
        if self._key is None:
            self._key = "driver[{}]".format(self.device.id)
        return self._key