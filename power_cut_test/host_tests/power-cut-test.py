#----------------------------------------------------------------------------
#   The confidential and proprietary information contained in this file may
#   only be used by a person authorised under and to the extent permitted
#   by a subsisting licensing agreement from ARM Limited or its affiliates.
#
#          (C) COPYRIGHT 2016 ARM Limited or its affiliates.
#              ALL RIGHTS RESERVED
#
#   This entire notice must be reproduced on all copies of this file
#   and copies of this file may only be made by a person if such person is
#   permitted to do so under the terms of a subsisting license agreement
#   from ARM Limited or its affiliates.
#----------------------------------------------------------------------------

import mbed_host_tests as mht
# from mbed_host_tests import BaseHostTest,BaseHostTestAbstract
from time import time
import threading
import uuid
from random import uniform

POWER_CUT_TEST_STATE_START, \
POWER_CUT_TEST_STATE_ERASE, \
POWER_CUT_TEST_STATE_COPY_FIRMWARE, \
POWER_CUT_TEST_STATE_FIRMWARE_VALIDATION, \
POWER_CUT_TEST_STATE_END = range(5)

states = [ POWER_CUT_TEST_STATE_START,
           POWER_CUT_TEST_STATE_ERASE,
           POWER_CUT_TEST_STATE_COPY_FIRMWARE,
           POWER_CUT_TEST_STATE_FIRMWARE_VALIDATION,
           POWER_CUT_TEST_STATE_END ]

CutPoints = [] # lets generate some cut points

class JigAuto(mht.BaseHostTest):
    """ Power cut jig's host test harness template
        Configuration is required
    """
    NUM_CUT_POINTS = 100

    __result = None
    name = "bootloader_power_cut_test"
    def __init__(self):
        # self.__event_queue = None
        self.__timer = None
        self.__cutIdx = 0
        self.timestamp_sync = 0
        self.timestamp_start = 0
        self.timestamp_end = 0
        mht.BaseHostTest.__init__(self)

    def nextCutPoint(self):
        cutPoint = {'state': -1, 'delay': 0}

        print self.NUM_CUT_POINTS

        if (self.timestamp_start == 0):
            cutPoint['state'] = states[0]
        elif (self.timestamp_end == 0):
            cutPoint['state'] = states[-1]
        elif self.NUM_CUT_POINTS > 0:
            self.NUM_CUT_POINTS -= 1
            cutPoint['state'] = states[0]
            cutPoint['delay'] = int(uniform(0, self.timestamp_end - self.timestamp_start) * 1e6)

        return cutPoint

    def _callback_state_match(self, key, value, timestamp):
        if (self.timestamp_start == 0 and self.timestamp_sync != 0):
            self.timestamp_start = timestamp - self.timestamp_sync
        elif (self.timestamp_end == 0 and self.timestamp_sync != 0):
            self.timestamp_end = timestamp - self.timestamp_sync
        self.timestamp_sync = 0

        self.send_kv("go",0);

    def _callback_send_sync(self, key, value, timestamp):
        # wait for 200 ms then send a sync packet
        delayInSeconds = 200 * 1000 / 1e6 # 200 ms
        self.__timer = threading.Timer(delayInSeconds, self.send_sync).start()

    def _callback_result(self, key, value, timestamp):
        if self.NUM_CUT_POINTS == 0:
            self.__result = True
        else:
            self.__result = False
        self.notify_complete(self.__result);

    def send_init(self):
        cutPoint = self.nextCutPoint()
        self.send_kv("jig_state", cutPoint['state'])
        self.send_kv("jig_delay", cutPoint['delay'])
        self.send_kv("go",0);
        self.__cutIdx += 1

    def setup(self):
        # Register callback for message 'gimme_something' from DUT
        self.register_callback("pdwn", self._callback_state_match)
        self.register_callback("get_cut_point", self.cut_point_handler)
        self.register_callback("send_sync", self._callback_send_sync)
        self.register_callback("__sync", self.sync_handler, force=True)
        self.register_callback("__timeout", self.timeout_handler, force=True)
        self.register_callback("__version", self.version_handler, force=True)
        self.register_callback("__host_test_name", self.host_test_name_handler, force=True)
        self.register_callback("power_cut_test_end", self._callback_result)
        # Initialize your host test here
        # ...

    def result(self):
        # Define your test result here
        # Or use self.notify_complete(bool) to pass result anytime!
        return self.__result

    def teardown(self):
        # Release resources here after test is completed
        pass

    def cut_point_handler(self, key, value, timestamp):
        self.send_init()

    def sync_handler(self, key, value, timestamp):
        self.timestamp_sync = timestamp
        if (str(self.expect_uuid) == value):
            self.__got_sync = True
            self.__got_timeout = False
            self.__got_version = False
            self.__got_host_test_name = False

    def send_sync(self):
        self.expect_uuid = uuid.uuid4()
        self.send_kv("__sync", str(self.expect_uuid))
        self.__got_sync = False
        self.__got_timeout = False
        self.__got_version = False
        self.__got_host_test_name = False

    def timeout_handler(self, key, value, timestamp):
        self.__got_timeout = True

    def version_handler(self, key, value, timestamp):
        self.__got_version = True

    def host_test_name_handler(self, key, value, timestamp):
        self.__got_host_test_name = True
