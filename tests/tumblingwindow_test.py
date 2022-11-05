# unit test for tumblingwindow.py
# pytest all test methods are test_*() or *_test()
# __init__.py tells pytest this isn't the root

from unittest import TestCase
from tumblingwindow import TumblingWindow
import time
from loggingconfig import load_logging

load_logging()

one_minute_msec = 60 * 1000
five_minute_msec = one_minute_msec * 5
six_minute_msec = one_minute_msec * 6
one_hour_msec = one_minute_msec * 60
now = time.time()
window_start_time = now - one_hour_msec
window_start_time_plus_min_1 = window_start_time + one_minute_msec
window_start_time_minus_min_1 = window_start_time - one_minute_msec
window_start_time_minus_sec_1 = window_start_time - 1000
window_start_time_plus_sec_1 = window_start_time + 1000
window_start_time_plus_sec_5 = window_start_time + 5000
# windows is 5000msec or 10 packets
window_size_msec = 5000
packet_num_max = 10
tw = TumblingWindow(window_size_msec, packet_num_max)

# 1000 msec is less that 5000 msec window
def test_inside_window():
    assert not tw.is_past_current_window(
        window_start_time_plus_sec_1, window_start_time, 1
    )


# 60000 msec is greater than 5000 msec
def test_time_past_window():
    assert tw.is_past_current_window(window_start_time_plus_min_1, window_start_time, 1)


# 8+1 packets is < max packets of 10
def test_another_packet_ok():
    assert not (
        tw.is_past_current_window(
            window_start_time_plus_sec_1, window_start_time, packet_num_max - 2
        )
    )


# 10+1 packets is > 10 packets
def test_one_packet_too_many():
    assert (
        tw.is_past_current_window(
            window_start_time_minus_sec_1, window_start_time, packet_num_max
        )
    ) == True


# should there be a method that says this value is before the window start time?
def test_time_before_start_window():
    assert tw.is_before_current_window(window_start_time_minus_min_1, window_start_time)


####


def test_same_tumbling_window():
    assert not tw.is_past_current_window(
        window_start_time_plus_sec_1, window_start_time, packet_num_max / 2
    )

    assert (
        tw.calculate_tumbling_window(
            window_start_time_plus_sec_1, window_start_time, packet_num_max / 2
        )
        == window_start_time
    )


def test_next_tumbling_window():
    assert tw.is_past_current_window(
        window_start_time_plus_sec_5, window_start_time, packet_num_max / 2
    )
    # should go to the next window
    assert (
        tw.calculate_tumbling_window(
            window_start_time_plus_sec_5, window_start_time, packet_num_max / 2
        )
        == window_start_time + window_size_msec
    )
