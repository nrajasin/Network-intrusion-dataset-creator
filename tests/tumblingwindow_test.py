# unit test for tumbling window
#
# TODO: write tests for calculate_tumbling_window()

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
tw = TumblingWindow(5000, 10)


def test_inside_window():
    assert not tw.is_past_current_window(
        window_start_time_plus_sec_1, window_start_time, 1
    )


def test_time_past_window():
    assert tw.is_past_current_window(window_start_time_plus_min_1, window_start_time, 1)


def test_another_packet_ok():
    assert not (
        tw.is_past_current_window(window_start_time_plus_sec_1, window_start_time, 8)
    )


def test_one_packet_too_many():
    assert (
        tw.is_past_current_window(window_start_time_minus_sec_1, window_start_time, 10)
    ) == True


# should there be a method that says this value is before the window start time?
def test_time_before_start_window():
    assert tw.is_before_current_window(window_start_time_minus_min_1, window_start_time)


####


def test_same_tumbling_window():
    assert not tw.is_past_current_window(
        window_start_time_plus_sec_1, window_start_time, 2
    )

    assert (
        tw.calculate_tumbling_window(window_start_time_plus_sec_1, window_start_time, 2)
        == window_start_time
    )


def test_next_tumbling_window():
    assert tw.is_past_current_window(window_start_time_plus_sec_5, window_start_time, 2)
    # should go to the next window
    assert (
        tw.calculate_tumbling_window(window_start_time_plus_sec_5, window_start_time, 2)
        == window_start_time + 5000
    )
