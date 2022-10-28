# Time based Tumbling window behavior

import logging


class TumblingWindow:
    def __init__(self, window_length_time, window_length_count):
        self.logger = logging.getLogger(__name__)
        # length of window in msec for time based windows
        self.window_length_time = window_length_time
        # length of window in packets for count based windows
        self.window_length_count = window_length_count

    # calculate the new time offsets
    # frame_time_epoch - time in message in msec from epoch
    # first time slot is aligns with the first packet
    # return the calculated window parameters for the passed in time
    def is_outside_current_window(
        self,
        frame_time_epoch,
        window_start_time_previous,
        window_end_time_previous,
        window_count_previous,
    ):
        self.logger.debug(
            "evaluating window fit: frame_time_epoch: %d start: %d stop: %d",
            frame_time_epoch,
            window_start_time_previous,
            window_end_time_previous,
            self.window_length_time,
        )
        return frame_time_epoch >= window_end_time_previous

    # calculate the new time offsets
    # frame_time_epoch - time in message in msec from epoch
    # first time slot is aligns with the first packet
    # return the calculated window parameters (time start and end) for the passed in time
    def calculate_tumbling_window(
        self,
        frame_time_epoch,
        window_start_time_previous,
        window_end_time_previous,
        window_count_previous,
    ):
        self.logger.debug(
            "old window: frame_time_epoch: %d start: %d stop: %d",
            frame_time_epoch,
            window_start_time_previous,
            window_end_time_previous,
            self.window_length_time,
        )

        if (
            window_end_time_previous is not None
            and frame_time_epoch < window_end_time_previous
        ):
            # return the same time if still in the window
            window_start_time_new = window_start_time_previous
            window_end_time_new = window_end_time_previous
            pass
        else:
            # move to the next window
            # first interval starts on the first packet. all others are locked to that
            if window_end_time_previous is None:
                window_start_time_new = frame_time_epoch
            else:
                window_start_time_new = window_end_time_previous
            window_end_time_new = window_start_time_new + self.window_length_time
            self.logger.debug(
                "new window: %d startTime: %d, stopTime: %d",
                window_start_time_new,
                window_end_time_new,
            )

        # return the calculated window parameters for the passed in time
        return (window_start_time_new, window_end_time_new)
