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
        window_count_previous,
    ):
        self.logger.debug(
            "evaluating window fit: frame_time_epoch: %d start: %d length: %s",
            frame_time_epoch,
            window_start_time_previous,
            self.window_length_time,
        )
        outside_time = window_start_time_previous is None or (
            self.window_length_time is not None
            and frame_time_epoch >= window_start_time_previous + self.window_length_time
        )
        outside_packets = window_count_previous is None or (
            self.window_length_count is not None
            and window_count_previous >= self.window_length_count
        )
        return outside_time or outside_packets

    # calculate the new time offsets
    # frame_time_epoch - time in message in msec from epoch
    # first time slot is aligns with the first packet
    # return the calculated window parameters (time start and end) for the passed in time
    def calculate_tumbling_window(
        self,
        frame_time_epoch,
        window_start_time_previous,
        window_count_previous,
    ):
        self.logger.debug(
            "old window: frame_time_epoch: %d window start: %d time-span: %s window count: %s count-span %s",
            frame_time_epoch,
            window_start_time_previous,
            self.window_length_time,
            window_count_previous,
            self.window_length_count,
        )

        if self.is_outside_current_window(
            frame_time_epoch=frame_time_epoch,
            window_start_time_previous=window_count_previous,
            window_count_previous=window_count_previous,
        ):
            # move to the next window
            if window_start_time_previous is None:
                # first interval starts on the first packet. all others are locked to that
                window_start_time_new = frame_time_epoch
            elif (
                self.window_length_count is not None
                and window_count_previous >= self.window_length_count
            ):
                # we ended the window because of the max packet count
                window_start_time_new = frame_time_epoch
            else:
                # we ended the window because we are outside the time window
                window_start_time_new = (
                    window_start_time_previous + self.window_length_time
                )
            self.logger.debug(
                "new window: %d startTime: %d",
                window_start_time_new,
            )
        else:
            # return the same time if still in the window
            window_start_time_new = window_start_time_previous
            pass

        self.logger.debug(
            "new window: frame_time_epoch: %d prev start: %d new start %d ",
            frame_time_epoch,
            window_start_time_previous,
            window_start_time_new,
        )
        # return the calculated window parameters for the passed in time
        return window_start_time_new
