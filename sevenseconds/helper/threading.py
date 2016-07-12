# Re-export Queue
from queue import Queue  # noqa
from threading import Thread
import traceback
from ..helper import error


class ThreadWorker(Thread):
    def __init__(self, queue, function):
        Thread.__init__(self)
        self.queue = queue
        self.function = function

    def run(self):
        while True:
            self.wrapper(*self.queue.get())
            self.queue.task_done()

    def wrapper(self, *args):
        try:
            self.function(*args)
        except Exception as e:
            error(traceback.format_exc())
            error(e)
