from queue import Queue  # noqa (reexport)
from threading import Thread


class ThreadWorker(Thread):
    def __init__(self, queue, function):
        Thread.__init__(self)
        self.queue = queue
        self.function = function

    def run(self):
        while True:
            self.function(*self.queue.get())
            self.queue.task_done()
