import sys
import click
from clickclick import secho
import yaml
from datetime import timedelta
import time
import threading

CONFIG_DIR_PATH = click.get_app_dir('sevenseconds')
START_TIME = time.time()
THREADDATA = threading.local()
PATTERNLENGTH = 25
QUITE = False


class ActionOnExit:
    def __init__(self, msg, **kwargs):
        self.msg_args = kwargs
        self.msg = click.style(msg.format(**kwargs), bold=True)
        self.errors = []
        self._suppress_exception = False
        self.ok_msg = ' OK'
        self.call_time = time.time()
        if not QUITE:
            self._print(' ...')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if not self.errors:
                self.msg += click.style(' {}'.format(self.ok_msg), fg='green', bold=True)
        elif not self._suppress_exception:
            self.msg += click.style(' EXCEPTION OCCURRED: {}'.format(exc_val), fg='red', bold=True)
        if not QUITE or self.errors:
            self._print(' +{:.6f}s'.format(time.time() - self.call_time))

    def fatal_error(self, msg, **kwargs):
        self._suppress_exception = True  # Avoid printing "EXCEPTION OCCURRED: -1" on exit
        self.error(msg, **kwargs)
        self._print(' +{:.6f}s'.format(time.time() - self.call_time))
        sys.exit(1)

    def error(self, msg, **kwargs):
        self.msg += click.style(' {}'.format(msg), fg='red', bold=True, **kwargs)
        self.errors.append(msg)

    def progress(self):
        self.msg += click.style(' .'.format())

    def warning(self, msg, **kwargs):
        self.msg += click.style(' {}'.format(msg), fg='yellow', bold=True, **kwargs)
        self.errors.append(msg)

    def ok(self, msg):
        self.ok_msg = ' {}'.format(msg)

    def _print(self, suffix=''):
        elapsed_seconds = time.time() - START_TIME
        # using timedelta here for convenient default formatting
        elapsed = timedelta(seconds=elapsed_seconds)
        print('[{} | {}] {}{}'.format(
            getattr(THREADDATA, 'name', 'GLOBAL').rjust(PATTERNLENGTH),
            elapsed,
            self.msg,
            suffix))


def _secho(msg, **kwargs):
    elapsed_seconds = time.time() - START_TIME
    # using timedelta here for convenient default formatting
    elapsed = timedelta(seconds=elapsed_seconds)
    secho('[{} | {}] {}'.format(getattr(THREADDATA, 'name', 'GLOBAL').rjust(PATTERNLENGTH), elapsed, msg), **kwargs)


def error(msg, **kwargs):
    _secho(msg, fg='red', bold=True, **kwargs)


def fatal_error(msg, **kwargs):
    error(msg, **kwargs)
    sys.exit(1)


def ok(msg=' OK', **kwargs):
    if not QUITE:
        _secho(msg, fg='green', bold=True, **kwargs)


def warning(msg, **kwargs):
    _secho(msg, fg='yellow', bold=True, **kwargs)


def info(msg):
    if not QUITE:
        _secho(msg, fg='blue', bold=True)


def substitute_template_vars(data, context: dict):
    '''
    >>> substitute_template_vars({'test': {'foo': {'foobar': 'dummy-{bob}'}}},
    ...                          {'bob': 'BOB-REPLACE', 'ann': 'ANN-REPLACE'})
    {'test': {'foo': {'foobar': 'dummy-BOB-REPLACE'}}}
    '''
    serialized = yaml.safe_dump(data)
    data = yaml.safe_load(serialized)
    for k, v in data.items():
        if isinstance(v, str):
            data[k] = v.format(**context)
        elif isinstance(v, dict):
            data[k] = substitute_template_vars(v, context)
    return data
