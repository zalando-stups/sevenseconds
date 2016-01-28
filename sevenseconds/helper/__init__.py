import sys
import click
from clickclick import secho
import yaml

CONFIG_DIR_PATH = click.get_app_dir('sevenseconds')
PROGNAME = 'GLOBAL'


class ActionOnExit:
    def __init__(self, msg, **kwargs):
        self.msg_args = kwargs
        self.msg = click.style(msg.format(**kwargs), bold=True)
        self.errors = []
        self._suppress_exception = False
        self.ok_msg = ' OK'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if not self.errors:
                self.msg += click.style(' {}'.format(self.ok_msg), fg='green', bold=True)
        elif not self._suppress_exception:
            self.msg += click.style(' EXCEPTION OCCURRED: {}'.format(exc_val), fg='red', bold=True)
        print('[{:>15}] {}'.format(PROGNAME, self.msg))

    def fatal_error(self, msg, **kwargs):
        self._suppress_exception = True  # Avoid printing "EXCEPTION OCCURRED: -1" on exit
        self.error(msg, **kwargs)
        print('[{:>15}] {}'.format(PROGNAME, self.msg))
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


def error(msg, **kwargs):
    secho('[{:>15}] {}'.format(PROGNAME, msg), fg='red', bold=True, **kwargs)


def fatal_error(msg, **kwargs):
    error('[{:>15}] {}'.format(PROGNAME, msg), **kwargs)
    sys.exit(1)


def warning(msg, **kwargs):
    secho('[{:>15}] {}'.format(PROGNAME, msg), fg='yellow', bold=True, **kwargs)


def info(msg):
    secho('[{:>15}] {}'.format(PROGNAME, msg), fg='blue', bold=True)


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
