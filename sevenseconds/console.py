import click


def action(msg, **kwargs):
    click.secho(msg.format(**kwargs), nl=False, bold=True)


def ok(msg=' OK', **kwargs):
    click.secho(msg, fg='green', bold=True, **kwargs)


def error(msg, **kwargs):
    click.secho(' {}'.format(msg), fg='red', bold=True, **kwargs)


def warning(msg, **kwargs):
    click.secho(' {}'.format(msg), fg='yellow', bold=True, **kwargs)


def info(msg):
    click.secho('{}'.format(msg), fg='blue', bold=True)


class Action:

    def __init__(self, msg, **kwargs):
        self.msg = msg
        self.msg_args = kwargs
        self.errors = []

    def __enter__(self):
        action(self.msg, **self.msg_args)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if not self.errors:
                ok()
        else:
            error('EXCEPTION OCCURRED: {}'.format(exc_val))

    def error(self, msg, **kwargs):
        error(msg, **kwargs)
        self.errors.append(msg)

    def progress(self):
        click.secho(' .', nl=False)


class AliasedGroup(click.Group):
    """
    Click group which allows using abbreviated commands
    """
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))
