import argparse

RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

class ColoredSelectiveDefaultsHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def __init__(self, *args, **kwargs):
        kwargs['max_help_position'] = 50  # default is 24; increase to shift help text
        super().__init__(*args, **kwargs)

    def _get_help_string(self, action):
        help_text = action.help or ''
        help_text = f'{GREEN}{help_text}{RESET}'
        if (
            '%(default)' not in help_text and
            action.default is not None and
            action.default is not argparse.SUPPRESS and
            not isinstance(action, argparse._StoreTrueAction) and
            not isinstance(action, argparse._StoreFalseAction)
        ):
            help_text += f' (default: {RED}{action.default}{RESET})'
        return help_text

    def format_help(self):
        help_text = super().format_help()

        # Indent description (usually on the first line) with 4 spaces
        lines = help_text.splitlines()

        return "\n".join(lines)

