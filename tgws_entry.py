"""Watcher-compatible headless entry point, also used for proxy-only builds."""
import contextlib
import io
import json
import logging
import re
import sys
from pathlib import Path
from proxy import __version__
from proxy.tg_ws_proxy import main


class PoolRefillFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.seen = set()

    def filter(self, record):
        match = re.match(r'^WS pool refill failed for (DC\d+[tm]*), retry in ', record.getMessage())
        if record.levelno != logging.INFO or not match:
            return True
        dc = match.group(1)
        if dc in self.seen:
            return False
        self.seen.add(dc)
        return True


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--watcher-probe':
        output = Path(sys.argv[2])
        sys.argv = [sys.argv[0], '--help']
        text = io.StringIO()
        with contextlib.redirect_stdout(text):
            try:
                main()
            except SystemExit as exc:
                if exc.code != 0:
                    raise
        Path(output).write_text(json.dumps({'contract': 1, 'version': __version__, 'help': text.getvalue()}), encoding='utf-8')
    else:
        logging.getLogger('tg-mtproto-proxy').addFilter(PoolRefillFilter())
        main()
