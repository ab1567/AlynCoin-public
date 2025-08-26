import json
import time
from pathlib import Path
from prometheus_client import start_http_server, Gauge

PROOF_FILE = Path(__file__).with_name('proof_of_reserve.json')
locked_gauge = Gauge('alyn_locked', 'Total ALYN locked')
minted_gauge = Gauge('walyn_minted', 'Total WALYN minted')


def read_state():
    if PROOF_FILE.exists():
        with open(PROOF_FILE) as f:
            return json.load(f)
    return {'locked':0,'minted':0}


def main():
    start_http_server(8000)
    while True:
        state = read_state()
        locked_gauge.set(state.get('locked', 0))
        minted_gauge.set(state.get('minted', 0))
        time.sleep(5)


if __name__ == '__main__':
    main()
