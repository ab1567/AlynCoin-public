import json
from pathlib import Path
import click

PROOF_FILE = Path(__file__).with_name('proof_of_reserve.json')


def load_state():
    if PROOF_FILE.exists():
        with open(PROOF_FILE) as f:
            return json.load(f)
    return {"locked":0, "minted":0, "burned":0, "released":0}


def save_state(state):
    with open(PROOF_FILE, 'w') as f:
        json.dump(state, f, indent=2)


@click.group()
def cli():
    """Simple WALYN bridge CLI"""
    pass


@cli.command()
@click.argument('evm_addr')
@click.argument('amount', type=int)
def lock(evm_addr, amount):
    """Record a lock on Alyn chain"""
    state = load_state()
    state['locked'] += amount
    save_state(state)
    click.echo(f"Locked {amount} for {evm_addr}")


@cli.command()
@click.option('--tx', 'tx_hash')
def mint(tx_hash):
    """Mint WALYN based on lock tx"""
    state = load_state()
    state['minted'] += state.get('pending', 0)
    save_state(state)
    click.echo(f"Mint submitted for {tx_hash}")


@cli.command()
@click.argument('amount', type=int)
def burn(amount):
    """Burn WALYN to release on Alyn"""
    state = load_state()
    state['burned'] += amount
    save_state(state)
    click.echo(f"Burned {amount}")


@cli.command()
@click.option('--tx', 'tx_hash')
def release(tx_hash):
    """Release ALYN based on burn tx"""
    state = load_state()
    state['released'] += state.get('pending_release', 0)
    save_state(state)
    click.echo(f"Release submitted for {tx_hash}")


@cli.command()
def stats():
    """Show proof-of-reserve stats"""
    state = load_state()
    click.echo(json.dumps(state, indent=2))


if __name__ == '__main__':
    cli()
