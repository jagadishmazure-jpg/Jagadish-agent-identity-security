import copy

import pytest

from idsec import detections, inventory
from idsec import graph as gmod


@pytest.fixture(scope="session")
def base_inv():
    return inventory.load()


@pytest.fixture
def inv(base_inv):
    """A private copy each test may change."""
    return copy.deepcopy(base_inv)


@pytest.fixture(scope="session")
def g(base_inv):
    return gmod.build(base_inv)


@pytest.fixture(scope="session")
def results(base_inv, g):
    return detections.run(base_inv, g)


@pytest.fixture(scope="session")
def found(results):
    return {(f.rule, f.subject) for r in results for f in r.findings}


def pid(inv, upn_or_name):
    """Principal ID by UPN prefix or display name."""
    for p in inv.principals.values():
        if p.upn.split("@")[0] == upn_or_name or p.upn == upn_or_name or p.name == upn_or_name:
            return p.id
    raise KeyError(upn_or_name)


def rescan(inv):
    g = gmod.build(inv)
    return {(f.rule, f.subject) for r in detections.run(inv, g) for f in r.findings}
