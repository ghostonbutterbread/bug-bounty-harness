"""Opt-in pytest guard for synthetic offline runs (not an OS sandbox)."""
import socket
import subprocess

import pytest


def blocked_network(*args, **kwargs):
    raise AssertionError('network blocked by offline test plugin')


def blocked_dns(*args, **kwargs):
    raise AssertionError('DNS blocked by offline test plugin')


def blocked_subprocess(*args, **kwargs):
    raise AssertionError('subprocess blocked by offline test plugin')


@pytest.fixture(autouse=True)
def offline_guard(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', blocked_dns)
    monkeypatch.setattr(socket, 'gethostbyname', blocked_dns)
    monkeypatch.setattr(socket.socket, 'connect', blocked_network)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked_network)
    monkeypatch.setattr(socket.socket, 'sendto', blocked_network)
    if hasattr(socket.socket, 'sendmsg'):
        monkeypatch.setattr(socket.socket, 'sendmsg', blocked_network)
    monkeypatch.setattr(subprocess, 'Popen', blocked_subprocess)
