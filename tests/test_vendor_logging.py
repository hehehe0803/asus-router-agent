import asyncio
import io
import logging
import uuid

from router_agent.vendor_logging import SUPPRESS_VENDOR


def test_lazy_children_are_silenced_and_host_logging_unchanged(caplog):
    caplog.set_level(logging.DEBUG)
    parent = logging.getLogger('asusrouter')
    before = (list(parent.handlers), parent.propagate)
    token = SUPPRESS_VENDOR.set(True)
    try:
        logging.getLogger('asusrouter.lazy.' + uuid.uuid4().hex).error('private-token')
        logging.getLogger('host.public').error('host-visible')
        assert 'private-token' not in caplog.text
        assert 'host-visible' in caplog.text
    finally:
        SUPPRESS_VENDOR.reset(token)
    assert (parent.handlers, parent.propagate) == before


def test_preexisting_vendor_handlers_restored_and_nested_scopes():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger('asusrouter.preexisting.' + uuid.uuid4().hex)
    logger.addHandler(handler)
    logger.propagate = False
    first = SUPPRESS_VENDOR.set(True)
    second = SUPPRESS_VENDOR.set(True)
    try:
        logger.error('private-token')
        SUPPRESS_VENDOR.reset(second)
        logging.getLogger(logger.name + '.lazy').error('private-child')
        assert not stream.getvalue()
    finally:
        SUPPRESS_VENDOR.reset(first)
    assert logger.handlers == [handler] and logger.propagate is False
    logger.error('outside-scope')
    assert stream.getvalue().strip() == 'outside-scope'
    logger.removeHandler(handler)


def test_unrelated_async_context_logging_still_emits(caplog):
    caplog.set_level(logging.DEBUG)
    async def run():
        ready = asyncio.Event()
        async def host():
            await ready.wait()
            logging.getLogger('host.async').warning('host-task-visible')
        task = asyncio.create_task(host())
        token = SUPPRESS_VENDOR.set(True)
        try:
            ready.set()
            await task
        finally:
            SUPPRESS_VENDOR.reset(token)
    asyncio.run(run())
    assert 'host-task-visible' in caplog.text
