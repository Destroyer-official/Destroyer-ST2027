import unittest

from network.connection import ConnectionManager


class _FakeWriter:
    def __init__(self):
        self.closed = False
        self.close_calls = 0

    def is_closing(self):
        return self.closed

    def close(self):
        self.close_calls += 1
        self.closed = True


class _FakeSession:
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.writer = _FakeWriter()
        self.cleanup_calls = 0

    def secure_cleanup(self):
        self.cleanup_calls += 1
        if not self.writer.is_closing():
            self.writer.close()


class _FakeOrchestrator:
    def __init__(self):
        self.forgotten = []

    def _forget_session_auth_key(self, peer_id):
        self.forgotten.append(peer_id)


class TestConnectionAliasCleanup(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.orchestrator = _FakeOrchestrator()
        self.manager = ConnectionManager(self.orchestrator)

    async def test_disconnect_removes_all_aliases_and_wipes_once(self):
        session = _FakeSession("192.0.2.10")
        self.manager._active_connections["[192.0.2.10]:4433"] = session
        self.manager._active_connections["192.0.2.10"] = session

        await self.manager.disconnect_peer("192.0.2.10")

        self.assertEqual(self.manager._active_connections, {})
        self.assertEqual(session.cleanup_calls, 1)
        self.assertEqual(session.writer.close_calls, 1)
        self.assertIn("192.0.2.10", self.orchestrator.forgotten)

    async def test_cleanup_does_not_double_close_aliases(self):
        session = _FakeSession("192.0.2.11")
        self.manager._active_connections["[192.0.2.11]:4433"] = session
        self.manager._active_connections["192.0.2.11"] = session

        await self.manager.cleanup()

        self.assertEqual(self.manager._active_connections, {})
        self.assertEqual(session.cleanup_calls, 1)
        self.assertEqual(session.writer.close_calls, 1)

    async def test_legacy_dict_connection_closes_socket(self):
        writer = _FakeWriter()
        self.manager._active_connections["legacy"] = {"socket": writer}

        await self.manager.disconnect_peer("legacy")

        self.assertEqual(self.manager._active_connections, {})
        self.assertEqual(writer.close_calls, 1)

    def test_max_active_count_counts_unique_sessions(self):
        first = _FakeSession("A")
        second = _FakeSession("B")
        self.manager._active_connections["a1"] = first
        self.manager._active_connections["a2"] = first
        self.assertEqual(self.manager._active_session_count(), 1)
        self.manager._active_connections["b1"] = second
        self.assertEqual(self.manager._active_session_count(), 2)


if __name__ == "__main__":
    unittest.main()
