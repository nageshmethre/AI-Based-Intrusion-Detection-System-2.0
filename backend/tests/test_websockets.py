"""Phase 7 WebSocket Real-Time Integration Verification Test."""

import sys
import asyncio
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.api.websockets import ConnectionManager, ws_manager


class MockWebSocket:
    """Mock WebSocket for unit testing broadcast dispatch."""
    def __init__(self):
        self.messages = []
        self.closed = False

    async def accept(self):
        pass

    async def send_text(self, text: str):
        self.messages.append(json.loads(text))

    async def close(self):
        self.closed = True


async def async_test_websocket_manager():
    print("Testing ConnectionManager broadcast and message format...")
    manager = ConnectionManager()
    loop = asyncio.get_running_loop()
    manager.set_loop(loop)

    mock_client1 = MockWebSocket()
    mock_client2 = MockWebSocket()

    await manager.connect(mock_client1)
    await manager.connect(mock_client2)
    assert len(manager.active_connections) == 2

    # Broadcast test event
    test_pulse = {
        "timestamp": "14:50:00",
        "packets_per_sec": 142,
        "bytes_per_sec": 48200
    }
    await manager.broadcast_json({"type": "TRAFFIC_PULSE", "data": test_pulse})

    assert len(mock_client1.messages) == 1
    assert mock_client1.messages[0]["type"] == "TRAFFIC_PULSE"
    assert mock_client1.messages[0]["data"]["packets_per_sec"] == 142

    assert len(mock_client2.messages) == 1
    assert mock_client2.messages[0]["type"] == "TRAFFIC_PULSE"

    # Test thread-safe dispatch
    manager.dispatch_from_thread("NEW_ALERT", {"title": "Test Thread Alert", "severity": "HIGH"})
    await asyncio.sleep(0.05) # Allow coroutine to run

    assert len(mock_client1.messages) == 2
    assert mock_client1.messages[1]["type"] == "NEW_ALERT"
    assert mock_client1.messages[1]["data"]["severity"] == "HIGH"

    # Disconnect
    manager.disconnect(mock_client1)
    assert len(manager.active_connections) == 1
    print("✓ WebSocket ConnectionManager and thread-safe dispatch validated successfully!")


def test_websockets():
    asyncio.run(async_test_websocket_manager())


if __name__ == "__main__":
    test_websockets()
    print("\n--- Phase 7 Verification Passed Successfully! ---")
