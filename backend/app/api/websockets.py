"""WebSocket Manager for Live Real-Time SOC Dashboard Updates."""

import asyncio
import json
import logging
from typing import List, Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger("WebSocketManager")
ws_router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections and thread-safe event dispatching."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Remaining clients: {len(self.active_connections)}")

    async def broadcast_json(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                logger.warning(f"Failed to send to client: {e}")
                disconnected.append(connection)

        for dead_conn in disconnected:
            self.disconnect(dead_conn)

    def dispatch_from_thread(self, event_type: str, data: Dict[str, Any]):
        """Thread-safe dispatch from background sniffer/ML threads into the async event loop."""
        if not self.active_connections or not self._loop or self._loop.is_closed():
            return

        payload = {
            "type": event_type,
            "data": data
        }

        try:
            asyncio.run_coroutine_threadsafe(self.broadcast_json(payload), self._loop)
        except Exception as e:
            logger.debug(f"Could not dispatch event {event_type}: {e}")


ws_manager = ConnectionManager()


@ws_router.websocket("/ws/soc")
async def websocket_soc_endpoint(websocket: WebSocket):
    """Real-time bidirectional WebSocket endpoint for SOC dashboard clients."""
    await ws_manager.connect(websocket)
    try:
        # Send initial handshake confirmation
        await websocket.send_text(json.dumps({
            "type": "CONNECTION_ESTABLISHED",
            "data": {"status": "CONNECTED", "service": "SOC AI Intrusion Detection Real-Time Stream"}
        }))

        while True:
            # Keepalive / handle client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG"}))

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)
