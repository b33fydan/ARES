"""Visual Emitter — WebSocket server for streaming ARES events to nw_wrld.

Session 029: Streams typed JSON events over WebSocket to connected
visualization clients. Events are produced by ScenarioReplayer and
sent with real-time timing delays for live visual playback.

Public API:
    VisualEmitter  — WebSocket server; call start(), stream(), stop()
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Set, Tuple

import websockets
from websockets.server import WebSocketServerProtocol

from ares.visual.events import VisualEvent

logger = logging.getLogger("ares.visual.emitter")


class VisualEmitter:
    """WebSocket server that streams ARES visual events.

    Usage:
        emitter = VisualEmitter(host="localhost", port=8765)
        events = replayer.replay(scenario)
        await emitter.start()
        await emitter.stream(events)
        await emitter.stop()

    Args:
        host: Hostname to bind to.
        port: Port to bind to.
    """

    def __init__(self, host: str = "localhost", port: int = 8765) -> None:
        self._host = host
        self._port = port
        self._clients: Set[WebSocketServerProtocol] = set()
        self._server: object = None

    @property
    def host(self) -> str:
        """Server hostname."""
        return self._host

    @property
    def port(self) -> int:
        """Server port."""
        return self._port

    @property
    def client_count(self) -> int:
        """Number of connected clients."""
        return len(self._clients)

    async def _handler(self, websocket: WebSocketServerProtocol) -> None:
        """Handle a new WebSocket connection."""
        self._clients.add(websocket)
        logger.info("Client connected (%d total)", len(self._clients))
        try:
            async for _message in websocket:
                pass  # We only send, not receive
        finally:
            self._clients.discard(websocket)
            logger.info("Client disconnected (%d remaining)", len(self._clients))

    async def start(self) -> None:
        """Start the WebSocket server."""
        self._server = await websockets.serve(
            self._handler,
            self._host,
            self._port,
        )
        logger.info("VisualEmitter started on ws://%s:%d", self._host, self._port)

    async def stream(
        self,
        events: Tuple[VisualEvent, ...],
        realtime: bool = True,
    ) -> None:
        """Stream events to all connected clients.

        If realtime=True, sleeps between events based on timestamp_ms deltas.
        If realtime=False, sends all events immediately.

        Args:
            events: Tuple of VisualEvents to stream.
            realtime: Whether to respect timing delays.
        """
        prev_ts = 0
        for event in events:
            if realtime and event.timestamp_ms > prev_ts:
                delay_s = (event.timestamp_ms - prev_ts) / 1000.0
                await asyncio.sleep(delay_s)

            payload = json.dumps(event.to_dict())
            if self._clients:
                await asyncio.gather(
                    *(client.send(payload) for client in self._clients),
                    return_exceptions=True,
                )

            logger.debug("Sent %s (t=%dms)", event.event_type, event.timestamp_ms)
            prev_ts = event.timestamp_ms

    async def stop(self) -> None:
        """Shutdown the server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            logger.info("VisualEmitter stopped")

    def __repr__(self) -> str:
        return f"VisualEmitter(ws://{self._host}:{self._port})"
