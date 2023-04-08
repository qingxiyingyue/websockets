from __future__ import annotations

import asyncio
import socket
import ssl
from typing import Any, Optional, Sequence, Type, Union

from ..client import ClientProtocol
from ..datastructures import HeadersLike
from ..extensions.base import ClientExtensionFactory
from ..extensions.permessage_deflate import enable_client_permessage_deflate
from ..headers import validate_subprotocols
from ..http import USER_AGENT
from ..http11 import Response
from ..protocol import CONNECTING, OPEN, Event
from ..typing import LoggerLike, Origin, Subprotocol
from ..uri import parse_uri
from .compatibility import asyncio_timeout
from .connection import Connection


__all__ = ["connect", "unix_connect", "ClientConnection"]


class ClientConnection(Connection):
    """
    :mod:`asyncio` implementation of a WebSocket client connection.

    :class:`ClientConnection` provides :meth:`recv` and :meth:`send` coroutines
    for receiving and sending messages.

    It supports asynchronous iteration to receive messages::

        async for message in websocket:
            await process(message)

    The iterator exits normally when the connection is closed with close code
    1000 (OK) or 1001 (going away) or without a close code. It raises a
    :exc:`~websockets.exceptions.ConnectionClosedError` when the connection is
    closed with any other code.

    Args:
        protocol: Sans-I/O connection.
        close_timeout: Timeout for closing the connection in seconds.

    """

    def __init__(
        self,
        socket: socket.socket,
        protocol: ClientProtocol,
        *,
        close_timeout: Optional[float] = 10,
    ) -> None:
        self.protocol: ClientProtocol
        self.response_rcvd = asyncio.Event()
        super().__init__(
            protocol,
            close_timeout=close_timeout,
        )

    async def handshake(
        self,
        additional_headers: Optional[HeadersLike] = None,
        user_agent_header: Optional[str] = USER_AGENT,
    ) -> None:
        """
        Perform the opening handshake.

        """
        async with self.send_context(expected_state=CONNECTING):
            self.request = self.protocol.connect()
            if additional_headers is not None:
                self.request.headers.update(additional_headers)
            if user_agent_header is not None:
                self.request.headers["User-Agent"] = user_agent_header
            self.protocol.send_request(self.request)

        try:
            await self.response_rcvd.wait()
        except asyncio.CancelledError:
            self.close_transport()
            await self.recv_events_task
            raise

        if self.response is None:
            self.close_transport()
            await self.recv_events_task
            raise ConnectionError("connection closed during handshake")

        if self.protocol.state is not OPEN:
            try:
                async with asyncio_timeout(self.close_timeout):
                    await self.recv_events_task
            except TimeoutError:
                pass
            self.close_transport()
            await self.recv_events_task

        if self.protocol.handshake_exc is not None:
            raise self.protocol.handshake_exc

    def process_event(self, event: Event) -> None:
        """
        Process one incoming event.

        """
        # First event - handshake response.
        if self.response is None:
            assert isinstance(event, Response)
            self.response = event
            self.response_rcvd.set()
        # Later events - frames.
        else:
            super().process_event(event)

    def recv_events(self) -> None:
        """
        Read incoming data from the socket and process events.

        """
        try:
            super().recv_events()
        finally:
            # If the connection is closed during the handshake, unblock it.
            self.response_rcvd.set()


async def connect(
    uri: str,
    *,
    # TCP/TLS — unix and path are only for unix_connect()
    sock: Optional[socket.socket] = None,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_hostname: Optional[str] = None,
    unix: bool = False,
    path: Optional[str] = None,
    # WebSocket
    origin: Optional[Origin] = None,
    extensions: Optional[Sequence[ClientExtensionFactory]] = None,
    subprotocols: Optional[Sequence[Subprotocol]] = None,
    additional_headers: Optional[HeadersLike] = None,
    user_agent_header: Optional[str] = USER_AGENT,
    compression: Optional[str] = "deflate",
    # Timeouts
    open_timeout: Optional[float] = 10,
    close_timeout: Optional[float] = 10,
    # Limits
    max_size: Optional[int] = 2**20,
    # Logging
    logger: Optional[LoggerLike] = None,
    # Escape hatch for advanced customization
    create_connection: Optional[Type[ClientConnection]] = None,
    # Other keyword arguments are passed to loop.create_connection
    **kwargs: Any,
) -> ClientConnection:
    """
    Connect to the WebSocket server at ``uri``.

    This function returns a :class:`ClientConnection` instance, which you can
    use to send and receive messages.

    :func:`connect` may be used as a context manager::

        async with websockets.asyncio.client.connect(...) as websocket:
            ...

    The connection is closed automatically when exiting the context.

    Args:
        uri: URI of the WebSocket server.
        sock: Preexisting TCP socket. ``sock`` overrides the host and port
            from ``uri``. You may call :func:`socket.create_connection` (not
            :func:`asyncio.create_connection`) to create a suitable TCP socket.
        ssl_context: Configuration for enabling TLS on the connection.
        server_hostname: Host name for the TLS handshake. ``server_hostname``
            overrides the host name from ``uri``.
        origin: Value of the ``Origin`` header, for servers that require it.
        extensions: List of supported extensions, in order in which they
            should be negotiated and run.
        subprotocols: List of supported subprotocols, in order of decreasing
            preference.
        additional_headers (HeadersLike | None): Arbitrary HTTP headers to add
            to the handshake request.
        user_agent_header: Value of  the ``User-Agent`` request header.
            It defaults to ``"Python/x.y.z websockets/X.Y"``.
            Setting it to :obj:`None` removes the header.
        compression: The "permessage-deflate" extension is enabled by default.
            Set ``compression`` to :obj:`None` to disable it. See the
            :doc:`compression guide <../../topics/compression>` for details.
        open_timeout: Timeout for opening the connection in seconds.
            :obj:`None` disables the timeout.
        close_timeout: Timeout for closing the connection in seconds.
            :obj:`None` disables the timeout.
        max_size: Maximum size of incoming messages in bytes.
            :obj:`None` disables the limit.
        logger: Logger for this client.
            It defaults to ``logging.getLogger("websockets.client")``.
            See the :doc:`logging guide <../../topics/logging>` for details.
        create_connection: Factory for the :class:`ClientConnection` managing
            the connection. Set it to a wrapper or a subclass to customize
            connection handling.

    Any other keyword arguments are passed the event loop's
    :meth:`~asyncio.loop.create_connection` method.

    For example, you can set ``host`` and ``port`` to connect to a different
    host and port from those found in ``uri``. This only changes the destination
    of the TCP connection. The host name from ``uri`` is still used in the TLS
    handshake for secure connections and in the ``Host`` header.

    Raises:
        InvalidURI: If ``uri`` isn't a valid WebSocket URI.
        OSError: If the TCP connection fails.
        InvalidHandshake: If the opening handshake fails.
        TimeoutError: If the opening handshake times out.

    """

    # Process parameters

    wsuri = parse_uri(uri)
    if not wsuri.secure and ssl_context is not None:
        raise TypeError("ssl_context argument is incompatible with a ws:// URI")

    ssl: Union[bool, Optional[ssl.SSLContext]] = ssl_context
    if wsuri.secure:
        if ssl is None:
            ssl = True
        if server_hostname is None:
            server_hostname = wsuri.host

    if unix:
        if path is None and sock is None:
            raise TypeError("missing path argument")
        elif path is not None and sock is not None:
            raise TypeError("path and sock arguments are incompatible")
    else:
        assert path is None  # private argument, only set by unix_connect()

    if subprotocols is not None:
        validate_subprotocols(subprotocols)

    if compression == "deflate":
        extensions = enable_client_permessage_deflate(extensions)
    elif compression is not None:
        raise ValueError(f"unsupported compression: {compression}")

    protocol = ClientProtocol(
        wsuri,
        origin=origin,
        extensions=extensions,
        subprotocols=subprotocols,
        max_size=max_size,
        logger=logger,
    )

    if create_connection is None:
        create_connection = ClientConnection

    try:
        async with asyncio_timeout(open_timeout):
            if unix:
                _, connection = await asyncio.get_event_loop().create_unix_connection(
                    lambda: create_connection(protocol, close_timeout=close_timeout),
                    path=path,
                    ssl=ssl,
                    sock=sock,
                    server_hostname=server_hostname,
                    **kwargs,
                )
            else:
                _, connection = await asyncio.get_event_loop().create_connection(
                    lambda: create_connection(protocol, close_timeout=close_timeout),
                    ssl=ssl,
                    sock=sock,
                    server_hostname=server_hostname,
                    **kwargs,
                )

            # On failure, handshake() closes the transport and raises an exception.
            await connection.handshake(
                additional_headers,
                user_agent_header,
            )

    except Exception:
        try:
            connection
        except NameError:
            pass
        else:
            connection.close_transport()
        raise

    return connection


async def unix_connect(
    path: Optional[str] = None,
    uri: Optional[str] = None,
    **kwargs: Any,
) -> ClientConnection:
    """
    Connect to a WebSocket server listening on a Unix socket.

    This function is identical to :func:`connect`, except for the additional
    ``path`` argument. It's only available on Unix.

    It's mainly useful for debugging servers listening on Unix sockets.

    Args:
        path: File system path to the Unix socket.
        uri: URI of the WebSocket server. ``uri`` defaults to
            ``ws://localhost/`` or, when a ``ssl_context`` is provided, to
            ``wss://localhost/``.

    """
    if uri is None:
        if kwargs.get("ssl_context") is None:
            uri = "ws://localhost/"
        else:
            uri = "wss://localhost/"
    return await connect(uri=uri, unix=True, path=path, **kwargs)
