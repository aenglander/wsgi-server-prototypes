import logging
import socket
import sys
import threading
import time
from types import TracebackType
from typing import List, Optional, Callable, Iterable, Dict, Tuple, Type, \
    NewType, Union
from wsgiref.handlers import format_date_time

import h11

ExcInfo = NewType("ExcInfo", Tuple[Type, BaseException, TracebackType])
Headers = NewType("Headers",
                  Union[List[Tuple[str, str]], List[Tuple[bytes, bytes]]])
StartResponseCallable = NewType("StartResponseCallable", Callable[
    [str, Headers, Optional[ExcInfo]], None])
Middleware = NewType("Middleware", Callable[
    [Dict[str, str], StartResponseCallable], List[str]])

WSGI_APP: Middleware = None


class H11SocketReader:
    def __init__(self, socket_to_read: socket.socket, h11_server: h11.Connection):
        self.__socket: socket.socket = socket_to_read
        self.__h11_server = h11_server
        self.__read_buffer = b""

    def read(self, size: int) -> bytes:
        while True:
            event = self.__h11_server.next_event()
            if type(event) is h11.NEED_DATA:
                byte_len = len(self.__read_buffer)
                if byte_len < size:
                    read_bytes = self.__socket.recv(size - byte_len)
                else:
                    read_bytes = self.__read_buffer[:size]
                    self.__read_buffer = self.__read_buffer[size:]
                self.__h11_server.receive_data(read_bytes)
            if type(event) is h11.Data:
                data_bytes = event.data
                data = data_bytes[:size]
                self.__read_buffer = data[size:]
                break
            if type(event) is h11.EndOfMessage:
                data = b""
                break
        return data

    def readline(self) -> bytes:
        line = b""
        while True:
            read_chunk = self.read(256)

            if read_chunk is None or len(read_chunk) == 0:
                break

            if b"\n" in read_chunk:
                try:
                    line_chunk, self.__read_buffer = read_chunk.split(b"\n", 1)
                    line += line_chunk + b"\n"
                except ValueError:
                    line += read_chunk
                break
            else:
                line += read_chunk
        return line

    def readlines(self, hint: Optional[int]) -> bytes:
        return self.readline()

    def __iter__(self):
        return self

    def __next__(self):
        return self.readline()


class LoggingErrorWriter:
    def __init__(self, logger: logging.Logger):
        self.__logger = logger

    def flush(self):
        pass

    def write(self, message: str):
        self.__logger.error(message)

    def writelines(self, seq: Iterable[str]):
        for line in seq:
            self.write(line)


class StartResponseHandler:
    def __init__(self):
        self.__status: Optional[str] = None
        self.__headers: Optional[List[List[str]]] = None
        self.__exc_info: Optional[ExcInfo]

    def __call__(self, status: str, response_headers: Headers,
                 exc_info=None):
        # TODO: validate this method is called only once unless exc info is
        #       provided

        # TODO: validate status
        self.__status = status

        # TODO: validate headers
        self.__headers = response_headers

        # TODO: validate exc info
        self.__exc_info = exc_info

    @property
    def status(self) -> str:
        # TODO: Handle status not set
        return self.__status

    @property
    def headers(self) -> Headers:
        # TODO: Handle headers not set
        return self.__headers


class WebServer:

    def __init__(self, *, max_threads: int = 16,
                 buffer_size: int = 2048, logger: logging.Logger = None,
                 log_level: int = logging.NOTSET):
        self.__client_sockets: List[socket.socket] = list()
        self.__read_buffer_size = buffer_size
        self.__write_buffer_size = buffer_size
        self.__max_threads = max_threads
        if logger is None:
            self.__logger = logging.getLogger()
            self.__logger.addHandler(logging.StreamHandler())
        else:
            self.__logger = logger
        self.__logger.setLevel(log_level)

    def listen(self, host: str, port: int, wsgi_app: Middleware,
               max_waiting: int = 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_server:
            socket_server.settimeout(0.001)
            socket_server.bind((host, port))
            socket_server.listen(max_waiting)
            self.__logger.info(f"Server started on {host}:{port}")

            try:
                self.__logger.debug("Starting connection loop")
                while True:
                    try:
                        (client_socket, address) = socket_server.accept()
                        self.__client_sockets.append(client_socket)
                        self.__logger.info(f"Connection to {address} from"
                                           f" {client_socket.getsockname()}")
                        thread = threading.Thread(
                            target=WebServer.handler,
                            args=(
                                client_socket, wsgi_app, self.__logger,
                                self.__read_buffer_size, host, str(port)
                            )
                        )
                        thread.start()
                        self.__logger.debug("Thread %s launched for %s",
                                            thread, client_socket)
                    except socket.timeout:
                        pass

            except KeyboardInterrupt:
                self.__logger.info("Stopping Server")

    @classmethod
    def handler(cls, connection: socket.socket, wsgi_app: Middleware,
                logger: logging.Logger,
                read_buffer_size: int, server_name: str, server_port: str):
        logger.debug("Starting handler for %s", connection)
        h11_server = h11.Connection(h11.SERVER)
        # noinspection PyBroadException
        try:
            logger.debug(f"Starting handler event loop for %s", connection)
            while True:
                logger.debug(f"Continuing handler event loop for %s",
                             connection)
                try:
                    event = h11_server.next_event()
                    logger.debug(
                        f"Handling event %s for %s", event, connection)
                except h11.RemoteProtocolError as rpe:
                    logger.debug(
                        f"Remote protocol error event for %s", connection)
                    response = cls.generate_response(rpe.error_status_hint,
                                                     b"INVALID REQUEST")
                    data = h11_server.send(response)
                    data += h11_server.send(h11.EndOfMessage())
                    connection.sendall(data)
                    break
                if type(event) is h11.ConnectionClosed:
                    logger.debug("Closing connection for %s", connection)
                    break
                if type(event) is h11.PAUSED:
                    h11_server.start_next_cycle()
                if type(event) is h11.Request:
                    logger.debug("Process HTTP request for %s", connection)
                    start_time = time.time()
                    environ = dict()
                    environ["wsgi.url_scheme"] = "http"
                    environ["wsgi.version"] = (1, 0)
                    environ["wsgi.multithread"] = True
                    environ["wsgi.multiprocess"] = False
                    environ["wsgi.run_once"] = False
                    environ["wsgi.input"] = H11SocketReader(connection, h11_server)
                    environ["wsgi.errors"] = LoggingErrorWriter(logger)
                    environ["SERVER_NAME"] = server_name
                    environ['SERVER_PORT'] = server_port
                    environ["REQUEST_METHOD"] = event.method.decode("utf8")
                    environ["SCRIPT_NAME"] = ""
                    event_target_str = event.target.decode("utf8")
                    try:
                        environ["PATH_INFO"], environ["QUERY_STRING"] = \
                            event_target_str.split("?", 1)
                    except ValueError:
                        environ["PATH_INFO"] = event_target_str
                        environ["QUERY_STRING"] = ""
                    environ["SERVER_PROTOCOL"] = \
                        "HTTP/" + event.http_version.decode("utf8")
                    for header in event.headers:
                        environ[f"HTTP_{header[0].decode().upper()}"] = header[
                            1].decode()
                        if header[0] == b"content-type":
                            environ["CONTENT_TYPE"] = header[1].decode("utf8")
                        if header[0] == b"content-length":
                            environ["CONTENT_LENGTH"] = header[1]

                    response_handler = StartResponseHandler()
                    logger.debug("Sending request to middleware for %s",
                                 connection)
                    response_body_str_iter = wsgi_app(environ, response_handler)
                    logger.debug("Received response from middleware for %s",
                                 connection)
                    response_body_bytes_iter = [segment.encode("utf8") if type(
                        segment) is str else segment for
                                                segment in
                                                response_body_str_iter]

                    # TODO: verify response_body
                    status_code_str, reason = response_handler.status.split(" ",
                                                                            1)
                    status_code = int(status_code_str)
                    h11_response = cls.generate_response(
                        status_code, reason, response_handler.headers)
                    response_heading = h11_server.send(h11_response)
                    logger.debug("Sending headers for %s", connection)
                    connection.sendall(response_heading)
                    logger.debug("Sending body for %s", connection)
                    for response_body_segment in response_body_bytes_iter:
                        h11_segment = h11.Data(data=response_body_segment)
                        if h11.ERROR in h11_server.states:
                            continue
                        data_segment = h11_server.send(h11_segment)
                        logger.debug("Sending body segment for %s", connection)
                        connection.sendall(data_segment)
                    if h11.ERROR in h11_server.states:
                        logger.debug("Error in h11 connection for %s",
                                     connection)
                        continue
                    response_footer = h11_server.send(h11.EndOfMessage())
                    logger.debug("Sending end message for %s", connection)
                    connection.sendall(response_footer)
                    end_time = time.time()
                    request_ms = (end_time - start_time) * 1000
                    logger.info(f"{event.method} {event.target} {request_ms}")
                if type(event) is h11.NEED_DATA:
                    logger.debug("Waiting for data for %s", connection)
                    buffer_bytes = connection.recv(read_buffer_size)
                    h11_server.receive_data(buffer_bytes)
        except BaseException:
            logger.error("Unhandled handler exception", exc_info=sys.exc_info())
            error_response_body = b"Internal Server Error"
            error_response_headers = [
                (b"Content-Type", b"text/text"),
                (
                    b"Content-Length",
                    str(len(error_response_body)).encode("utf8"))
            ]
            error_response = cls.generate_response(
                500, b"INTERNAL SERVER ERROR", error_response_headers)
            error_data = h11.Data(data=error_response_body)
            error_eom = h11.EndOfMessage()
            error_response_bytes = h11_server.send(error_response) + \
                                   h11_server.send(error_data) + \
                                   h11_server.send(error_eom)
            connection.sendall(error_response_bytes)
        connection.close()

    @classmethod
    def generate_response(cls, status_code: int, reason: bytes,
                          headers: Headers = None) -> h11.Response:
        if headers is None:
            headers = list()

        headers += [
            (b"Date", format_date_time(None).encode("ascii")),
            (b"Server", b"Werkzeug h11 Dev Server/0.0.1")
        ]
        response = h11.Response(
            headers=headers,
            status_code=status_code,
            reason=reason)
        return response


def middleware(environ: Dict[str, str],
               start_response: StartResponseCallable) -> Iterable[str]:
    import json
    body = json.dumps(environ)
    start_response("200 OK", [("Content-Type", "text/json"),
                              ("Content-Length", str(len(body)))])
    return [body]
