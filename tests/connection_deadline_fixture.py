"""Owned loopback listen queue: TCP establishment stalls without firewall changes."""
import socket


class SaturatedListener:
    def __init__(self):
        self.listener = socket.socket()
        self.blockers = []
        try:
            self.listener.bind(('127.0.0.1', 0))
            self.listener.listen(1)
            self.address = self.listener.getsockname()
            for _ in range(4):
                connection = socket.socket()
                connection.settimeout(.15)
                try:
                    connection.connect(self.address)
                except TimeoutError:
                    connection.close()
                    break
                except BaseException:
                    connection.close()
                    raise
                self.blockers.append(connection)
            else:
                raise RuntimeError('Owned loopback listen queue did not saturate within four connections')
            if not self.blockers:
                raise RuntimeError('Owned listen queue never admitted its first connection')
        except BaseException:
            self.close()
            raise

    def close(self):
        self.listener.close()
        for connection in self.blockers:
            connection.close()
        self.blockers.clear()
