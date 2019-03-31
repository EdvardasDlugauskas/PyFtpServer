import os
import socket
import threading
import time
from typing import Tuple

HOST = socket.gethostbyname(socket.gethostname()) # '127.0.0.1'
PORT = 21  # command port
CWD = "."  # os.getenv('HOME')
STOP = False

# https://www.w3.org/Protocols/rfc959/4_FileTransfer.html
# https://resources.avid.com/SupportFiles/attach/Broadcast/iNEWS-FTP-FTPS-ServerProtocol.pdf


def log(message):
    log_msg = time.strftime(f"%Y-%m-%d %H-%M-%S: {message}")
    print(log_msg)


# checks authorization
def authorize(func):
    def func_wrapper(self, arg):
        if not self.is_authenticated:
            self.send_command('530 User not logged in.')
            return
        return func(self, arg)
    return func_wrapper


class FtpServer(threading.Thread):
    def __init__(self, command_socket: socket.socket, address: Tuple[str, int]):
        threading.Thread.__init__(self)
        self.is_authenticated = False
        self.is_passive_mode = False
        self.current_dir = CWD
        self.command_socket = command_socket  # communication socket
        self.address = address

        self.username = ""
        self.password = ""
        self.repr_type = ""
        self.server_listen_socket: socket.socket = None
        self.data_socket: socket.socket = None

        # For DATA PORT
        self.data_socket_addr = ""
        self.data_socket_port = 0

    def run(self):
        self.send_welcome()
        while True:
            if STOP:
                return

            data = ""
            try:
                data = self.command_socket.recv(1024).strip()
            except socket.error as err:
                log(err)

            if len(data) == 0:
                break

            try:
                data = data.decode('utf-8')
            except AttributeError:
                log(f"Bad format command received: {data}")
                continue

            log(f"Received: {data}")
            command = data[:4].strip().upper()
            argument = data[4:].strip() or None

            try:
                func = getattr(self, command)
            except AttributeError as err:
                self.send_command(f"502 Command not implemented. Command '{command}' unrecognized.\r\n")
                log(f"Syntax error: {err}")
                continue

            try:
                func(argument)
            except Exception as e:
                log(f"Internal server error: {e}")
                self.send_command("502 Command not implemented: Internal server error")

    def start_datasocket(self):
        log('Opening data socket')
        try:
            if self.is_passive_mode:
                self.data_socket, self.address = self.server_listen_socket.accept()
            else:
                self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.data_socket.connect((self.data_socket_addr, self.data_socket_port))
        except socket.error as err:
            log(err)

    def stop_datasocket(self):
        log('Closing data socket')
        try:
            self.data_socket.close()
            if self.is_passive_mode:
                self.server_listen_socket.close()
        except socket.error as err:
            log(err)

    def send_command(self, cmd):
        log(f"Sending: {cmd}")
        cmd = cmd + "\r\n"
        self.command_socket.send(cmd.encode('utf-8'))

    def send_data(self, data):
        log(f"Sending data: {data}")
        if isinstance(data, str):
            data = data + "\r\n"
            self.data_socket.send(data.encode('utf-8'))
        else:
            self.data_socket.send(data)

    def send_welcome(self):
        self.send_command('220 Welcome.')

    # === COMMANDS ===

    def USER(self, user):
        if not user:
            self.send_command('501 Syntax error: username not supplied.')
        else:
            self.send_command('331 User name okay, need password.')
        self.username = user

    def PASS(self, password):
        if not password:
            self.send_command('501 Syntax error: password not supplied.')
        elif not self.username:
            self.send_command('503 Bad sequence of commands.')
        else:
            # Accept any password...
            self.send_command('230 User logged in, proceed.')
            self.password = password
        self.is_authenticated = True

    @authorize
    def TYPE(self, repr_type):
        self.repr_type = repr_type
        if self.repr_type == 'I':
            self.send_command('200 Binary mode.')
        elif self.repr_type == 'A':
            self.send_command('200 Ascii mode.')
        else:
            self.send_command(f"501 Syntax error: type '{repr_type}' not found.")

    @authorize
    def PASV(self, arg):
        self.is_passive_mode = True
        self.server_listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_listen_socket.bind((HOST, 0))
        self.server_listen_socket.listen(1)
        addr, port = self.server_listen_socket.getsockname()
        address_string = ','.join(addr.split('.'))
        self.send_command(f'227 Entering Passive Mode ({address_string},{port >> 8 & 0xFF},{port & 0xFF}).')

    @authorize
    def LIST(self, dirpath):
        if not dirpath:
            fullpath = os.path.abspath(self.current_dir)
        elif dirpath.startswith(os.path.sep):
            fullpath = os.path.abspath(dirpath)
        else:
            fullpath = os.path.abspath(os.path.join(self.current_dir, dirpath))

        log(f"Listing: {fullpath}")
        if not os.path.exists(fullpath):
            self.send_command('550 LIST failed: path does not exist.')
        else:
            self.send_command('150 Here is listing.')
            self.start_datasocket()
            if not os.path.isdir(fullpath):
                filename = fullpath
                rights = "-rw-rw-rw-"
                info = os.stat(filename)
                self.send_data(f"{rights} {info.st_nlink} {info.st_uid} {info.st_gid} {info.st_size} {time.strftime('%b %d %H:%M', time.gmtime(info.st_mtime))} {os.path.basename(filename)}")
            else:
                for file in os.listdir(fullpath):
                    filename = os.path.join(fullpath, file)
                    rights = "drwxrwxrwx" if os.path.isdir(filename) else "-rw-rw-rw-"
                    info = os.stat(filename)
                    self.send_data(f"{rights} {info.st_nlink} {info.st_uid} {info.st_gid} {info.st_size} {time.strftime('%b %d %H:%M', time.gmtime(info.st_mtime))} {os.path.basename(filename)}")
            self.stop_datasocket()
            self.send_command('226 List done.')

    @authorize
    def PORT(self, cmd):
        if self.is_passive_mode:
            self.server_listen_socket.close()
            self.is_passive_mode = False

        new_host_bytes = cmd[5:].split(',')
        new_datasocket_addr = '.'.join(new_host_bytes[:4])
        new_datasocket_port = (int(new_host_bytes[4]) << 8) + int(new_host_bytes[5])

        self.data_socket_addr = new_datasocket_addr
        self.data_socket_port = new_datasocket_port
        self.send_command('200 Port set.')

    @authorize
    def RETR(self, filename):
        pathname = os.path.join(self.current_dir, filename)
        if not os.path.exists(pathname):
            self.send_command('550 File not found.')
            return

        file = None
        try:
            if self.repr_type == 'I':
                file = open(pathname, 'rb')
            else:
                file = open(pathname, 'r')
        except OSError as err:
            log(f"OSError during RETR: {err}")
            self.send_command('450 File unavailable.')
            return

        self.send_command('150 Opening data connection.')

        self.start_datasocket()
        while True:
            data = file.read(1024)
            if not data:
                break
            self.send_data(data)

        file.close()
        self.stop_datasocket()
        self.send_command('226 Transfer complete.')

    @authorize
    def PWD(self, arg):
        full_path = os.path.abspath(self.current_dir)
        self.send_command(f'257 "{full_path}"')


    @authorize
    def CWD(self, dirname):
        if os.path.exists(dirname) and os.path.isdir(dirname):
            self.current_dir = dirname
        else:
            fullpath = os.path.join(self.current_dir, dirname)
            if os.path.exists(fullpath) and os.path.isdir(fullpath):
                self.current_dir = fullpath
            else:
                self.send_command('550 CWD failed Directory not exists.')
                return

        self.send_command('250 CWD Command successful.')


    #TODO: SIZE, CWD, MDTM

    def HELP(self, arg):
        help = """
            214
            """
        self.send_command(help)

    def QUIT(self, arg):
        self.send_command('221 Goodbye.')


def server_listener():
    global listen_sock
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((HOST, PORT))
    listen_sock.listen(5)

    log(f"Listening on: {listen_sock.getsockname()}")
    while True:
        if STOP:
            return
        connection, address = listen_sock.accept()
        f = FtpServer(connection, address)
        f.start()
        log(f"Created connection with: {address}")


if __name__ == "__main__":
    log('FTP server started')
    listen_thread = threading.Thread(target=server_listener)
    listen_thread.start()

    if input().lower() == "q":
        STOP = True
        listen_sock.close()
        log('Server closed')
