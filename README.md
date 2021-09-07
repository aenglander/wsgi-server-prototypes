# WSGI Server Prototypes
Prototype WSGI servers to possible replace or augment the
Werkzeug dev server


## h11 Threaded Sockets WSGI Server

Uses threading for multitasking and blocking sockets to communicate.
The h11 library is used to parse input from and output to the socket.

### h11 Info
- [Docs](https://h11.readthedocs.io/en/latest/index.html)
- [GitHub Repo](https://github.com/python-hyper/h11)

