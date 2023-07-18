# Kashk

Automatic generation of eBPF kernel offload programs from application source code.

## Asumptions

1. The per connection state is defined  inside `TCPConnection` class
2. The entry function is `Server::handle_connection(TCPConnection::pointer conn)
3. Consider the most outer loop that has invocation of `async\_read\_some` as the "Event Loop"

## Dependancy

* `pip install clang==15.0.7`
* clang-15
* Asio header files [It is provided in `deps/` folder. No need to install anything]

