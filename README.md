# Distributed Multi-Tier Analytics Engine (DMTAE)

A high-performance, distributed live infrastructure monitoring system built using a 3-tier architecture across C++17, Python 3, and Vanilla JavaScript. 

The system implements a deterministic data eviction pipeline inspired by psychological models of memory decay, ensuring aggressive heap optimization during high-throughput workloads.

## Architecture Overview
- **Data Plane (`engine.cpp`):** Multi-threaded C++ processing core that ingests metrics, protects memory pools using mutexes and condition variables, and handles eviction via the **Ebbinghaus Forgetting Curve formula** ($R = e^{-t/S}$). Streams data over a POSIX TCP socket.
- **Control Plane (`server.py`):** Python middleware broker that ingests raw bytes from the C++ socket stream on background threads and serves sanitized JSON payloads over a REST API gateway.
- **Presentation Plane (`index.html`):** A dark-themed web administration dashboard utilizing pure JavaScript asynchronous polling and responsive DOM manipulation to visualize live decay states.

## How to Run It
1. **Compile and run the core engine:**
   ```bash
   g++ -std=c++17 engine.cpp -o engine -lpthread
   ./engine
