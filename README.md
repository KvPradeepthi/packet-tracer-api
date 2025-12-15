# Packet Tracer API

A comprehensive API-driven network packet tracer simulator that models packet journey through a virtual network topology. This project provides a hands-on implementation of fundamental networking concepts including DNS resolution, IP routing with longest prefix match algorithm, firewall rule processing, and TTL (Time-To-Live) management.

## Overview

The Packet Tracer API simulates how a network packet travels from source to destination, making routing decisions, passing through firewalls, and handling DNS resolution. Each request returns a detailed hop-by-hop trace of the packet's complete journey through the network.

## Features

✅ **DNS Resolution Component**
- Support for A records (IPv4 addresses) and CNAME aliases
- CNAME chain following with loop detection
- NXDOMAIN error handling for non-existent domains

✅ **Routing Engine**
- Longest Prefix Match (LPM) algorithm implementation
- CIDR block matching and route selection
- TTL (Time-To-Live) decrementing at each hop
- Direct network detection (destination reachability)
- "No route to host" error handling

✅ **Firewall Component**
- Ordered rule processing (first match wins)
- Protocol filtering (TCP, UDP, ICMP, ANY)
- Source IP CIDR matching
- Destination port and port range matching
- Allow/Deny actions with explicit rule tracking

✅ **Packet Lifecycle Management**
- Complete hop-by-hop packet journey trace
- TTL exceeded detection
- Error condition reporting (NXDOMAIN, NO_ROUTE, FIREWALL_BLOCKED)
- JSON-based configuration for network topology

## Architecture

```
Packet Tracer API (Orchestrator)
├── DNS Resolver
│   ├── A Records (hostname → IP)
│   └── CNAME Records (alias following)
├── Routing Engine
│   ├── Router definitions with interfaces
│   ├── Route tables with CIDR blocks
│   └── Longest Prefix Match algorithm
└── Firewall
    ├── Ordered rule list
    ├── Protocol/IP/Port matching
    └── Allow/Deny decisions
```

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup

1. **Clone the repository:**
```bash
git clone https://github.com/KvPradeepthi/packet-tracer-api.git
cd packet-tracer-api
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Verify configuration files:**
Ensure the following JSON config files are in the project root:
- `dns.json` - DNS records (A and CNAME)
- `routes.json` - Router definitions and routing tables
- `firewall.json` - Firewall rules and policies

## Running the Server

Start the FastAPI server:

```bash
python main.py
```

The API will be available at `http://localhost:8000`

### Interactive API Documentation
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

## API Endpoints

### POST /trace
Traces a packet's journey through the network.

**Request Body:**
```json
{
  "source_ip": "192.168.1.10",
  "destination": "example.com",
  "destination_port": 80,
  "protocol": "TCP",
  "ttl": 5
}
```

**Response:**
```json
{
  "trace": [
    {
      "hop": 1,
      "location": "DNS Resolver",
      "action": "Resolved example.com to 10.0.0.5"
    },
    {
      "hop": 2,
      "location": "Router-1",
      "action": "TTL decremented to 4; matched route 10.0.0.0/16 via 192.168.1.1 on eth0; forwarded to 192.168.1.1"
    },
    {
      "hop": 3,
      "location": "Firewall-A",
      "action": "Allowed by rule #1 (allow TCP 192.168.1.0/24 -> port 80)"
    }
  ],
  "final_status": "DELIVERED"
}
```

**Possible final_status values:**
- `DELIVERED` - Packet successfully reached destination
- `NXDOMAIN` - Hostname could not be resolved
- `TTL_EXCEEDED` - TTL reached zero before reaching destination
- `NO_ROUTE` - No matching route found for destination IP
- `FIREWALL_BLOCKED` - Packet blocked by firewall rule

### GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "ok"
}
```

## Configuration Files

### dns.json
Defines DNS records for hostname resolution.

```json
{
  "records": [
    {
      "type": "A",
      "name": "example.com",
      "address": "10.0.0.5"
    },
    {
      "type": "CNAME",
      "name": "www.example.com",
      "alias": "example.com"
    }
  ]
}
```

### routes.json
Defines routers, interfaces, and routing tables.

```json
{
  "routers": [
    {
      "name": "Router-1",
      "interfaces": [
        {
          "name": "eth0",
          "cidr": "192.168.1.0/24"
        }
      ],
      "routes": [
        {
          "destination": "10.0.0.0/16",
          "next_hop": "192.168.1.1",
          "interface": "eth0"
        },
        {
          "destination": "0.0.0.0/0",
          "next_hop": "192.168.1.254",
          "interface": "eth0"
        }
      ]
    }
  ]
}
```

### firewall.json
Defines firewall rules and policies.

```json
{
  "name": "Firewall-A",
  "rules": [
    {
      "id": 1,
      "action": "allow",
      "protocol": "TCP",
      "src": "192.168.1.0/24",
      "dst_port": "80"
    },
    {
      "id": 2,
      "action": "deny",
      "protocol": "TCP",
      "src": "0.0.0.0/0",
      "dst_port": "23"
    }
  ],
  "default_action": "deny"
}
```

## Example Test Scenarios

### 1. Successful DNS Resolution and Delivery
```bash
curl -X POST http://localhost:8000/trace \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.10",
    "destination": "example.com",
    "destination_port": 80,
    "protocol": "TCP",
    "ttl": 10
  }'
```
**Expected Result:** `DELIVERED` with DNS resolution in trace

### 2. NXDOMAIN Error
```bash
curl -X POST http://localhost:8000/trace \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.10",
    "destination": "nonexistent.local",
    "destination_port": 80,
    "protocol": "TCP",
    "ttl": 10
  }'
```
**Expected Result:** `NXDOMAIN` status

### 3. TTL Exceeded
```bash
curl -X POST http://localhost:8000/trace \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.10",
    "destination": "example.com",
    "destination_port": 80,
    "protocol": "TCP",
    "ttl": 1
  }'
```
**Expected Result:** `TTL_EXCEEDED` status

### 4. Firewall Block
```bash
curl -X POST http://localhost:8000/trace \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.100.50",
    "destination": "10.0.0.5",
    "destination_port": 80,
    "protocol": "TCP",
    "ttl": 10
  }'
```
**Expected Result:** `FIREWALL_BLOCKED` status (if rule 7 blocks this)

## Key Algorithms

### Longest Prefix Match (LPM)
The router uses LPM to select the most specific route for a destination IP:
1. Find all routes where destination IP matches the CIDR block
2. Calculate prefix length (/24, /16, /8, etc.) for each match
3. Select route with the longest (most specific) prefix

Example:
- Destination IP: `10.1.5.10`
- Route 1: `10.0.0.0/8` (prefix 8)
- Route 2: `10.1.0.0/16` (prefix 16) ✓ Selected (more specific)

### Ordered Firewall Rule Processing
Rules are processed in order until a match is found:
1. Check if packet's protocol matches rule's protocol
2. Check if source IP is within rule's CIDR block
3. Check if destination port is in rule's port range
4. If all match → apply rule's action (allow/deny)
5. If no rule matches → apply default action

## Technology Stack

- **Framework:** FastAPI (modern, fast Python web framework)
- **Server:** Uvicorn (ASGI server)
- **Data Validation:** Pydantic (runtime type checking)
- **IP Handling:** Python's ipaddress module (standard library)
- **Configuration:** JSON (human-readable, widely supported)

## Project Structure

```
packet-tracer-api/
├── main.py              # Main API with all components
├── dns.json            # DNS configuration
├── routes.json         # Routing configuration
├── firewall.json       # Firewall configuration
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Learning Outcomes

This project demonstrates:
✅ **Networking Fundamentals** - DNS, IP routing, firewalls, TTL
✅ **Algorithm Implementation** - Longest Prefix Match for routing
✅ **System Design** - Modular architecture with clear separation of concerns
✅ **API Design** - RESTful API with JSON contracts
✅ **Configuration Management** - External config files for network topology
✅ **Error Handling** - Comprehensive error scenarios and reporting
✅ **Testing** - Multiple test scenarios covering happy path and edge cases

## Future Enhancements

- Multi-router traversal (follow multiple hops across routers)
- NAT (Network Address Translation) simulation
- QoS (Quality of Service) handling
- Load balancing simulation
- Packet loss simulation
- Latency tracking per hop
- Web UI for network topology visualization
- Support for IPv6
- Unit and integration tests

## License

This project is open source and available for educational purposes.

## Author

**KvPradeepthi**

---

**Built with ❤️ to understand networking fundamentals**
