"""
Packet Tracer API - Network Packet Simulator
Simulates network packet journey through DNS, routing, and firewall
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Tuple
from ipaddress import ip_address, ip_network, IPv4Address
import json

# ============================================================================
# DATA MODELS
# ============================================================================

class Packet(BaseModel):
    source_ip: str
    destination: str  # hostname or IP
    destination_port: int
    protocol: str  # TCP, UDP
    ttl: int

class TraceEntry(BaseModel):
    hop: int
    location: str
    action: str

class TraceResponse(BaseModel):
    trace: List[TraceEntry]
    final_status: str

# ============================================================================
# DNS RESOLVER
# ============================================================================

class DNSResolver:
    def __init__(self, config: Dict):
        self.a_records = {}
        self.cname_records = {}
        
        for record in config.get('records', []):
            if record['type'] == 'A':
                self.a_records[record['name']] = record['address']
            elif record['type'] == 'CNAME':
                self.cname_records[record['name']] = record['alias']
    
    def resolve(self, hostname: str) -> str:
        """Resolve hostname to IP, following CNAME chain"""
        visited = set()
        name = hostname
        
        while True:
            if name in self.a_records:
                return self.a_records[name]
            
            if name in self.cname_records:
                if name in visited:
                    raise Exception("CNAME loop detected")
                visited.add(name)
                name = self.cname_records[name]
            else:
                raise Exception(f"NXDOMAIN for {hostname}")

# ============================================================================
# ROUTING ENGINE
# ============================================================================

class RouteDecision:
    def __init__(self, matched_route=None, next_router=None, delivered=False):
        self.matched_route = matched_route
        self.next_router = next_router
        self.delivered = delivered

class RoutingEngine:
    def __init__(self, config: Dict):
        self.routers = {r['name']: r for r in config.get('routers', [])}
    
    def _ip_in_cidr(self, ip: IPv4Address, cidr: str) -> bool:
        """Check if IP is in CIDR range"""
        network = ip_network(cidr, strict=False)
        return ip in network
    
    def _longest_prefix_match(self, dest_ip: IPv4Address, routes: List[Dict]) -> Optional[Dict]:
        """Find route with longest prefix match"""
        candidates = []
        
        for route in routes:
            if self._ip_in_cidr(dest_ip, route['destination']):
                prefix_len = int(route['destination'].split('/')[1])
                candidates.append((prefix_len, route))
        
        if not candidates:
            return None
        
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]
    
    def route(self, router_name: str, dest_ip: IPv4Address) -> RouteDecision:
        """Find next hop for packet"""
        router = self.routers.get(router_name)
        if not router:
            return RouteDecision()
        
        # Check if destination is on directly connected interface
        for iface in router.get('interfaces', []):
            if self._ip_in_cidr(dest_ip, iface['cidr']):
                return RouteDecision(delivered=True)
        
        # Find best route via longest prefix match
        matched = self._longest_prefix_match(dest_ip, router.get('routes', []))
        if not matched:
            return RouteDecision()
        
        return RouteDecision(matched_route=matched, next_router=router_name)

# ============================================================================
# FIREWALL
# ============================================================================

class Firewall:
    def __init__(self, config: Dict):
        self.rules = config.get('rules', [])
        self.default_action = config.get('default_action', 'allow')
    
    def _ip_in_cidr(self, ip: IPv4Address, cidr: str) -> bool:
        """Check if IP is in CIDR range"""
        network = ip_network(cidr, strict=False)
        return ip in network
    
    def _port_in_range(self, port: int, port_spec: str) -> bool:
        """Check if port matches port spec (single or range)"""
        if '-' in port_spec:
            start, end = map(int, port_spec.split('-'))
            return start <= port <= end
        return port == int(port_spec)
    
    def evaluate(self, packet: Packet) -> Tuple[bool, Optional[int]]:
        """Evaluate firewall rules"""
        src_ip = ip_address(packet.source_ip)
        
        for rule in self.rules:
            # Check protocol
            if rule['protocol'] != 'ANY' and rule['protocol'] != packet.protocol:
                continue
            
            # Check source IP
            if not self._ip_in_cidr(src_ip, rule['src']):
                continue
            
            # Check destination port
            if not self._port_in_range(packet.destination_port, rule['dst_port']):
                continue
            
            # Rule matched
            allowed = rule['action'] == 'allow'
            return (allowed, rule['id'])
        
        # No rule matched, use default
        allowed = self.default_action == 'allow'
        return (allowed, None)

# ============================================================================
# PACKET TRACER ORCHESTRATOR
# ============================================================================

class PacketTracer:
    def __init__(self, dns_config: Dict, route_config: Dict, fw_config: Dict):
        self.dns_resolver = DNSResolver(dns_config)
        self.routing_engine = RoutingEngine(route_config)
        self.firewall = Firewall(fw_config)
    
    def _is_hostname(self, dst: str) -> bool:
        """Check if destination is a hostname or IP"""
        try:
            ip_address(dst)
            return False
        except ValueError:
            return True
    
    def trace(self, packet_in: Packet) -> TraceResponse:
        """Simulate packet journey"""
        packet = Packet(**packet_in.dict())
        trace = []
        hop = 1
        
        # Step 1: DNS Resolution
        if self._is_hostname(packet.destination):
            try:
                resolved_ip = self.dns_resolver.resolve(packet.destination)
                packet.destination = resolved_ip
                trace.append(TraceEntry(
                    hop=hop,
                    location="DNS Resolver",
                    action=f"Resolved {packet_in.destination} to {resolved_ip}"
                ))
                hop += 1
            except Exception as e:
                trace.append(TraceEntry(
                    hop=hop,
                    location="DNS Resolver",
                    action=f"NXDOMAIN for {packet_in.destination}"
                ))
                return TraceResponse(trace=trace, final_status="NXDOMAIN")
        
        dest_ip = ip_address(packet.destination)
        current_router = "Router-1"
        max_hops = 100  # Safety limit
        
        # Step 2: Routing & Firewall loop
        while hop < max_hops:
            if packet.ttl <= 0:
                trace.append(TraceEntry(
                    hop=hop,
                    location=current_router,
                    action="Time to Live exceeded (TTL <= 0); packet dropped"
                ))
                return TraceResponse(trace=trace, final_status="TTL_EXCEEDED")
            
            # Decrement TTL
            packet.ttl -= 1
            
            # Route decision
            decision = self.routing_engine.route(current_router, dest_ip)
            
            if decision.delivered:
                trace.append(TraceEntry(
                    hop=hop,
                    location=current_router,
                    action=f"TTL decremented to {packet.ttl}; destination {dest_ip} is directly connected; packet delivered"
                ))
                return TraceResponse(trace=trace, final_status="DELIVERED")
            
            if not decision.matched_route:
                trace.append(TraceEntry(
                    hop=hop,
                    location=current_router,
                    action=f"No route to host for {dest_ip}; packet dropped"
                ))
                return TraceResponse(trace=trace, final_status="NO_ROUTE")
            
            # Firewall check
            allowed, rule_id = self.firewall.evaluate(packet)
            if not allowed:
                rule_msg = f" (rule #{rule_id})" if rule_id else ""
                trace.append(TraceEntry(
                    hop=hop,
                    location="Firewall-A",
                    action=f"Packet blocked by firewall{rule_msg}"
                ))
                return TraceResponse(trace=trace, final_status="FIREWALL_BLOCKED")
            
            # Log forwarding
            route = decision.matched_route
            trace.append(TraceEntry(
                hop=hop,
                location=current_router,
                action=(
                    f"TTL decremented to {packet.ttl}; "
                    f"matched route {route['destination']} "
                    f"via {route['next_hop']} on {route['interface']}; "
                    f"forwarded to {route['next_hop']}"
                )
            ))
            
            hop += 1
        
        return TraceResponse(trace=trace, final_status="MAX_HOPS_EXCEEDED")

# ============================================================================
# FASTAPI SETUP
# ============================================================================

# Load configurations
with open('dns.json', 'r') as f:
    dns_config = json.load(f)

with open('routes.json', 'r') as f:
    routes_config = json.load(f)

with open('firewall.json', 'r') as f:
    firewall_config = json.load(f)

tracer = PacketTracer(dns_config, routes_config, firewall_config)

app = FastAPI(
    title="Packet Tracer API",
    description="Simulates network packet journey through DNS, routing, and firewall",
    version="1.0.0"
)

@app.post("/trace", response_model=TraceResponse)
async def trace_packet(packet: Packet):
    """Trace packet journey through the network"""
    return tracer.trace(packet)

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
