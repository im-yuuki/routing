####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

import json

from packet import Packet
from router import Router


class DVrouter(Router):
    """Distance vector routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.infinity = 16
        self.port_to_endpoint = {}
        self.endpoint_to_port = {}
        self.link_costs = {}
        self.neighbor_vectors = {}
        self.known_destinations = {self.addr}
        self.distance_vector = {self.addr: 0}
        self.forwarding_table = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            out_port = self.forwarding_table.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
        else:
            try:
                message = json.loads(packet.content)
            except (TypeError, ValueError):
                return

            if message.get("type") != "dv" or port not in self.port_to_endpoint:
                return

            neighbor = self.port_to_endpoint[port]
            vector = {
                destination: min(float(cost), self.infinity)
                for destination, cost in message.get("vector", {}).items()
            }

            if self.neighbor_vectors.get(neighbor) == vector:
                return

            self.neighbor_vectors[neighbor] = vector
            self.known_destinations.update(vector.keys())
            if self._recompute_routes():
                self._broadcast_vector()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.port_to_endpoint[port] = endpoint
        self.endpoint_to_port[endpoint] = port
        self.link_costs[endpoint] = cost
        self.known_destinations.add(endpoint)
        self._recompute_routes()
        self._broadcast_vector()

    def handle_remove_link(self, port):
        """Handle removed link."""
        endpoint = self.port_to_endpoint.pop(port, None)
        if endpoint is None:
            return

        self.endpoint_to_port.pop(endpoint, None)
        self.link_costs.pop(endpoint, None)
        self.neighbor_vectors.pop(endpoint, None)
        self.known_destinations.add(endpoint)
        self._recompute_routes()
        self._broadcast_vector()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_vector()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return (
            f"DVrouter(addr={self.addr}, "
            f"dv={self.distance_vector}, ft={self.forwarding_table})"
        )

    def _recompute_routes(self):
        old_vector = dict(self.distance_vector)
        old_forwarding_table = dict(self.forwarding_table)

        destinations = set(self.known_destinations)
        destinations.update(self.link_costs.keys())
        for vector in self.neighbor_vectors.values():
            destinations.update(vector.keys())

        new_vector = {self.addr: 0}
        new_forwarding_table = {}

        for destination in sorted(destinations):
            if destination == self.addr:
                continue

            best_cost = self.infinity
            best_port = None

            if destination in self.link_costs:
                best_cost = min(float(self.link_costs[destination]), self.infinity)
                best_port = self.endpoint_to_port.get(destination)

            for neighbor in sorted(self.neighbor_vectors):
                if neighbor not in self.link_costs:
                    continue
                neighbor_cost = self.neighbor_vectors[neighbor].get(
                    destination, self.infinity
                )
                candidate = min(
                    float(self.link_costs[neighbor]) + float(neighbor_cost),
                    self.infinity,
                )
                neighbor_port = self.endpoint_to_port.get(neighbor)
                if candidate < best_cost:
                    best_cost = candidate
                    best_port = neighbor_port

            new_vector[destination] = best_cost
            if best_cost < self.infinity and best_port is not None:
                new_forwarding_table[destination] = best_port

        self.distance_vector = new_vector
        self.forwarding_table = new_forwarding_table
        return old_vector != new_vector or old_forwarding_table != new_forwarding_table

    def _broadcast_vector(self):
        for port, endpoint in list(self.port_to_endpoint.items()):
            vector = {}
            for destination, cost in self.distance_vector.items():
                if (
                    destination != endpoint
                    and self.forwarding_table.get(destination) == port
                ):
                    vector[destination] = self.infinity
                else:
                    vector[destination] = cost

            packet = Packet(
                Packet.ROUTING,
                self.addr,
                endpoint,
                content=json.dumps(
                    {"type": "dv", "src": self.addr, "vector": vector}
                ),
            )
            self.send(port, packet)
