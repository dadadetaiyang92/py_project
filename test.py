import configparser
import select
import socket
import sys
import time
import threading
import struct
import datetime
from random import randint, randrange

DEBUG = False

LOCALHOST = '127.0.0.1'
UNREACHABLE_METRIC = 16

UPDATE_INTERVAL = 5
MAX_TRY_TIMEOUT = 30
DELETE_EXPIRE = 20

AF_INET = 2


# class 1 done
class StateTransition:
    """
    This class aims to execute a state transition in a finite state machine.
    此类旨在在有限状态机中执行状态转换
    """

    def __init__(self, to_state):
        """
        Initializes a new instance of the StateTransition class.
        param next_state: The state that this transition leads to.
        """
        self.to_state = to_state

    def execute(self):
        """Executes the transition between the current state and the next state."""
        pass


# class 2 done
class RoutingState:
    """
    Class representing a routing state
    表示路由状态的类
    """

    def __init__(self, fsm):
        """Initialize the state with the finite state machine instance"""
        self.fsm = fsm

    def enter(self):
        """Function to be executed when entering the state"""
        pass

    def execute(self):
        """Function to be executed while in the state"""
        pass

    def exit(self):
        """Function to be executed when leaving the state"""
        pass


# class 3 done
class RouterStartUpState(RoutingState):
    """
    This class aims to read and set up the configuration file &
    initialize the router's inputs, outputs, routing table.
    """

    def __init__(self, fsm):
        super(RouterStartUpState, self).__init__(fsm)

    def execute(self):
        """
        Execute the configuration functions for the router.

        This function reads the configuration file and initializes the router
        with the settings specified. It sets up the inputs and outputs, gets
        the router ID number, and creates the routing table.
        该函数读取配置文件并初始化路由器与指定的设置。 它设置输入和输出，得到路由器 ID 号，并创建路由表。

        Raises:
            Exception: If there is an invalid setting in the configuration file.
        """

        print_string_statement("You are reading and setting configuration file: '" + self.fsm.router.config_file + "'")
        # creates a ConfigParser object and reads in the specified configuration file
        config = configparser.ConfigParser()
        config.read(self.fsm.router.config_file)
        # get and set router id number by call this function
        self.get_router_id(config)
        # get the content from router settings dictionary
        self.get_outputs(config)
        # create input socket
        self.setup_inputs(config)
        # create routing table
        self.setup_routing_table()
        self.fsm.router.print_routing_table()
        self.fsm.to_transition("toWaiting")

    def get_router_id(self, config):
        """Read the router id and set it as the router's ID"""

        # Check that the router ID number is valid
        if 1 <= int(config['Settings']['router-id']) <= 64000:
            self.fsm.router.router_settings['id'] = int(config['Settings']['router-id'])
        else:
            # Raise an exception if the router ID number is invalid
            raise Exception('This is uncorrected router ID number')

    def get_outputs(self, config):
        """
        Parses the 'outputs' configuration section and returns a dictionary of
        output ports and their corresponding cost and destination router ID.
        解析“输出”配置部分并返回字典输出端口及其相应的成本和目标路由器 ID。

        Raises:
            Exception: If any of the output ports have invalid settings.
        """

        # Split the outputs by comma and space
        outputs = config['Settings']['outputs'].split(', ')
        outputs = [i.split('-') for i in outputs]

        # Initialize the outputs dictionary and existing_ports list
        self.fsm.router.router_settings['outputs'] = {}
        existing_ports = []

        # Loop through each output and check if it's valid
        for output in outputs:
            # Check if the port is valid
            if 1024 <= int(output[0]) <= 64000 and int(output[0]) not in existing_ports:
                is_valid_port = True
                existing_ports.append(int(output[0]))
            else:
                is_valid_port = False

            # Check if the cost is valid
            if 1 <= int(output[1]) < 16:
                is_valid_cost = True
            else:
                is_valid_cost = False

            # Check if the router id is valid
            if 1 <= int(output[2]) <= 64000:
                is_valid_id = True
            else:
                is_valid_id = False

            # If all values are valid, add the output to the router settings dictionary
            if is_valid_port and is_valid_cost and is_valid_id:
                existing_ports.append(int(output[0]))
                self.fsm.router.router_settings['outputs'][int(output[2])] = \
                    {'metric': int(output[1]), 'port': int(output[0])}
            else:
                # Raise an exception if any output has invalid settings
                raise Exception('This is uncorrected Outputs')

    def setup_inputs(self, config):
        """
        Create input sockets for the specified input ports in the configuration file.
        为配置文件中指定的输入端口创建输入套接字。

        Raises:
            Exception: If the port number is invalid.
                      If there is an error creating or binding the socket.
        """

        # Get input ports from configuration file
        ports = config['Settings']['input-ports'].split(', ')

        # Validate and store input ports
        inputs = []
        for port in ports:
            if 1024 <= int(port) <= 64000 and not int(port) in inputs:
                inputs.append(int(port))
            else:
                raise Exception('Invalid Port Number')

        self.fsm.router.router_settings['inputs'] = {}

        # Create a socket for each input port and bind it to the specified host
        for port in inputs:
            # create socket for each input port
            try:
                self.fsm.router.router_settings['inputs'][port] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                print_string_statement('Socket ' + str(port) + ' Created.')
            except socket.error as msg:
                print('Failed to create socket. Message: ' + str(msg))
                sys.exit()
            # bind port to socket
            try:
                self.fsm.router.router_settings['inputs'][port].bind((LOCALHOST, port))
                print_string_statement('Socket ' + str(port) + ' Bind Complete.')
            except socket.error as msg:
                print('Failed to bind socket to port ' + str(port) + '. Message: ' + str(msg))
                sys.exit()

    def setup_routing_table(self):
        """Initialize the routing table with the current router's ID as the first entry"""

        # Create a RIPRouteEntry for the current router with a nexthop of 0,
        # a metric of 0, and the "imported" flag set to True
        self.fsm.router.routing_table[self.fsm.router.router_settings['id']] = \
            RIPRouteEntry(address=self.fsm.router.router_settings['id'],
                          nexthop=0,
                          metric=0,
                          imported=True)

    def exit(self):
        """Prints a message to indicate that the router setup is complete"""

        print_string_statement("The router is setup successfully.")


# class 4 done
class Waiting(RoutingState):
    """
        If the router receive the messages then change the state to read state.
        路由器等待的FSM的等待状态的类用于在其输入套接字上接收消息。 当消息是收到状态更改为 ReadMeessage 状态。
    """

    def __init__(self, fsm):
        super(Waiting, self).__init__(fsm)

    def enter(self):
        """Print a message indicating the state is in waiting state"""
        print_string_statement("Entering waiting state.")

    def execute(self):
        """Function is executed if receive the message then change the state"""

        # select readable sockets from inputs
        readable_sockets, _, _ = select.select(self.fsm.router.router_settings['inputs'].values(), [], [])

        if readable_sockets:
            # store the list of readable sockets in the router object
            self.fsm.router.readable_ports = readable_sockets
            # transition to the ReadMessage state
            self.fsm.to_transition("toReadMessage")

    def exit(self):
        """Print a message indicating the state has been exited"""

        print_string_statement("Message received, change to read state.")


# class 5 done
class ReadMessage(RoutingState):
    """
        Read message and update routing table
    """

    def __init__(self, fsm):
        super(ReadMessage, self).__init__(fsm)

    def enter(self):
        """Print a message indicating the state is in reading state"""
        print_string_statement("Entering message reading state.")

    def execute(self):
        """Read messages from input sockets and update routing table"""

        for port in self.fsm.router.readable_ports:
            # receive message and create RIP packet object
            message, address = port.recvfrom(1024)
            packet = RIPPacket(message)
            # update routing table with received packet
            self.fsm.router.update_routing_table(packet)

        # check for changes in routing table and trigger update if necessary
        if self.fsm.router.route_state_change:
            self.fsm.router.trigger_update()

        # print current routing table
        self.fsm.router.print_routing_table()

        # transition to waiting state
        self.fsm.to_transition("toWaiting")

    def exit(self):
        """Print a message indicating the state has been exited"""
        print_string_statement("Messages are read, exiting message reading state.")


# class 6 done
class RouterFSM:
    """Router finite state machine"""

    def __init__(self, rip_router):
        """Initialize the RouterFSM class"""
        self.router = rip_router
        self.states = {}
        self.transitions = {}
        self.cur_state = None
        self.trans = None

    def add_state(self, state_name, state):
        """Add a new state to the FSM with the given name and state object representing a state of the router"""
        self.states[state_name] = state

    def add_transistion(self, trans_name, transition):
        """Add a new transition to the FSM with the given name and transition object"""
        self.transitions[trans_name] = transition

    def set_state(self, state_name):
        """Set the current state of the FSM to the state with the given name."""
        self.cur_state = self.states[state_name]

    def to_transition(self, to_trans):
        """Set the current transition of the FSM to the transition with the given name"""
        self.trans = self.transitions[to_trans]

    def execute(self):
        """Execute the FSM"""
        self.cur_state.execute()
        if self.trans:
            self.cur_state.exit()
            self.trans.execute()
            self.set_state(self.trans.to_state)
            self.cur_state.enter()
            self.trans = None


# class 7 done
class RIPPacket:
    """Create header and body of a RIP packet"""

    def __init__(self, data=None, header=None, rtes=None):
        """
        Initialize the RIPPacket object.

        Args:
        - data: Optional; raw bytes of the RIP packet received from the network.
        - header: Optional; a RIPHeader object representing the header of the RIP packet.
        - rtes: Optional; a list of RIPRouteEntry objects representing the route entries of the RIP packet.

        Raises:
        - ValueError: if neither `data` nor (`header` and `rtes`) are provided.
        """
        if data:
            # Initialize the RIPPacket object from raw bytes received from the network
            self._init_from_network(data)
        elif header and rtes:
            # Initialize the RIPPacket object from a RIPHeader object and a list of RIPRouteEntry objects
            self._init_from_host(header, rtes)
        else:
            raise ValueError("Either 'data' or ('header' and 'rtes') must be provided.")

    def __repr__(self):
        """Return a string representation of the RIPPacket object."""
        return "RIPPacket: Command {}, Ver. {}, number of RTEs {}.".format(self.header.cmd, self.header.ver,
                                                                           len(self.rtes))

    def _init_from_network(self, data):
        """
        Initialize the RIPPacket object from raw bytes received from the network.

        Args:
        - data: raw bytes of the RIP packet received from the network.

        Raises:
        - FormatException: if the packet is malformed.
        """
        # Packet Validation
        length_data = len(data)
        if length_data < RIPHeader.SIZE:
            raise FormatException("The packet is too short.")
        wrong_format = (length_data - RIPHeader.SIZE) % RIPRouteEntry.SIZE
        if wrong_format:
            raise FormatException("Something is wrong, check the format again.")

        # Convert bytes in packet to header and RTE data
        num_rtes = int((length_data - RIPHeader.SIZE) / RIPRouteEntry.SIZE)
        self.header = RIPHeader(data[0:RIPHeader.SIZE])
        self.rtes = []
        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE

        # Loop over data packet to obtain each RTE
        for i in range(num_rtes):
            self.rtes.append(RIPRouteEntry(rawdata=data[rte_start:rte_end], src_id=self.header.src))
            rte_start += RIPRouteEntry.SIZE
            rte_end += RIPRouteEntry.SIZE

    def _init_from_host(self, header, rtes):
        """
        Initialize the RIPPacket object from a RIPHeader object and a list of RIPRouteEntry objects.

        Args:
        - header: a RIPHeader object representing the header of the RIP packet.
        - rtes: a list of RIPRouteEntry objects representing the route entries of the RIP packet.

        Raises:
        - ValueError: if the version number of the RIPHeader object is not 2.
        """
        if header.ver != 2:
            raise ValueError("Only Version 2 is supported.")
        self.header = header
        self.rtes = rtes

    def serialize(self):
        """返回表示此数据包的字节串以进行网络传输。"""
        packed = self.header.serialize()
        for rte in self.rtes:
            packed += rte.serialize()
        return packed


# class 8 done
class RIPHeader:
    """Class representing the header of a RIP packet"""

    FORMAT = "!BBH"
    SIZE = struct.calcsize(FORMAT)
    TYPE_RESPONSE = 2
    VERSION = 2

    def __init__(self, rawdata=None, router_id=None):

        self.packed = None

        if rawdata:
            self._init_from_network(rawdata)
        elif router_id:
            self._init_from_host(router_id)
        else:
            raise ValueError

    def __repr__(self):
        return "RIP Header (cmd = {}, ver = {}, src = {})".format(self.cmd,
                                                                  self.ver,
                                                                  self.src)

    def _init_from_network(self, rawdata):
        '''init for data from network'''
        header = struct.unpack(self.FORMAT, rawdata)

        self.cmd = header[0]
        self.ver = header[1]
        self.src = header[2]

    def _init_from_host(self, router_id):
        """Init for data from host"""
        self.cmd = self.TYPE_RESPONSE
        self.ver = self.VERSION
        self.src = router_id

    def serialize(self):
        """Return the byte sting representing this header for network
        transmission"""
        return struct.pack(self.FORMAT, self.cmd, self.ver, self.src)


# class 9 done
class RIPRouteEntry:
    """表示单个 RIP 路由条目 (RTE) 的类"""

    # Format string for packing and unpacking RIP route entry data
    FORMAT = "!HHIII"
    # Size of RIP route entry in bytes
    SIZE = struct.calcsize(FORMAT)
    # Minimum metric value
    MIN_METRIC = 0
    # Maximum metric value for an unreachable destination
    UNREACHABLE_METRIC = 16

    def __init__(self, rawdata=None, src_id=None, address=None, nexthop=None, metric=None, imported=False):
        """
        Constructor method for RIPRouteEntry class.

        Parameters:
        - rawdata (bytes): raw data representing the RIP route entry received from the network
        - src_id (int): source ID of the RIP route entry
        - address (str): destination IP address of the RIP route entry
        - nexthop (str): IP address of the next hop for the RIP route entry
        - metric (int): metric value for the RIP route entry
        - imported (bool): whether the RIP route entry is imported from another router

        Raises:
        - ValueError: if the arguments are not valid

        """

        self.changed = False
        self.imported = imported
        self.init_timeout()

        if rawdata and src_id is not None:
            self._init_from_network(rawdata, src_id)
        elif address and nexthop is not None and metric is not None:
            self._init_from_host(address, nexthop, metric)
        else:
            raise ValueError("Invalid arguments")

    def __repr__(self):
        """
        Method for representing RIPRouteEntry object as a string.

        Returns:
        - str: string representation of RIPRouteEntry object

        """
        template = "|{:^11}|{:^10}|{:^11}|{:^15}|{:^10}|{:^13}|"

        # Check that timeout is set
        if self.timeout is None:
            return template.format(self.addr, self.metric, self.nexthop,
                                   self.changed, self.garbage, str(self.timeout))
        else:
            timeout = (datetime.datetime.now() - self.timeout).total_seconds()
            return template.format(self.addr, self.metric, self.nexthop,
                                   self.changed, self.garbage, round(timeout, 1))

    def _init_from_host(self, address, nexthop, metric):
        """
        Initialize RIPRouteEntry object from data received from a host.

        Parameters:
        - address (str): destination IP address of the RIP route entry
        - nexthop (str): IP address of the next hop for the RIP route entry
        - metric (int): metric value for the RIP route entry

        """
        self.afi = AF_INET
        self.addr = address
        self.nexthop = nexthop
        self.metric = metric
        self.tag = 0

    def _init_from_network(self, rawdata, src_id):
        """
        Initialize RIPRouteEntry object from data received from the network.

        Parameters:
        - rawdata (bytes): raw data representing the RIP route entry received from the network
        - src_id (int): source ID of the RIP route entry

        Raises:
        - FormatException: if the metric value is not valid
        """
        rte = struct.unpack(self.FORMAT, rawdata)
        self.afi = rte[0]
        self.addr = rte[2]
        self.set_next_hop(rte[3])
        self.metric = rte[4]
        self.tag = rte[1]

        if self.nexthop == 0:
            self.nexthop = src_id

        # Validation
        if not self.MIN_METRIC <= self.metric <= self.UNREACHABLE_METRIC:
            raise FormatException

    def init_timeout(self):
        """
         Initializes the timeout property for the route entry.
         If the entry was imported from another router, sets the timeout to None
         If the entry is locally generated, sets the timeout to the current datetime.
        """

        if self.imported:
            self.timeout = None
        else:
            self.timeout = datetime.datetime.now()
        self.garbage = False
        self.marked_to_delete = False

    def __eq__(self, other):
        """
        Checks if two RIPRouteEntry objects are equal by comparing their AFI, address, tag, nexthop, and metric properties.
        Returns True if they are equal, False otherwise.
        """
        return (self.afi, self.addr, self.tag, self.nexthop, self.metric) == \
            (other.afi, other.addr, other.tag, other.nexthop, other.metric)

    def set_next_hop(self, nexthop):
        """Set the nexthop property to the given value."""
        self.nexthop = nexthop

    def serialize(self):
        """Pack this route entry into the typical RIPv2 packet format for
        sending over the network.

        Returns:
            A bytes object containing the packed data.
        """
        return struct.pack(self.FORMAT, self.afi, self.tag, self.addr, self.nexthop, self.metric)


# class 10 done
class FormatException(Exception):
    """Exception raised when there is an issue with the format of an RIP route entry."""

    def __init__(self, message=""):
        """Initializes the FormatException with an optional message."""

        self.message = message


# class 11 done
class Router:
    """RIP router"""

    def __init__(self, config_file):
        """Initializes a new instance of the Router class.

        Args:
            config_file (str): The name of the configuration file for the router.
        """
        self.config_file = config_file
        self.router_settings = {}
        self.readable_ports = []
        self.fsm = RouterFSM(self)
        self.routing_table = {}
        self.route_state_change = False

        # Add the states to the finite state machine.
        self.fsm.add_state("RouterStartUpState", RouterStartUpState(self.fsm))
        self.fsm.add_state("Waiting", Waiting(self.fsm))
        self.fsm.add_state("ReadMessage", ReadMessage(self.fsm))

        # Add the transitions to the finite state machine.
        self.fsm.add_transistion("toWaiting", StateTransition("Waiting"))
        self.fsm.add_transistion("toReadMessage", StateTransition("ReadMessage"))

        # Set the initial state of the finite state machine.
        self.fsm.set_state("RouterStartUpState")

    def execute(self):
        """Executes the finite state machine (FSM) of the router."""
        self.fsm.execute()

    def update_routing_table(self, packet):
        """
        Updates the routing table of the router based on a received packet.
        param packet: the packet containing the routing information
        """

        for rte in packet.rtes:
            if rte.addr == self.router_settings['id']:
                continue

            # Get the best route in the routing table for the given address
            bestroute = self.routing_table.get(rte.addr)

            # Set the next hop to the source router and calculate metric
            rte.set_next_hop(packet.header.src)
            rte.metric = min(rte.metric + self.router_settings['outputs'][packet.header.src]['metric'],
                             RIPRouteEntry.UNREACHABLE_METRIC)

            # Check if the route already exists in the routing table
            if not bestroute:
                # Route does not yet exist
                if rte.metric == RIPRouteEntry.UNREACHABLE_METRIC:
                    # Ignore RTEs with a metric of UNREACHABLE_METRIC
                    return

                # Add new RTE to routing table
                rte.changed = True
                self.route_state_change = True
                self.routing_table[rte.addr] = rte
                print_string_statement("RTE added for Router: " + str(rte.addr))
                return
            # Update existing route
            else:
                # Route already exists
                if rte.nexthop == bestroute.nexthop:
                    if bestroute.metric != rte.metric:
                        if bestroute.metric != RIPRouteEntry.UNREACHABLE_METRIC and rte.metric >= RIPRouteEntry.UNREACHABLE_METRIC:
                            bestroute.metric = RIPRouteEntry.UNREACHABLE_METRIC
                            bestroute.garbage = True
                            bestroute.changed = True
                            self.route_state_change = True
                        else:
                            self.update_route(bestroute, rte)
                    elif not bestroute.garbage:
                        bestroute.init_timeout()
                elif rte.metric < bestroute.metric:
                    self.update_route(bestroute, rte)

    def update_route(self, best_route, rte):
        """
        Updates an existing route entry with new route information.

        Args:
            best_route (RIPRouteEntry): The existing route entry to be updated.
            rte (RIPRouteEntry): The new route information to use for the update.
        """

        # Initialize timeout and clear garbage flag
        best_route.init_timeout()
        best_route.garbage = False
        best_route.changed = True

        # Update metric and nexthop
        best_route.metric = rte.metric
        best_route.nexthop = rte.nexthop

        # Set route state change flag
        self.route_state_change = True

        # Print confirmation message
        print_string_statement("RTE for Router: " + str(rte.addr) + " updated with metric=" + str(rte.metric) +
                               ", nexthop=" + str(rte.nexthop) + ".")

    def print_routing_table(self):
        """Print the routing table to the terminal"""

        # print table header
        line = "-----------------------------------------------------------------------------"
        print(line)
        print("|                             Routing Table   (Router " + str(self.router_settings['id']) + ")         "
                                                                                                           "          "
                                                                                                           " |")
        print(line)
        print("| Router ID |  Metric  |  NextHop  |    Changed    | ToDelete |   Timeout   |")
        print(line)

        # print the entry for the current router
        print(self.routing_table[self.router_settings['id']])

        # print entries for other routers in the table
        for entry in self.routing_table:
            if entry != self.router_settings['id']:
                print(self.routing_table[entry])
                print(line)
        print('\n')

    def trigger_update(self):
        """routing updated"""

        # Create a list to store the changed routes.
        route_changed = []

        # Print a message indicating that a trigger update is being sent.
        print_string_statement("Sending Trigger update.")

        # Iterate over all routes in the routing table, and add any that have changed to the list.
        for rte in self.routing_table.values():
            if rte.changed:
                route_changed.append(rte)
                rte.changed = False

        # Set the route_state_change flag to False, indicating that all changes have been processed.
        self.route_state_change = False

        # Send the update with a random delay between 1 and 5 seconds.
        delay = randint(1, 5)
        threading.Timer(delay, self.update, [route_changed])

    def update(self, entries):
        """Send an updated message when changed"""

        # Check if the router has settings
        if self.router_settings != {}:

            # Get the input socket
            sock = list(self.router_settings['inputs'].values())[1]

            # Create a local header
            local_header = RIPHeader(router_id=self.router_settings['id'])

            # Iterate over all output ports
            for output in self.router_settings['outputs']:

                # Initialize a list of route entries for the current port
                split_horizon_entries = []

                # Check if any of the entries in the routing table have changed
                for entry in entries:
                    # Apply the split horizon rule: do not send an entry back to the same router it was learned from
                    if entry.nexthop != output:
                        split_horizon_entries.append(entry)
                    else:
                        # If the next hop is the same as the output port, the entry is poisoned
                        poisoned_entry = RIPRouteEntry(rawdata=None,
                                                       src_id=None, address=entry.addr,
                                                       nexthop=entry.nexthop, metric=RIPRouteEntry.UNREACHABLE_METRIC,
                                                       imported=entry.imported)
                        split_horizon_entries.append(poisoned_entry)

                # Create a packet with the updated route entries and send it through the output port
                packet = RIPPacket(header=local_header, rtes=split_horizon_entries)
                sock.sendto(packet.serialize(),
                            (LOCALHOST, self.router_settings['outputs'][output]["port"]))

                # Print a message indicating that the packet was sent to the output port
                print_string_statement("Message Sent To Router: " + str(output))

    def check_timeout(self):
        """Check the current timeout value in the routing table."""

        print_string_statement("Checking timeout...")

        # check if the routing table is not empty
        if self.routing_table:
            # iterate over all routing table entries
            for rte in self.routing_table.values():
                # check if timeout has been set and has expired
                if rte.timeout and (datetime.datetime.now() - rte.timeout).total_seconds() >= MAX_TRY_TIMEOUT:
                    # mark the route as garbage, set metric to UNREACHABLE_METRIC and update timestamp
                    rte.garbage = True
                    rte.changed = True
                    rte.metric = RIPRouteEntry.UNREACHABLE_METRIC
                    rte.timeout = datetime.datetime.now()
                    # mark route state change and print updated routing table
                    self.route_state_change = True
                    self.print_routing_table()
                    print_string_statement(f"Router: {rte.addr} timed out.")

    def garbage_timer(self):
        """Check the status of the garbage property."""

        print_string_statement("Now, we are checking garbage timeout.")
        if self.routing_table:
            for rte in self.routing_table.values():
                if rte.garbage and (datetime.datetime.now() - rte.timeout).total_seconds() >= DELETE_EXPIRE:
                    rte.marked_to_delete = True

    def garbage_collection(self):
        """
        Check the routing table for any RTE's that have been marked for deletion, and remove them from the routing table.
        If any routes are deleted, the updated routing table is printed to the console.
        """

        # Print a status message
        print_string_statement("Now, collecting Garbage.")

        # Check if the routing table is not empty
        if self.routing_table != {}:
            # Create a list to store the RTEs that need to be deleted
            delete_routes = []
            # Loop through each RTE in the routing table
            for rte in self.routing_table.values():
                # If the RTE is marked for deletion, add it to the list of routes to delete
                if rte.marked_to_delete:
                    delete_routes.append(rte.addr)
                    # Print a status message indicating that the RTE has been removed
                    print_string_statement("Router: " + str(rte.addr) + " has been " + "removed from the routing table.")
            # Loop through the list of routes to delete and remove them from the routing table
            for entry in delete_routes:
                del self.routing_table[entry]
            # Print the updated routing table to the console
            self.print_routing_table()

    def timer(self, function, param=None):
        '''
        Start a periodic timer which calls a specified function.

        Args:
        - function: a function to be called periodically
        - param: an optional dictionary of parameters to pass to the function

        Returns:
        - None

        Behavior:
        - If param is not None, call the function with the dictionary's values
          as arguments, and set the period to UPDATE_INTERVAL times a random
          float between 0.8 and 1.2.
        - If param is None, call the function with no arguments, and set the
          period to UPDATE_INTERVAL.
        - Start a timer with the specified period that calls this timer function
          with the same arguments.
        '''
        if param is not None:
            function(list(param.values()))
            period = UPDATE_INTERVAL * randrange(8, 12, 1) / 10
        else:
            period = UPDATE_INTERVAL
            function()

        threading.Timer(period, self.timer, [function, param]).start()

    def start_timers(self):
        """Start the routing update, timeout check, garbage timer, and garbage collection timers on separate threads."""
        self.timer(self.update, param=self.routing_table)
        self.timer(self.check_timeout)
        self.timer(self.garbage_timer)
        self.timer(self.garbage_collection)

    def main_loop(self):
        """Run the main loop for the program."""

        while True:
            self.execute()


def print_string_statement(message):
    """Output information"""
    if DEBUG:
        print("[" + time.strftime("%H:%M:%S") + "]: " + message)


def main():
    """Main function to run the program."""

    if __name__ == "__main__":
        router = Router(str(sys.argv[-1]))
        router.start_timers()
        router.main_loop()


main()
