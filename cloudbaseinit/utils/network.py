# Copyright 2012 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import binascii
import collections
import copy
import ipaddress
import time

import netaddr
import socket
import struct
import sys
from urllib import parse
from urllib import request

from oslo_log import log as oslo_logging

from cloudbaseinit import exception
from cloudbaseinit.models import network as network_model
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.plugins.common import networkconfig


LOG = oslo_logging.getLogger(__name__)
MAX_URL_CHECK_RETRIES = 3
DEFAULT_GATEWAY_CIDR_IPV4 = u"0.0.0.0/0"
DEFAULT_GATEWAY_CIDR_IPV6 = u"::/0"
LOCAL_IPV4 = "local-ipv4"
LOCAL_IPV6 = "local-ipv6"

NETWORK_LINK_TYPE_PHY = 'physical'
NETWORK_LINK_TYPE_ETHERNET = 'ethernet'
NETWORK_LINK_TYPE_BOND = 'bond'
NETWORK_LINK_TYPE_BRIDGE = 'bridge'
NETWORK_LINK_TYPE_VLAN = 'vlan'
NETWORK_SERVICE_NAMESERVER = 'nameserver'

SUBNET_TYPE_MANUAL = 'manual'
SUBNET_TYPE_STATIC = 'static'
SUBNET_TYPE_DHCP = 'dhcp'
SUBNET_TYPE_DHCP6 = 'dhcp6'


def get_local_ip(address=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((address or "<broadcast>", 8000))
    return s.getsockname()[0]


def check_url(url, retries_count=MAX_URL_CHECK_RETRIES):
    for i in range(0, MAX_URL_CHECK_RETRIES):
        try:
            LOG.debug("Testing url: %s" % url)
            request.urlopen(url)
            return True
        except Exception:
            pass
    return False


def check_metadata_ip_route(metadata_url):
    # Workaround for: https://bugs.launchpad.net/quantum/+bug/1174657
    osutils = osutils_factory.get_os_utils()

    if sys.platform == 'win32' and osutils.check_os_version(6, 0):
        # 169.254.x.x addresses are not getting routed starting from
        # Windows Vista / 2008
        metadata_netloc = parse.urlparse(metadata_url).netloc
        metadata_host = metadata_netloc.split(':')[0]

        if metadata_host.startswith("169.254."):
            if (not osutils.check_static_route_exists(metadata_host) and
                    not check_url(metadata_url)):
                (interface_index, gateway) = osutils.get_default_gateway()
                if gateway:
                    try:
                        LOG.debug('Setting gateway for host: %s',
                                  metadata_host)
                        osutils.add_static_route(metadata_host,
                                                 "255.255.255.255",
                                                 gateway,
                                                 interface_index,
                                                 10)
                    except Exception as ex:
                        # Ignore it
                        LOG.exception(ex)


def address6_to_4_truncate(address6):
    """Try to obtain IPv4 address from version 6."""
    chunks = address6.split(":")
    hi, lo = chunks[-2], chunks[-1]
    network_address = binascii.unhexlify(hi.zfill(4) + lo.zfill(4))
    return socket.inet_ntoa(network_address)


def netmask6_to_4_truncate(netmask6):
    """Try to obtain IPv4 netmask from version 6."""
    # Harsh 128bit to 32bit.
    length = int(int(netmask6) / 4)
    mask = "1" * length + "0" * (32 - length)
    network_address = struct.pack("!L", int(mask, 2))
    return socket.inet_ntoa(network_address)


def ip_netmask_to_cidr(ip_address, netmask):
    if not netmask:
        return ip_address
    prefix_len = netaddr.IPNetwork(
        u"%s/%s" % (ip_address, netmask)).prefixlen
    return u"%s/%s" % (ip_address, prefix_len)


def get_default_ip_addresses(network_details):
    ipv4_address = None
    ipv6_address = None
    if network_details:
        for net in network_details.networks:
            ip_net = netaddr.IPNetwork(net.address_cidr)
            addr = ip_net.ip
            default_route = False
            for route in net.routes:
                if addr.version == 6 and \
                        route.network_cidr == DEFAULT_GATEWAY_CIDR_IPV6:
                    default_route = True

                elif addr.version == 4 and \
                        route.network_cidr == DEFAULT_GATEWAY_CIDR_IPV4:
                    default_route = True

            if not default_route:
                continue

            if not ipv6_address and addr.version == 6:
                v6_addr = ipaddress.IPv6Address(addr)
                if v6_addr.is_private or v6_addr.is_global:
                    ipv6_address = str(v6_addr)

            if not ipv4_address and addr.version == 4:
                v4_addr = ipaddress.IPv4Address(addr)
                if v4_addr.is_private or v4_addr.is_global:
                    ipv4_address = str(v4_addr)

    return ipv4_address, ipv6_address


def get_host_info(hostname, network_details):
    """Returns host information such as the host name and network interfaces.

    """
    host_info = {
        "network": {
            "interfaces": {
                "by-mac": collections.OrderedDict(),
                "by-ipv4": collections.OrderedDict(),
                "by-ipv6": collections.OrderedDict(),
            },
        },
    }
    if hostname:
        host_info["hostname"] = hostname
        host_info["local-hostname"] = hostname
        host_info["local_hostname"] = hostname

    by_mac = host_info["network"]["interfaces"]["by-mac"]
    by_ipv4 = host_info["network"]["interfaces"]["by-ipv4"]
    by_ipv6 = host_info["network"]["interfaces"]["by-ipv6"]

    if not network_details:
        return host_info

    default_ipv4, default_ipv6 = get_default_ip_addresses(network_details)
    if default_ipv4:
        host_info[LOCAL_IPV4] = default_ipv4
        host_info[LOCAL_IPV4.replace('-', '_')] = default_ipv4
    if default_ipv6:
        host_info[LOCAL_IPV6] = default_ipv6
        host_info[LOCAL_IPV6.replace('-', '_')] = default_ipv6

    """
    IPv4: {
            'bcast': '',
            'ip': '127.0.0.1',
            'mask': '255.0.0.0',
            'scope': 'host',
          }
    IPv6: {
            'ip': '::1/128',
            'scope6': 'host'
          }
    """
    mac_by_link_names = {}
    for link in network_details.links:
        mac_by_link_names[link.name] = link.mac_address

    for net in network_details.networks:
        mac = mac_by_link_names[net.link]

        # Do not bother recording localhost
        if mac == "00:00:00:00:00:00":
            continue

        ip_net = netaddr.IPNetwork(net.address_cidr)
        addr = ip_net.ip
        is_v6 = addr.version == 6
        is_v4 = addr.version == 4

        if mac:
            if mac not in by_mac:
                val = {}
            else:
                val = by_mac[mac]
            key = None
            if is_v4:
                key = 'ipv4'
                val[key] = {
                    'addr': str(addr),
                    'netmask': str(ip_net.netmask),
                    'broadcast': str(ip_net.broadcast),
                }
            elif is_v6:
                key = 'ipv6'
                val[key] = {
                    'addr': str(addr),
                    'broadcast': str(ip_net.broadcast),
                }
            if key:
                by_mac[mac] = val

        if is_v4:
            by_ipv4[str(addr)] = {
                'mac': mac,
                'netmask': str(ip_net.netmask),
                'broadcast': str(ip_net.broadcast),
            }

        if is_v6:
            by_ipv6[str(addr)] = {
                'mac': mac,
                'broadcast': str(ip_net.broadcast),
            }

    return host_info


class NetworkConfigV1Parser(object):
    SUPPORTED_NETWORK_CONFIG_TYPES = [
        NETWORK_LINK_TYPE_PHY,
        NETWORK_LINK_TYPE_BOND,
        NETWORK_LINK_TYPE_VLAN,
        NETWORK_SERVICE_NAMESERVER
    ]

    def _parse_subnets(self, subnets, link_id):
        networks = []

        if not subnets or not isinstance(subnets, list):
            LOG.warning("Subnets '%s' is empty or not a list.",
                        subnets)
            return networks

        for subnet in subnets:
            if not isinstance(subnet, dict):
                LOG.warning("Subnet '%s' is not a dictionary",
                            subnet)
                continue

            if subnet.get("type") in [
                    SUBNET_TYPE_DHCP,
                    SUBNET_TYPE_DHCP6,
                    SUBNET_TYPE_MANUAL]:
                continue

            routes = []
            for route_data in subnet.get("routes", []):
                route_netmask = route_data.get("netmask")
                route_network = route_data.get("network")
                route_network_cidr = ip_netmask_to_cidr(
                    route_network, route_netmask)

                route_gateway = route_data.get("gateway")
                route = network_model.Route(
                    network_cidr=route_network_cidr,
                    gateway=route_gateway
                )
                routes.append(route)

            address_cidr = subnet.get("address")
            netmask = subnet.get("netmask")
            if netmask:
                address_cidr = ip_netmask_to_cidr(
                    address_cidr, netmask)

            gateway = subnet.get("gateway")
            if gateway:
                # Map the gateway as a default route, depending on the
                # IP family / version (4 or 6)
                gateway_net_cidr = "0.0.0.0/0"
                if netaddr.valid_ipv6(gateway):
                    gateway_net_cidr = "::/0"

                routes.append(
                    network_model.Route(
                        network_cidr=gateway_net_cidr,
                        gateway=gateway
                    )
                )

            networks.append(network_model.Network(
                link=link_id,
                address_cidr=address_cidr,
                dns_nameservers=subnet.get("dns_nameservers"),
                routes=routes
            ))

        return networks

    def _is_link_enabled(self, subnets):
        return SUBNET_TYPE_MANUAL not in [s.get("type") for s in subnets]

    def _parse_physical_config_item(self, item):
        if not item.get('name'):
            LOG.warning("Physical NIC does not have a name.")
            return

        link_id = item.get('id')
        name = item.get('name')
        if not link_id:
            link_id = name
        if not name:
            name = link_id
        subnets = item.get("subnets", [])

        link = network_model.Link(
            id=link_id,
            name=name,
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=self._is_link_enabled(subnets),
            mac_address=item.get('mac_address'),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=None,
            vlan_id=None
        )

        return network_model.NetworkDetailsV2(
            links=[link],
            networks=self._parse_subnets(subnets, link.id),
            services=[]
        )

    def _parse_bond_config_item(self, item):
        link_id = item.get('id')
        name = item.get('name')
        if not link_id:
            link_id = name
        if not name:
            name = link_id

        if not name:
            LOG.warning("Bond does not have a name.")
            return

        bond_params = item.get('params')
        if not bond_params:
            LOG.warning("Bond does not have parameters")
            return

        bond_mode = bond_params.get('bond-mode')
        if bond_mode not in network_model.AVAILABLE_BOND_TYPES:
            raise exception.CloudbaseInitException(
                "Unsupported bond mode: %s" % bond_mode)

        bond_lacp_rate = bond_params.get('bond-lacp-rate')
        if not bond_lacp_rate:
            bond_lacp_rate = None
        if (bond_lacp_rate and bond_lacp_rate not in
                network_model.AVAILABLE_BOND_LACP_RATES):
            raise exception.CloudbaseInitException(
                "Unsupported bond lacp rate: %s" % bond_lacp_rate)

        bond_xmit_hash_policy = bond_params.get("bond-xmit-hash-policy")
        if not bond_xmit_hash_policy:
            bond_xmit_hash_policy = bond_params.get('xmit_hash_policy')
        if (bond_xmit_hash_policy and bond_xmit_hash_policy not in
                network_model.AVAILABLE_BOND_LB_ALGORITHMS):
            raise exception.CloudbaseInitException(
                "Unsupported bond hash policy: %s" %
                bond_xmit_hash_policy)

        bond_interfaces = item.get('bond_interfaces')

        bond = network_model.Bond(
            members=bond_interfaces,
            type=bond_mode,
            lb_algorithm=bond_xmit_hash_policy,
            lacp_rate=bond_lacp_rate,
        )

        link = network_model.Link(
            id=link_id,
            name=name,
            type=network_model.LINK_TYPE_BOND,
            enabled=True,
            mac_address=item.get('mac_address'),
            mtu=item.get('mtu'),
            bond=bond,
            vlan_link=None,
            vlan_id=None
        )

        return network_model.NetworkDetailsV2(
            links=[link],
            networks=self._parse_subnets(item.get("subnets"), link.id),
            services=[]
        )

    def _parse_vlan_config_item(self, item):
        link_id = item.get('id')
        name = item.get('name')
        if not link_id:
            link_id = name
        if not name:
            name = link_id

        if not name:
            LOG.warning("VLAN NIC does not have a name.")
            return

        link = network_model.Link(
            id=link_id,
            name=name,
            type=network_model.LINK_TYPE_VLAN,
            enabled=True,
            mac_address=item.get('mac_address'),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=item.get('vlan_link'),
            vlan_id=item.get('vlan_id')
        )

        return network_model.NetworkDetailsV2(
            links=[link],
            networks=self._parse_subnets(item.get("subnets"), link.id),
            services=[]
        )

    def _parse_nameserver_config_item(self, item):
        return network_model.NetworkDetailsV2(
            links=[],
            networks=[],
            services=[network_model.NameServerService(
                addresses=item.get('address', []),
                search=item.get('search')
            )]
        )

    def _get_network_config_parser(self, parser_type):
        parsers = {
            NETWORK_LINK_TYPE_PHY: self._parse_physical_config_item,
            NETWORK_LINK_TYPE_BOND: self._parse_bond_config_item,
            NETWORK_LINK_TYPE_VLAN: self._parse_vlan_config_item,
            NETWORK_SERVICE_NAMESERVER: self._parse_nameserver_config_item
        }
        parser = parsers.get(parser_type)
        if not parser:
            raise exception.CloudbaseInitException(
                "Network config parser '%s' does not exist",
                parser_type)
        return parser

    def parse(self, network_config):
        links = []
        networks = []
        services = []

        if network_config and network_config.get('network'):
            network_config = network_config.get('network')
        if network_config:
            network_config = network_config.get('config')

        if not network_config:
            LOG.warning("Network configuration is empty")
            return

        if not isinstance(network_config, list):
            LOG.warning("Network config '%s' is not a list.",
                        network_config)
            return

        for network_config_item in network_config:
            if not isinstance(network_config_item, dict):
                LOG.warning("Network config item '%s' is not a dictionary",
                            network_config_item)
                continue

            net_conf_type = network_config_item.get("type")
            if net_conf_type not in self.SUPPORTED_NETWORK_CONFIG_TYPES:
                LOG.warning("Network config type '%s' is not supported",
                            net_conf_type)
                continue

            net_details = (
                self._get_network_config_parser(net_conf_type)
                                               (network_config_item))

            if net_details:
                links += net_details.links
                networks += net_details.networks
                services += net_details.services

        return network_model.NetworkDetailsV2(
            links=links,
            networks=networks,
            services=services
        )


class NetworkConfigV2Parser(object):
    SUPPORTED_NETWORK_CONFIG_TYPES = {
        NETWORK_LINK_TYPE_ETHERNET: 'ethernets',
        NETWORK_LINK_TYPE_BOND: 'bonds',
        NETWORK_LINK_TYPE_VLAN: 'vlans',
    }

    def _parse_mac_address(self, item):
        return item.get("match", {}).get("macaddress")

    def _parse_addresses(self, item, link_name):
        networks = []
        services = []

        routes = []
        # handle route config in deprecated gateway4/gateway6
        gateway4 = item.get("gateway4")
        gateway6 = item.get("gateway6")
        default_route = None
        if gateway6 and netaddr.valid_ipv6(gateway6):
            default_route = network_model.Route(
                network_cidr=DEFAULT_GATEWAY_CIDR_IPV6,
                gateway=gateway6)
        elif gateway4 and netaddr.valid_ipv4(gateway4):
            default_route = network_model.Route(
                network_cidr=DEFAULT_GATEWAY_CIDR_IPV4,
                gateway=gateway4)
        if default_route:
            routes.append(default_route)

        # netplan format config
        routes_config = item.get("routes", {})
        for route_config in routes_config:
            network_cidr = route_config.get("to")
            gateway = route_config.get("via")
            if network_cidr.lower() == "default":
                if netaddr.valid_ipv6(gateway):
                    network_cidr = DEFAULT_GATEWAY_CIDR_IPV6
                else:
                    network_cidr = DEFAULT_GATEWAY_CIDR_IPV4
            route = network_model.Route(
                network_cidr=network_cidr,
                gateway=gateway)
            routes.append(route)

        nameservers = item.get("nameservers", {})
        nameserver_addresses = nameservers.get("addresses", []) \
            if nameservers else []
        searches = nameservers.get("search", [])
        service = network_model.NameServerService(
            addresses=nameserver_addresses,
            search=','.join(searches) if searches else None,
        )
        services.append(service)

        addresses = item.get("addresses", [])
        for addr in addresses:
            network = network_model.Network(
                link=link_name,
                address_cidr=addr,
                dns_nameservers=nameserver_addresses,
                routes=routes
            )
            networks.append(network)

        return networks, services

    def _parse_ethernet_config_item(self, item):
        if not item.get('name'):
            LOG.warning("Ethernet does not have a name.")
            return

        name = item.get('name')
        eth_name = item.get("set-name", name)
        link = network_model.Link(
            id=name,
            name=eth_name,
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address=self._parse_mac_address(item),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=None,
            vlan_id=None
        )

        networks, services = self._parse_addresses(item, link.name)
        return network_model.NetworkDetailsV2(
            links=[link],
            networks=networks,
            services=services,
        )

    def _parse_bond_config_item(self, item):
        if not item.get('name'):
            LOG.warning("Bond does not have a name.")
            return

        bond_params = item.get('parameters')
        if not bond_params:
            LOG.warning("Bond does not have parameters")
            return

        bond_mode = bond_params.get('mode')
        if bond_mode not in network_model.AVAILABLE_BOND_TYPES:
            raise exception.CloudbaseInitException(
                "Unsupported bond mode: %s" % bond_mode)

        bond_lacp_rate = None
        if bond_mode == network_model.BOND_TYPE_8023AD:
            bond_lacp_rate = bond_params.get('lacp-rate')
            if (bond_lacp_rate and bond_lacp_rate not in
                    network_model.AVAILABLE_BOND_LACP_RATES):
                raise exception.CloudbaseInitException(
                    "Unsupported bond lacp rate: %s" % bond_lacp_rate)

        bond_xmit_hash_policy = bond_params.get('transmit-hash-policy')
        if (bond_xmit_hash_policy and bond_xmit_hash_policy not in
                network_model.AVAILABLE_BOND_LB_ALGORITHMS):
            raise exception.CloudbaseInitException(
                "Unsupported bond hash policy: %s" %
                bond_xmit_hash_policy)

        bond_interfaces = item.get('interfaces')

        bond = network_model.Bond(
            members=bond_interfaces,
            type=bond_mode,
            lb_algorithm=bond_xmit_hash_policy,
            lacp_rate=bond_lacp_rate,
        )

        link = network_model.Link(
            id=item.get('name'),
            name=item.get('name'),
            type=network_model.LINK_TYPE_BOND,
            enabled=True,
            mac_address=self._parse_mac_address(item),
            mtu=item.get('mtu'),
            bond=bond,
            vlan_link=None,
            vlan_id=None
        )

        networks, services = self._parse_addresses(item, link.name)
        return network_model.NetworkDetailsV2(
            links=[link],
            networks=networks,
            services=services
        )

    def _parse_vlan_config_item(self, item):
        if not item.get('name'):
            LOG.warning("VLAN NIC does not have a name.")
            return

        link = network_model.Link(
            id=item.get('name'),
            name=item.get('name'),
            type=network_model.LINK_TYPE_VLAN,
            enabled=True,
            mac_address=self._parse_mac_address(item),
            mtu=item.get('mtu'),
            bond=None,
            vlan_link=item.get('link'),
            vlan_id=item.get('id')
        )

        networks, services = self._parse_addresses(item, link.name)
        return network_model.NetworkDetailsV2(
            links=[link],
            networks=networks,
            services=services,
        )

    def _get_network_config_parser(self, parser_type):
        parsers = {
            NETWORK_LINK_TYPE_ETHERNET: self._parse_ethernet_config_item,
            NETWORK_LINK_TYPE_BOND: self._parse_bond_config_item,
            NETWORK_LINK_TYPE_VLAN: self._parse_vlan_config_item,
        }
        parser = parsers.get(parser_type)
        if not parser:
            raise exception.CloudbaseInitException(
                "Network config parser '%s' does not exist",
                parser_type)
        return parser

    def parse(self, network_config):
        links = []
        networks = []
        services = []

        if network_config and network_config.get('network'):
            network_config = network_config.get('network')

        if not network_config:
            LOG.warning("Network configuration is empty")
            return

        if not isinstance(network_config, dict):
            LOG.warning("Network config '%s' is not a dict.",
                        network_config)
            return

        for singular, plural in self.SUPPORTED_NETWORK_CONFIG_TYPES.items():
            network_config_items = network_config.get(plural, {})
            if not network_config_items:
                continue

            if not isinstance(network_config_items, dict):
                LOG.warning("Network config '%s' is not a dict",
                            network_config_items)
                continue

            for name, network_config_item in network_config_items.items():
                if not isinstance(network_config_item, dict):
                    LOG.warning(
                        "network config item '%s' of type %s is not a dict",
                        network_config_item, singular)
                    continue

                item = copy.deepcopy(network_config_item)
                item['name'] = name
                net_details = (
                    self._get_network_config_parser(singular)
                    (item))

                if net_details:
                    links += net_details.links
                    networks += net_details.networks
                    services += net_details.services

        return network_model.NetworkDetailsV2(
            links=links,
            networks=networks,
            services=services
        )


class NetworkConfigParser(object):

    @staticmethod
    def _enable_bond_physical_links(links):
        """Enables physical interfaces that are bond members.

        The MAAS metadata sets the NIC subnet type as "manual" for both
        disconnected NICs and bond members. We need to make sure that the
        latter are enabled.
        """

        for link1 in links:
            if link1.type == network_model.LINK_TYPE_BOND:
                for index, link2 in enumerate(links):
                    if (link2.type == network_model.LINK_TYPE_PHYSICAL and
                            not link2.enabled and
                            link2.id in link1.bond.members):
                        links[index] = link2._replace(enabled=True)

    @staticmethod
    def _create_bond_for_bondless_vlans(links: list, networks: list):
        """Creates bonds for interfaces that have vlans directly attached.

        It is possible to have a vlan attached to an individual interface,
        without a bond being created. The network configuration code requires
        that a network team is created for each interface that has vlans.
        We create bonds for such interfaces, and move configurations to that
        bond.
        """

        # Get list of bond interface IDs.
        bond_links = [
            link.id for link in links
            if link.type == network_model.LINK_TYPE_BOND]

        # List of links that needs bonds added.
        bondless_links = []

        # Find all vlan links without a bond interface.
        for link in links:
            if (link.type == network_model.LINK_TYPE_VLAN and
                    link.vlan_link is not None and
                    link.vlan_link not in bond_links and
                    link.vlan_link not in bondless_links):
                bondless_links.append(link.vlan_link)

        # Create bonds for bondless links.
        for link_id in bondless_links:
            # Find the physical link for this vlan.
            for link1 in links:
                if (link1.type == network_model.LINK_TYPE_PHYSICAL and
                        link1.id == link_id):

                    # Create a new bond link for this interface.
                    bond_id = "%s_vlan" % link1.id
                    LOG.debug('New bond interface %s' % bond_id)
                    bond = network_model.Bond(
                        members=[link1.id],
                        type="active-backup",
                        lb_algorithm="layer2",
                        lacp_rate=None
                    )
                    link = network_model.Link(
                        id=bond_id,
                        name=bond_id,
                        type=network_model.LINK_TYPE_BOND,
                        enabled=True,
                        mac_address=link1.mac_address,
                        mtu=link1.mtu,
                        bond=bond,
                        vlan_id=None,
                        vlan_link=None
                    )

                    # Update all vlan links on this interface to use the bond.
                    for index, link2 in enumerate(links):
                        if (link2.type == network_model.LINK_TYPE_VLAN and
                                link2.vlan_link == link1.id):
                            links[index] = link2._replace(vlan_link=bond_id)

                    # Add the bond link.
                    bond_links.append(bond_id)
                    links.append(link)

                    # Update all networks which are assigned to the physical
                    # interface, so that they are now assigned to the bond
                    # interface we created.
                    for index, net in enumerate(networks):
                        if net.link == link1.id:
                            networks[index] = net._replace(link=bond_id)
                    break

    @staticmethod
    def _prepare_and_clean_links(links: list, networks: list):
        """Prepares for network configuration.

        Looks for links configured without a physical interface, and bonds
        that already have team nics created. Removes links without a matching
        interface, and team nics so they can be re-configured.
        """

        # Get the OS utilities to check interfaces.
        osutils = osutils_factory.get_os_utils()

        # Enable disabled adapters to ensure all adapters are available
        # to configure.
        osutils.enable_disabled_network_adapters()

        # Get adapters on this system.
        network_adapters = osutils.get_network_adapters()

        # Keep track of what needs to be removed, we cannot remove links
        # as we are looping through the list.
        linksToRemove = []

        # Prepare links.
        for link in links:
            # If link type is physical, we need to verify it exists and
            # ensure its enabled. If it doesn't exist, we should remove it.
            if link.type == network_model.LINK_TYPE_PHYSICAL:
                # Find the physical link.
                foundPhysical = False
                for adapter in network_adapters:
                    if adapter[1].lower() == link.mac_address.lower():
                        foundPhysical = True
                        break

                # If not found, add to list of links to remove.
                if not foundPhysical:
                    LOG.info("The interface '%s' does not have an matching "
                             "physical adapter, removing."
                             % link.id)
                    linksToRemove.append(link.id)
                    continue

            # If link type is bond, and bond interface is already on
            # server. We need to reset, by removing the bond. Otherwise,
            # we'll get the error "Multiple network interfaces with MAC
            # address".
            elif (link.type == network_model.LINK_TYPE_BOND
                  and sys.platform == "win32"):
                # Find the link in adapter list.
                foundBond = False
                for adapter in network_adapters:
                    if adapter[0] == link.id:
                        foundBond = True
                        break

                # Remove the bond if it exists.
                if foundBond:
                    osutils._get_network_team_manager().delete_team(
                        networkconfig.BOND_FORMAT_STR % link.id)

                    # Allow some time for windows to propagate the change.
                    # Otherwise, we run into errors when we re-create the
                    # bond.
                    time.sleep(10)

        # Remove links that physical interfaces do not exist for.
        for link_id in linksToRemove:
            # Remove all links.
            for index, link in enumerate(links):
                if link.id == link_id:
                    links.pop(index)
                    break

            # Remove all networks relating to this link.
            foundNet = True
            while foundNet:
                foundNet = False
                for index, net in enumerate(networks):
                    if net.link == link_id:
                        foundNet = True
                        networks.pop(index)
                        break

    @staticmethod
    def parse(network_data):
        # we can have a network key in some cases
        if network_data.get("network"):
            network_data = network_data.get("network")
        network_data_version = network_data.get("version")

        if network_data_version == 1:
            network_config_parser = NetworkConfigV1Parser()
        elif network_data_version == 2:
            network_config_parser = NetworkConfigV2Parser()
        else:
            raise exception.CloudbaseInitException(
                "Unsupported network_data_version: '%s'"
                % network_data_version)

        net_details = network_config_parser.parse(network_data)

        # Windows requires a team nic to be created before you can add vlans
        # to an interface. The network config plugin uses bonds to create team
        # nics, so we need to make a virtual bond for every interface that is
        # assigned vlans.
        NetworkConfigParser._create_bond_for_bondless_vlans(
            net_details.links, net_details.networks)

        # Interfaces that are on a bond in MaaS does not have subnets which
        # ends up going disabled. We need to re-enable the interfaces,
        # so that the bond can be created ontop of it.
        NetworkConfigParser._enable_bond_physical_links(net_details.links)

        # Cleanup the link and network list, to ensure we do not have
        # stray networks.
        NetworkConfigParser._prepare_and_clean_links(
            net_details.links,
            net_details.networks)

        return net_details

    @staticmethod
    def network_details_v1_to_v2(v1_networks):
        """Converts `NetworkDetails` objects to `NetworkDetailsV2` object.

        """
        if not v1_networks:
            return None

        links = []
        networks = []
        services = []
        for nic in v1_networks:
            link = network_model.Link(
                id=nic.name,
                name=nic.name,
                type=network_model.LINK_TYPE_PHYSICAL,
                mac_address=nic.mac,
                enabled=None,
                mtu=None,
                bond=None,
                vlan_link=None,
                vlan_id=None,
            )
            links.append(link)

            dns_addresses_v4 = []
            dns_addresses_v6 = []
            if nic.dnsnameservers:
                for ns in nic.dnsnameservers:
                    if netaddr.valid_ipv6(ns):
                        dns_addresses_v6.append(ns)
                    else:
                        dns_addresses_v4.append(ns)

            dns_services_v6 = None
            if dns_addresses_v6:
                dns_service_v6 = network_model.NameServerService(
                    addresses=dns_addresses_v6,
                    search=None,
                )
                dns_services_v6 = [dns_service_v6]
                services.append(dns_service_v6)

            dns_services_v4 = None
            if dns_addresses_v4:
                dns_service_v4 = network_model.NameServerService(
                    addresses=dns_addresses_v4,
                    search=None,
                )
                dns_services_v4 = [dns_service_v4]
                services.append(dns_service_v4)

            # Note: IPv6 address might be set to IPv4 field
            # Not sure if it's a bug
            default_route_v6 = None
            default_route_v4 = None
            if nic.gateway6:
                default_route_v6 = network_model.Route(
                    network_cidr=DEFAULT_GATEWAY_CIDR_IPV6,
                    gateway=nic.gateway6)

            if nic.gateway:
                if netaddr.valid_ipv6(nic.gateway):
                    default_route_v6 = network_model.Route(
                        network_cidr=DEFAULT_GATEWAY_CIDR_IPV6,
                        gateway=nic.gateway)
                else:
                    default_route_v4 = network_model.Route(
                        network_cidr=DEFAULT_GATEWAY_CIDR_IPV4,
                        gateway=nic.gateway)

            routes_v6 = [default_route_v6] if default_route_v6 else []
            routes_v4 = [default_route_v4] if default_route_v4 else []

            if nic.address6:
                net = network_model.Network(
                    link=link.name,
                    address_cidr=ip_netmask_to_cidr(
                        nic.address6, nic.netmask6),
                    routes=routes_v6,
                    dns_nameservers=dns_services_v6,
                )
                networks.append(net)

            if nic.address:
                if netaddr.valid_ipv6(nic.address):
                    net = network_model.Network(
                        link=link.name,
                        address_cidr=ip_netmask_to_cidr(
                            nic.address, nic.netmask),
                        routes=routes_v6,
                        dns_nameservers=dns_services_v6,
                    )
                else:
                    net = network_model.Network(
                        link=link.name,
                        address_cidr=ip_netmask_to_cidr(
                            nic.address, nic.netmask),
                        routes=routes_v4,
                        dns_nameservers=dns_services_v4,
                    )
                networks.append(net)

        return network_model.NetworkDetailsV2(links=links,
                                              networks=networks,
                                              services=services)
