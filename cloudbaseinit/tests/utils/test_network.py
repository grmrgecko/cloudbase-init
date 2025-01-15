# Copyright 2013 Cloudbase Solutions Srl
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

import collections
import ddt
import importlib
import textwrap
import unittest
import unittest.mock as mock

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.models import network as network_model
from cloudbaseinit.tests.metadata import fake_json_response
from cloudbaseinit.tests import testutils
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import network
from cloudbaseinit.utils import serialization


CONF = cloudbaseinit_conf.CONF

MODULE_PATH = "cloudbaseinit.utils.network"
NETWORK_CONFIG_TEST_DATA_V1_EMPTY_CONFIG = """
network:
  version: 1
  t: 1
"""
NETWORK_CONFIG_TEST_DATA_V1_CONFIG_IS_NOT_LIST = """
network:
  version: 1
  config: {
    test: abc
  }
"""
NETWORK_CONFIG_TEST_DATA_V1_CONFIG_ITEM_IS_NOT_DICT = """
network:
  version: 1
  config:
  - ['test', 'abc']
"""
NETWORK_CONFIG_TEST_DATA_V1_ROUTER_CONFIG_NOT_SUPPORTED = """
network:
  version: 1
  config:
  - type: router
"""
NETWORK_CONFIG_TEST_DATA_V1_LEGACY = """
version: 1
config:
- type: physical
  name: interface0
  mac_address: "52:54:00:12:34:00"
  mtu: 1450
  subnets:
  - type: static
    address: 192.168.1.10
    netmask: 255.255.255.0
    gateway: 192.168.1.1
    dns_nameservers:
    - 192.168.1.11
- type: bond
  name: bond0
  bond_interfaces:
  - gbe0
  - gbe1
  mac_address: "52:54:00:12:34:00"
  params:
    bond-mode: active-backup
    bond-lacp-rate: false
  mtu: 1450
  subnets:
  - type: static
    address: 192.168.1.10
    netmask: 255.255.255.0
    dns_nameservers:
    - 192.168.1.11
- type: vlan
  name: vlan0
  vlan_link: eth1
  vlan_id: 150
  mac_address: "52:54:00:12:34:00"
  mtu: 1450
  subnets:
  - type: static
    address: 192.168.1.10
    netmask: 255.255.255.0
    dns_nameservers:
    - 192.168.1.11
- type: nameserver
  address:
  - 192.168.23.2
  - 8.8.8.8
  search: acme.local
"""
NETWORK_CONFIG_TEST_DATA_V1 = """
network:%s
""" % (textwrap.indent(NETWORK_CONFIG_TEST_DATA_V1_LEGACY, "  "))
NETWORK_CONFIG_TEST_DATA_V2_EMPTY_CONFIG = """
"""
NETWORK_CONFIG_TEST_DATA_V2_CONFIG_IS_NOT_DICT = """
network:
- config
"""
NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_IS_NOT_DICT = """
network:
  version: 2
  ethernets:
  - test
"""
NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_SETTING_IS_NOT_DICT = """
network:
  version: 2
  ethernets:
    eth0:
     - test
"""
NETWORK_CONFIG_TEST_DATA_V2_LEGACY = """
version: 2
ethernets:
  interface0:
    match:
      macaddress: "52:54:00:12:34:00"
    set-name: "eth0"
    addresses:
    - 192.168.1.10/24
    gateway4: 192.168.1.1
    nameservers:
      addresses:
      - 192.168.1.11
      - 192.168.1.12
      search:
      - acme.local
    mtu: 1450
  interface1:
    set-name: "interface1"
    addresses:
    - 192.168.1.100/24
    gateway4: 192.168.1.1
    nameservers:
      addresses:
      - 192.168.1.11
      - 192.168.1.12
      search:
      - acme.local
bonds:
  bond0:
    interfaces: ["gbe0", "gbe1"]
    match:
      macaddress: "52:54:00:12:34:00"
    parameters:
      mode: active-backup
      lacp-rate: false
    addresses:
    - 192.168.1.10/24
    nameservers:
      addresses:
      - 192.168.1.11
    mtu: 1450
vlans:
  vlan0:
    id: 150
    link: eth1
    dhcp4: yes
    match:
      macaddress: "52:54:00:12:34:00"
    addresses:
    - 192.168.1.10/24
    nameservers:
      addresses:
      - 192.168.1.11
    mtu: 1450
bridges:
  br0:
    interfaces: ['eth0']
    dhcp4: true
"""
NETWORK_CONFIG_TEST_DATA_V2 = """
network:%s
""" % (textwrap.indent(NETWORK_CONFIG_TEST_DATA_V2_LEGACY, "  "))


@ddt.ddt
class TestNetworkConfigV1Parser(unittest.TestCase):
    def setUp(self):
        module = importlib.import_module(MODULE_PATH)
        self._parser = module.NetworkConfigV1Parser()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @ddt.data(
        (NETWORK_CONFIG_TEST_DATA_V1_EMPTY_CONFIG,
            ('Network configuration is empty', None)),
        (NETWORK_CONFIG_TEST_DATA_V1_CONFIG_IS_NOT_LIST,
         ("is not a list", None)),
        (NETWORK_CONFIG_TEST_DATA_V1_CONFIG_ITEM_IS_NOT_DICT,
         ("is not a dictionary",
          network_model.NetworkDetailsV2(links=[], networks=[], services=[]))),
        (NETWORK_CONFIG_TEST_DATA_V1_ROUTER_CONFIG_NOT_SUPPORTED,
         ("Network config type 'router' is not supported",
          network_model.NetworkDetailsV2(links=[], networks=[], services=[])))
    )
    @ddt.unpack
    def test_parse_empty_result(self, input, expected_result):

        with self.snatcher:
            result = self._parser.parse(serialization.parse_json_yaml(input))

        self.assertEqual(True, expected_result[0] in self.snatcher.output[0])
        self.assertEqual(result, expected_result[1])

    @ddt.data(
        (NETWORK_CONFIG_TEST_DATA_V1, True),
        (NETWORK_CONFIG_TEST_DATA_V1_LEGACY, True)
    )
    @ddt.unpack
    def test_network_details_v2(self, test_data, expected_result):
        expected_bond = network_model.Bond(
            members=["gbe0", "gbe1"],
            type=network_model.BOND_TYPE_ACTIVE_BACKUP,
            lb_algorithm=None,
            lacp_rate=None,
        )
        expected_link_bond = network_model.Link(
            id='bond0',
            name='bond0',
            type=network_model.LINK_TYPE_BOND,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=expected_bond,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link = network_model.Link(
            id='interface0',
            name='interface0',
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link_vlan = network_model.Link(
            id='vlan0',
            name='vlan0',
            type=network_model.LINK_TYPE_VLAN,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link='eth1',
            vlan_id=150,
        )
        expected_network = network_model.Network(
            link='interface0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[
                network_model.Route(
                    network_cidr='0.0.0.0/0',
                    gateway="192.168.1.1",
                    metric=256)
            ]
        )

        expected_network_bond = network_model.Network(
            link='bond0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )

        expected_network_vlan = network_model.Network(
            link='vlan0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )
        expected_nameservers = network_model.NameServerService(
            addresses=['192.168.23.2', '8.8.8.8'],
            search='acme.local')

        result = self._parser.parse(
            serialization.parse_json_yaml(test_data))

        self.assertEqual(result.links[0], expected_link)
        self.assertEqual(result.networks[0], expected_network)

        self.assertEqual(result.links[1], expected_link_bond)
        self.assertEqual(result.networks[1], expected_network_bond)

        self.assertEqual(result.links[2], expected_link_vlan)
        self.assertEqual(result.networks[2], expected_network_vlan)

        self.assertEqual(result.services[0], expected_nameservers)


@ddt.ddt
class TestNetworkConfigV2Parser(unittest.TestCase):
    def setUp(self):
        module = importlib.import_module(MODULE_PATH)
        self._parser = module.NetworkConfigV2Parser()
        self.snatcher = testutils.LogSnatcher(MODULE_PATH)

    @ddt.data(
        (NETWORK_CONFIG_TEST_DATA_V2_EMPTY_CONFIG,
         ('Network configuration is empty', None)),
        (NETWORK_CONFIG_TEST_DATA_V2_CONFIG_IS_NOT_DICT,
         ('is not a dict', None)),
        (NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_IS_NOT_DICT,
         ('is not a dict',
          network_model.NetworkDetailsV2(links=[], networks=[], services=[])),
         ),
        (NETWORK_CONFIG_TEST_DATA_V2_CONFIG_ITEM_SETTING_IS_NOT_DICT,
         ('of type ethernet is not a dict',
          network_model.NetworkDetailsV2(links=[], networks=[], services=[])),
         )
    )
    @ddt.unpack
    def test_parse_empty_result(self, input, expected_result):
        with self.snatcher:
            result = self._parser.parse(serialization.parse_json_yaml(input))

        self.assertEqual(True, expected_result[0] in self.snatcher.output[0])
        self.assertEqual(result, expected_result[1])

    @ddt.data(
        (NETWORK_CONFIG_TEST_DATA_V2, True),
        (NETWORK_CONFIG_TEST_DATA_V2_LEGACY, True)
    )
    @ddt.unpack
    def test_network_details_v2(self, test_data, expected_result):
        expected_bond = network_model.Bond(
            members=["gbe0", "gbe1"],
            type=network_model.BOND_TYPE_ACTIVE_BACKUP,
            lb_algorithm=None,
            lacp_rate=None,
        )
        expected_link_bond = network_model.Link(
            id='bond0',
            name='bond0',
            type=network_model.LINK_TYPE_BOND,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=expected_bond,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link = network_model.Link(
            id='interface0',
            name='eth0',
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link_if1 = network_model.Link(
            id='interface1',
            name='interface1',
            type=network_model.LINK_TYPE_PHYSICAL,
            enabled=True,
            mac_address=None,
            mtu=None,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        expected_link_vlan = network_model.Link(
            id='vlan0',
            name='vlan0',
            type=network_model.LINK_TYPE_VLAN,
            enabled=True,
            mac_address="52:54:00:12:34:00",
            mtu=1450,
            bond=None,
            vlan_link='eth1',
            vlan_id=150,
        )
        expected_network = network_model.Network(
            link='eth0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11', '192.168.1.12'],
            routes=[
                network_model.Route(
                    network_cidr='0.0.0.0/0',
                    gateway="192.168.1.1",
                    metric=256)
            ]
        )
        expected_network_if1 = network_model.Network(
            link='interface1',
            address_cidr='192.168.1.100/24',
            dns_nameservers=['192.168.1.11', '192.168.1.12'],
            routes=[
                network_model.Route(
                    network_cidr='0.0.0.0/0',
                    gateway="192.168.1.1",
                    metric=256)
            ]
        )

        expected_network_bond = network_model.Network(
            link='bond0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )

        expected_network_vlan = network_model.Network(
            link='vlan0',
            address_cidr='192.168.1.10/24',
            dns_nameservers=['192.168.1.11'],
            routes=[],
        )
        expected_nameservers = network_model.NameServerService(
            addresses=['192.168.1.11', '192.168.1.12'],
            search='acme.local')

        result = self._parser.parse(
            serialization.parse_json_yaml(test_data))

        self.assertEqual(result.links[0], expected_link)
        self.assertEqual(result.links[1], expected_link_if1)
        self.assertEqual(result.networks[0], expected_network)
        self.assertEqual(result.networks[1], expected_network_if1)

        self.assertEqual(result.links[2], expected_link_bond)
        self.assertEqual(result.networks[2], expected_network_bond)

        self.assertEqual(result.links[3], expected_link_vlan)
        self.assertEqual(result.networks[3], expected_network_vlan)

        self.assertEqual(result.services[0], expected_nameservers)


class NetworkUtilsTest(unittest.TestCase):
    link0 = network_model.Link(
        id="eth0",
        name="eth0",
        type=network_model.LINK_TYPE_PHYSICAL,
        mac_address="ab:cd:ef:ef:cd:ab",
        enabled=None,
        mtu=None,
        bond=None,
        vlan_link=None,
        vlan_id=None,
    )
    network_private_default_route = network_model.Network(
        link="eth0",
        address_cidr="192.168.1.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"0.0.0.0/0",
                gateway="192.168.1.1",
                metric=256
            ),
        ],
        dns_nameservers=[]
    )
    network_public = network_model.Network(
        link="eth0",
        address_cidr="2.3.4.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"2.3.4.1/24",
                gateway="2.3.4.1",
                metric=256
            ),
        ],
        dns_nameservers=[]
    )
    network_public_default_route = network_model.Network(
        link="eth0",
        address_cidr="2.3.4.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"0.0.0.0/0",
                gateway="2.3.4.1",
                metric=256
            ),
        ],
        dns_nameservers=[]
    )
    network_private = network_model.Network(
        link="eth0",
        address_cidr="172.10.1.2/24",
        routes=[
            network_model.Route(
                network_cidr=u"172.10.1.1/24",
                gateway="172.10.1.1",
                metric=256
            ),
        ],
        dns_nameservers=[]
    )
    network_local = network_model.Network(
        link="eth0",
        address_cidr="127.0.0.4/24",
        routes=[
            network_model.Route(
                network_cidr=u"127.0.0.4/24",
                gateway="127.0.0.2",
                metric=256
            ),
        ],
        dns_nameservers=[]
    )
    ipv6_addr = '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38'
    network_v6 = network_model.Network(
        link="eth0",
        address_cidr=ipv6_addr + '/64',
        routes=[network_model.Route(
            network_cidr=u"::/0",
            gateway="::1",
            metric=256
        )],
        dns_nameservers=[]
    )
    ipv6_addr_private = 'fe80::216:3eff:fe16:db54'
    network_v6_local = network_model.Network(
        link="eth0",
        address_cidr=ipv6_addr_private + '/64',
        routes=[],
        dns_nameservers=[]
    )

    @mock.patch('urllib.request.urlopen')
    def test_check_url(self, mock_url_open):
        mock_url_open.return_value = None
        self.assertTrue(network.check_url("fake_url"))

    @mock.patch('sys.platform', new='win32')
    @mock.patch('cloudbaseinit.osutils.factory.get_os_utils')
    @mock.patch('urllib.parse.urlparse')
    def _test_check_metadata_ip_route(self, mock_urlparse, mock_get_os_utils,
                                      side_effect):
        mock_utils = mock.MagicMock()
        mock_get_os_utils.return_value = mock_utils
        mock_utils.check_os_version.return_value = True
        mock_urlparse().netloc.split.return_value = ['169.254.128.254']
        mock_utils.check_static_route_exists.return_value = False
        mock_utils.get_default_gateway.return_value = ('eth1', '0.0.0.0')
        mock_utils.add_static_route.side_effect = [side_effect]
        network.check_metadata_ip_route('196.254.196.254')
        mock_utils.check_os_version.assert_called_once_with(6, 0)
        mock_urlparse.assert_called_with('196.254.196.254')
        mock_utils.check_static_route_exists.assert_called_once_with(
            '169.254.128.254/32')
        mock_utils.get_default_gateway.assert_called_once_with()
        mock_utils.add_static_route.assert_called_once_with(
            'eth1', '169.254.128.254/32', '0.0.0.0', 10)

    def test_test_check_metadata_ip_route(self):
        self._test_check_metadata_ip_route(side_effect=None)

    def test_test_check_metadata_ip_route_fail(self):
        with testutils.LogSnatcher(MODULE_PATH) as snatcher:
            self._test_check_metadata_ip_route(side_effect=ValueError)

        self.assertIn('ValueError', snatcher.output[-1])

    def test_address6_to_4_truncate(self):
        address_map = {
            "0:0:0:0:0:ffff:c0a8:f": "192.168.0.15",
            "::ffff:c0a8:e": "192.168.0.14",
            "::1": "0.0.0.1",
            "1:2:3:4:5::8": "0.0.0.8",
            "::": "0.0.0.0",
            "::7f00:1": "127.0.0.1"
        }
        for v6, v4 in address_map.items():
            self.assertEqual(v4, network.address6_to_4_truncate(v6))

    def test_netmask6_to_4_truncate(self):
        netmask_map = {
            "128": "255.255.255.255",
            "96": "255.255.255.0",
            "0": "0.0.0.0",
            "100": "255.255.255.128"
        }
        for v6, v4 in netmask_map.items():
            self.assertEqual(v4, network.netmask6_to_4_truncate(v6))

    @mock.patch('socket.socket')
    def test_get_local_ip(self, mock_socket):
        mock_socket.return_value = mock.Mock()
        mock_socket().getsockname.return_value = ["fake name"]
        res = network.get_local_ip("fake address")
        self.assertEqual(res, "fake name")
        mock_socket().connect.assert_called_with(("fake address", 8000))

    def _test_ip_netmask_to_cidr(self, expected_result, fake_ip_address,
                                 fake_netmask):
        result = network.ip_netmask_to_cidr(fake_ip_address, fake_netmask)
        self.assertEqual(expected_result, result)

    def test_ip_netmask_to_cidr(self):
        fake_ip_address = '10.1.1.1'
        expected_result = '10.1.1.1/24'
        fake_netmask = '255.255.255.0'
        self._test_ip_netmask_to_cidr(expected_result, fake_ip_address,
                                      fake_netmask)

    def test_ip_netmask_to_cidr_empty_netmask(self):
        fake_ip_address = '10.1.1.1'
        fake_netmask = None
        self._test_ip_netmask_to_cidr(fake_ip_address, fake_ip_address,
                                      fake_netmask)

    def test_get_default_ip_addresses(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private_default_route,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertEqual('192.168.1.2', ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_link_local(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertIsNone(ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_public_default_route(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_public_default_route,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertEqual("2.3.4.2", ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_v6(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_v6,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertIsNone(ipv4)
        self.assertEqual(self.ipv6_addr, ipv6)

    def test_get_default_ip_addresses_v6_local(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_v6_local,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertIsNone(ipv4)
        self.assertIsNone(ipv6)

    def test_get_default_ip_addresses_dual_stack(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private_default_route,
                self.network_public,
                self.network_v6,
            ],
            services=[
            ],
        )
        ipv4, ipv6 = network.get_default_ip_addresses(network_details)
        self.assertEqual('192.168.1.2', ipv4)
        self.assertEqual(self.ipv6_addr, ipv6)

    def test_get_host_info(self):
        network_details = network_model.NetworkDetailsV2(
            links=[
                self.link0
            ],
            networks=[
                self.network_private_default_route,
                self.network_public, self.network_v6,
            ],
            services=[
            ],
        )
        expect = {
            'hostname': 'fake_host',
            'local-hostname': 'fake_host',
            'local-ipv4': '192.168.1.2',
            'local_ipv4': '192.168.1.2',
            'local-ipv6': '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
            'local_ipv6': '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
            'local_hostname': 'fake_host',
            'network': {'interfaces': {
                'by-ipv4': collections.OrderedDict([
                    ('192.168.1.2',
                     {'broadcast': '192.168.1.255',
                      'mac': 'ab:cd:ef:ef:cd:ab',
                      'netmask': '255.255.255.0'}
                     ),
                    ('2.3.4.2',
                     {'broadcast': '2.3.4.255',
                      'mac': 'ab:cd:ef:ef:cd:ab',
                      'netmask': '255.255.255.0'}
                     )
                ]),
                'by-ipv6': collections.OrderedDict([
                    ('1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
                     {'broadcast': '1a8f:9aaf:2904:858f:ffff:ffff:ffff:ffff',
                      'mac': 'ab:cd:ef:ef:cd:ab',
                      }
                     )
                ]),
                'by-mac': collections.OrderedDict([
                    ('ab:cd:ef:ef:cd:ab',
                     {'ipv4': {'addr': '2.3.4.2',
                               'broadcast': '2.3.4.255',
                               'netmask': '255.255.255.0'},
                      'ipv6': {
                          'addr': '1a8f:9aaf:2904:858f:1bce:6f85:2b04:f38',
                          'broadcast': '1a8f:9aaf:2904:858f:'
                                       'ffff:ffff:ffff:ffff'}
                      }
                     ),
                ])
            }}
        }
        host_info = network.get_host_info('fake_host', network_details)
        self.assertEqual(expect, host_info)

    def test_to_network_details_v2(self):
        date = "2013-04-04"
        content = fake_json_response.get_fake_metadata_json(date)
        nics = debiface.parse(content["network_config"]["debian_config"])
        v2 = network.NetworkConfigParser.network_details_v1_to_v2(nics)
        link0 = network_model.Link(
            id=fake_json_response.NAME0,
            name=fake_json_response.NAME0,
            type=network_model.LINK_TYPE_PHYSICAL,
            mac_address=fake_json_response.MAC0.upper(),
            enabled=None,
            mtu=None,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        link1 = network_model.Link(
            id=fake_json_response.NAME1,
            name=fake_json_response.NAME1,
            type=network_model.LINK_TYPE_PHYSICAL,
            mac_address=None,
            enabled=None,
            mtu=None,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        link2 = network_model.Link(
            id=fake_json_response.NAME2,
            name=fake_json_response.NAME2,
            type=network_model.LINK_TYPE_PHYSICAL,
            mac_address=fake_json_response.MAC2,
            enabled=None,
            mtu=None,
            bond=None,
            vlan_link=None,
            vlan_id=None,
        )
        dns_service0 = network_model.NameServerService(
            addresses=fake_json_response.DNSNS0.split(),
            search=None,
        )
        network0 = network_model.Network(
            link=fake_json_response.NAME0,
            address_cidr=network.ip_netmask_to_cidr(
                fake_json_response.ADDRESS0, fake_json_response.NETMASK0),
            routes=[network_model.Route(
                network_cidr=u"0.0.0.0/0",
                gateway=fake_json_response.GATEWAY0,
                metric=256
            )],
            dns_nameservers=[dns_service0],
        )
        network0_v6 = network_model.Network(
            link=fake_json_response.NAME0,
            address_cidr=network.ip_netmask_to_cidr(
                fake_json_response.ADDRESS60, fake_json_response.NETMASK60),
            routes=[network_model.Route(
                network_cidr=u"::/0",
                gateway=fake_json_response.GATEWAY60,
                metric=256
            )],
            dns_nameservers=None,
        )
        network1 = network_model.Network(
            link=fake_json_response.NAME1,
            address_cidr=network.ip_netmask_to_cidr(
                fake_json_response.ADDRESS1, fake_json_response.NETMASK1),
            routes=[network_model.Route(
                network_cidr=u"0.0.0.0/0",
                gateway=fake_json_response.GATEWAY1,
                metric=256
            )],
            dns_nameservers=None,
        )
        network2 = network_model.Network(
            link=fake_json_response.NAME2,
            address_cidr=network.ip_netmask_to_cidr(
                fake_json_response.ADDRESS2, fake_json_response.NETMASK2),
            routes=[network_model.Route(
                network_cidr=u"::/0",
                gateway=fake_json_response.GATEWAY2,
                metric=256
            )],
            dns_nameservers=None,
        )
        expected = network_model.NetworkDetailsV2(
            links=[
                link0, link1, link2,
            ],
            networks=[
                network0_v6, network0, network1, network2,
            ],
            services=[
                dns_service0
            ],
        )
        self.assertEqual(expected, v2)
