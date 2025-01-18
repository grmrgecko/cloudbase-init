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


import sys
import unittest
import unittest.mock as mock
from unittest.mock import call

from cloudbaseinit.models import network as network_model
from cloudbaseinit.plugins.common import localnetworkconfig

AF_INET = 2
AF_INET6 = 23

NETWORK_JSON_CONFIG = """
{
  "config": [
    {
      "id": "eno1",
      "mac_address": "52:54:00:12:34:00",
      "mtu": 1500,
      "name": "eno1",
      "subnets": [
        {
          "type": "manual"
        }
      ],
      "type": "physical"
    },
    {
      "id": "eno1.10",
      "mtu": 1500,
      "name": "eno1.10",
      "subnets": [
        {
          "address": "10.0.10.21/24",
          "dns_nameservers": [
            "1.1.1.1",
            "8.8.8.8"
          ],
          "dns_search": [
            "maas"
          ],
          "gateway": "10.0.10.1",
          "type": "static"
        }
      ],
      "type": "vlan",
      "vlan_id": 10,
      "vlan_link": "eno1"
    },
    {
      "id": "eno1.20",
      "mtu": 1500,
      "name": "eno1.20",
      "subnets": [
        {
          "address": "fc00:1:2:3::7/64",
          "type": "static",
          "routes": [
            {
              "destination": "fc00:1:2:3::1/128",
              "gateway": "fe80::1",
              "metric": 250
            }
          ]
        }
      ],
      "type": "vlan",
      "vlan_id": 20,
      "vlan_link": "eno1"
    },
    {
      "id": "eno2",
      "mac_address": "52:54:00:12:34:01",
      "mtu": 1500,
      "name": "eno2",
      "subnets": [
        {
          "type": "manual"
        }
      ],
      "type": "physical"
    },
    {
      "id": "eno3",
      "mac_address": "52:54:00:12:34:02",
      "mtu": 1500,
      "name": "eno3",
      "subnets": [
        {
          "type": "dhcp4"
        }
      ],
      "type": "physical"
    },
    {
      "address": [
        "1.1.1.1",
        "8.8.8.8"
      ],
      "search": [
        "maas"
      ],
      "type": "nameserver"
    }
  ],
  "version": 1
}
"""

NETWORK_YAML_CONFIG = """
network:
  bonds:
    bond0:
      dhcp4: true
      interfaces:
      - eth0
      - eth1
      macaddress: 52:54:00:dc:cb:67
      mtu: 1500
      parameters:
        down-delay: 0
        gratuitious-arp: 1
        mii-monitor-interval: 0
        mode: active-backup
        transmit-hash-policy: layer2
        up-delay: 0
  ethernets:
    eth0:
      match:
        macaddress: 52:54:00:dc:cb:67
      mtu: 1500
      set-name: eth0
    eth1:
      match:
        macaddress: 52:54:00:8c:fb:03
      mtu: 1500
      set-name: eth1
    eth2:
      match:
        macaddress: 52:54:00:6c:5b:24
      mtu: 1500
      set-name: eth2
  version: 2
  vlans:
    bond0.30:
      addresses:
      - 10.30.20.88/28
      gateway4: 10.30.20.81
      id: 30
      link: bond0
      mtu: 1500
      nameservers:
        addresses:
        - 10.30.20.81
        search:
        - maas
      routes:
      - to: 10.20.10.0/24
        via: 10.30.20.82
        metric: 128
    bond0.55:
      addresses:
      - fc00:1:0:4:1:0:1:6/64
      id: 55
      link: bond0
      mtu: 1500
      nameservers:
        addresses:
        - 10.30.20.81
        search:
        - maas
      routes:
      - to: fc00:1:0:4::1/128
        via: fe80::1
        metric: 250
"""


class TestLocalNetworkConfigPlugin(unittest.TestCase):

    @mock.patch("builtins.open", new_callable=mock.mock_open,
                read_data=NETWORK_JSON_CONFIG)
    @mock.patch("os.path.isfile")
    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def test_json_config(self, mock_get_os_util, mock_isfile, mock_file):
        # Setup the osutils mock tool.
        osutils = mock.MagicMock()
        osutils.get_config_value.return_value = None

        # When get os utils is called, return the mock.
        mock_get_os_util.return_value = osutils

        # Default isfile to True.
        mock_isfile.return_value = True

        # Setup test data.
        mock.sentinel.mac1 = "52:54:00:12:34:00"
        mock.sentinel.mac2 = "52:54:00:12:34:01"
        mock.sentinel.mac3 = "52:54:00:12:34:02"
        mock.sentinel.name1 = "eno1"
        mock.sentinel.name2 = "eno2"
        mock.sentinel.name3 = "eno3"
        mock.sentinel.bond_name = "eno1_vlan"
        mock.sentinel.bond_id = "bond_eno1_vlan"
        mock.sentinel.vlan1 = "eno1.10"
        mock.sentinel.vlan2 = "eno1.20"
        nameservers = ['1.1.1.1', '8.8.8.8']
        osutils.get_network_adapter_name_by_mac_address.side_effect = [
            mock.sentinel.old_name1, mock.sentinel.old_name2,
            mock.sentinel.old_name3]
        osutils.get_network_adapters.return_value = [
            (mock.sentinel.old_name1, mock.sentinel.mac1),
            (mock.sentinel.old_name2, mock.sentinel.mac2),
            (mock.sentinel.old_name3, mock.sentinel.mac3)]

        # Windows specific test data.
        adapter_enabled = mock.Mock()
        adapter_enabled.NetEnabled = True
        adapter_disabled = mock.Mock()
        adapter_disabled.NetEnabled = False
        osutils._get_network_adapter.side_effect = [
            adapter_enabled, adapter_enabled, adapter_enabled,
            adapter_disabled, adapter_enabled]

        # Call the plugin.
        service = mock.Mock()
        plugin = localnetworkconfig.LocalNetworkConfigPlugin()
        plugin.execute(service, {})

        # Confirm it read the correct file.
        mock_file.assert_called_with('/curtin/network.json', 'r')

        # Confirm the interface rename was called.
        osutils.rename_network_adapter.assert_any_call(
            mock.sentinel.old_name1, mock.sentinel.name1)
        osutils.rename_network_adapter.assert_any_call(
            mock.sentinel.old_name2, mock.sentinel.name2)
        osutils.rename_network_adapter.assert_any_call(
            mock.sentinel.old_name3, mock.sentinel.name3)

        # Confirm network enable/disable function.
        osutils.enable_network_adapter.assert_any_call(
            mock.sentinel.name1, True)
        osutils.enable_network_adapter.assert_any_call(
            mock.sentinel.name2, False)
        osutils.enable_network_adapter.assert_any_call(
            mock.sentinel.name3, True)

        # Confirm the bond is created for vlans added directly to an interface.
        osutils.create_network_team.assert_called_once_with(
            mock.sentinel.bond_id,
            network_model.BOND_TYPE_ACTIVE_BACKUP,
            network_model.BOND_LB_ALGO_L2,
            [mock.sentinel.name1],
            mock.sentinel.mac1,
            mock.sentinel.bond_name,
            None,
            None)

        # Ensure vlans are added.
        osutils.add_network_team_nic.assert_any_call(
            mock.sentinel.bond_id, mock.sentinel.vlan1, 10)
        osutils.add_network_team_nic.assert_any_call(
            mock.sentinel.bond_id, mock.sentinel.vlan2, 20)

        # Ensure IP addresses were set.
        osutils.set_static_network_config.assert_any_call(
            mock.sentinel.vlan1, "10.0.10.21", '24', None, nameservers, True)
        osutils.set_static_network_config.assert_any_call(
            mock.sentinel.vlan2, "fc00:1:2:3::7", '64', None, [], True)

        # Static routes were added.
        osutils.add_static_route.assert_any_call(
            mock.sentinel.vlan1, "0.0.0.0/0", '10.0.10.1', 256)
        osutils.add_static_route.assert_any_call(
            mock.sentinel.vlan2, "fc00:1:2:3::1/128", 'fe80::1', 250)

        # Below are windows specific tests, ignore on other platforms.
        if sys.platform != "win32":
            return

        # Verify DHCP fix calls.
        osutils._fix_network_adapter_dhcp.assert_has_calls([
            call(mock.sentinel.bond_name, False, AF_INET),
            call(mock.sentinel.bond_name, False, AF_INET6),
            call(mock.sentinel.vlan1, False, AF_INET),
            call(mock.sentinel.vlan1, False, AF_INET6),
            call(mock.sentinel.vlan2, False, AF_INET),
            call(mock.sentinel.vlan2, False, AF_INET6),
            call(mock.sentinel.name3, True, AF_INET),
            call(mock.sentinel.name3, False, AF_INET6)])

    @mock.patch("builtins.open", new_callable=mock.mock_open,
                read_data=NETWORK_YAML_CONFIG)
    @mock.patch("os.path.isfile")
    @mock.patch("cloudbaseinit.osutils.factory.get_os_utils")
    def test_yaml_config(self, mock_get_os_util, mock_isfile, mock_file):
        # Setup the osutils mock tool.
        osutils = mock.MagicMock()
        osutils.get_config_value.return_value = None

        # When get os utils is called, return the mock.
        mock_get_os_util.return_value = osutils

        # Set isfile responses to return yaml file.
        mock_isfile.side_effect = [False, False, True, True]

        # Setup test data.
        mock.sentinel.mac1 = "52:54:00:dc:cb:67"
        mock.sentinel.mac2 = "52:54:00:8c:fb:03"
        mock.sentinel.mac3 = "52:54:00:6c:5b:24"
        mock.sentinel.name1 = "eth0"
        mock.sentinel.name2 = "eth1"
        mock.sentinel.name3 = "eth2"
        mock.sentinel.bond_name = "bond0"
        mock.sentinel.bond_id = "bond_bond0"
        mock.sentinel.vlan1 = "bond0.30"
        mock.sentinel.vlan2 = "bond0.55"
        nameservers = ['10.30.20.81']
        osutils.get_network_adapter_name_by_mac_address.side_effect = [
            mock.sentinel.old_name1, mock.sentinel.old_name2,
            mock.sentinel.old_name3]
        osutils.get_network_adapters.return_value = [
            (mock.sentinel.old_name1, mock.sentinel.mac1),
            (mock.sentinel.old_name2, mock.sentinel.mac2),
            (mock.sentinel.old_name3, mock.sentinel.mac3)]

        # Windows specific test data.
        adapter_enabled = mock.Mock()
        adapter_enabled.NetEnabled = True
        adapter_disabled = mock.Mock()
        adapter_disabled.NetEnabled = False
        osutils._get_network_adapter.side_effect = [
            adapter_enabled, adapter_enabled, adapter_disabled,
            adapter_enabled, adapter_enabled, adapter_enabled]

        # Call the plugin.
        service = mock.Mock()
        plugin = localnetworkconfig.LocalNetworkConfigPlugin()
        plugin.execute(service, {})

        # Confirm it read the correct file.
        mock_file.assert_called_with('/network.yaml', 'r')

        # Confirm the interface rename was called.
        osutils.rename_network_adapter.assert_any_call(
            mock.sentinel.old_name1, mock.sentinel.name1)
        osutils.rename_network_adapter.assert_any_call(
            mock.sentinel.old_name2, mock.sentinel.name2)
        osutils.rename_network_adapter.assert_any_call(
            mock.sentinel.old_name3, mock.sentinel.name3)

        # Confirm network enable/disable function.
        osutils.enable_network_adapter.assert_any_call(
            mock.sentinel.name1, True)
        osutils.enable_network_adapter.assert_any_call(
            mock.sentinel.name2, True)
        osutils.enable_network_adapter.assert_any_call(
            mock.sentinel.name3, False)

        # Confirm the bond is created for vlans added directly to an interface.
        osutils.create_network_team.assert_called_once_with(
            mock.sentinel.bond_id,
            network_model.BOND_TYPE_ACTIVE_BACKUP,
            network_model.BOND_LB_ALGO_L2,
            [mock.sentinel.name1, mock.sentinel.name2],
            mock.sentinel.mac1,
            mock.sentinel.bond_name,
            None,
            None)

        # Ensure vlans are added.
        osutils.add_network_team_nic.assert_any_call(
            mock.sentinel.bond_id, mock.sentinel.vlan1, 30)
        osutils.add_network_team_nic.assert_any_call(
            mock.sentinel.bond_id, mock.sentinel.vlan2, 55)

        # Ensure IP addresses were set.
        osutils.set_static_network_config.assert_any_call(
            mock.sentinel.vlan1, "10.30.20.88", '28', None, nameservers, True)
        osutils.set_static_network_config.assert_any_call(
            mock.sentinel.vlan2, "fc00:1:0:4:1:0:1:6", '64', None,
            nameservers, True)

        # Static routes were added.
        osutils.add_static_route.assert_any_call(
            mock.sentinel.vlan1, "0.0.0.0/0", '10.30.20.81', 256)
        osutils.add_static_route.assert_any_call(
            mock.sentinel.vlan1, "10.20.10.0/24", '10.30.20.82', 128)
        osutils.add_static_route.assert_any_call(
            mock.sentinel.vlan2, "fc00:1:0:4::1/128", 'fe80::1', 250)

        # Below are windows specific tests, ignore on other platforms.
        if sys.platform != "win32":
            return

        # Verify DHCP fix calls.
        osutils._fix_network_adapter_dhcp.assert_has_calls([
            call(mock.sentinel.name1, False, AF_INET),
            call(mock.sentinel.name1, False, AF_INET6),
            call(mock.sentinel.name2, False, AF_INET),
            call(mock.sentinel.name2, False, AF_INET6),
            call(mock.sentinel.bond_name, True, AF_INET),
            call(mock.sentinel.bond_name, False, AF_INET6),
            call(mock.sentinel.vlan1, False, AF_INET),
            call(mock.sentinel.vlan1, False, AF_INET6),
            call(mock.sentinel.vlan2, False, AF_INET),
            call(mock.sentinel.vlan2, False, AF_INET6)])
