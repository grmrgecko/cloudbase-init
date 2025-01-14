# Copyright 2014 Cloudbase Solutions Srl
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

import json
import os
import sys
import yaml

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.models import network as network_model
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.osutils import windows
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import networkconfig
from cloudbaseinit.utils import network as network_utils

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)
KEY = "LocalNetworkConfig"


class LocalNetworkConfigPlugin(base.BasePlugin):
    """Configure the network with local configuration files."""

    execution_stage = base.PLUGIN_STAGE_PRE_NETWORKING

    @staticmethod
    def _get_network_data():
        # Find the local network config file path.
        configPath = CONF.local_network_config.config_path
        if configPath is None:
            for filePath in [
                    '/curtin/network.json',
                    '/network.json',
                    '/network.yaml',
                    '/network.cfg']:
                if os.path.isfile(filePath):
                    configPath = filePath
                    break

        # If the config file wasn't found,
        if configPath is None or not os.path.isfile(configPath):
            LOG.info('The network config %s does not exist.' % configPath)
            return None

        # Parse the network config file.
        network_data = None
        try:
            file = open(configPath, 'r')
            fileExt = os.path.splitext(configPath)[1].lower()

            # Try yaml if the extension is one which is expected to be yaml.
            if fileExt == ".yaml" or fileExt == ".yml" or fileExt == ".cfg":
                network_data = yaml.safe_load(file)
            else:
                # Default to json otherwise.
                network_data = json.load(file)
        except Exception:
            file.close()
            raise exception.CloudbaseInitException(
                'Error reading and parsing data.')
        file.close()
        return network_data

    @staticmethod
    def _configure_interfaces_dhcp(config: list, links: list):
        """Configure DHCP state on interfaces per the configuration

        This is only available in the local network config plugin because,
        I believe it is only useful in cases where you want the entire network
        configuration managed by cloudbase-init. Most of the other plugins
        seems to exist to only partially configure networking.
        """

        # Ignore other platforms.
        if sys.platform != "win32":
            return

        # Get the network config.
        if config and config.get('network'):
            config = config.get('network')
        if config:
            config = config.get('config')

        # Loop through each local config item, find its interface name,
        # and enable or disable DHCP.
        for config_item in config:
            # If not an interface config, we should skip.
            if not config_item.get("type") in [
                    network_utils.NETWORK_LINK_TYPE_PHY,
                    network_utils.NETWORK_LINK_TYPE_ETHERNET,
                    network_utils.NETWORK_LINK_TYPE_BOND,
                    network_utils.NETWORK_LINK_TYPE_VLAN]:
                continue

            # Get the name from the local config.
            name = config_item.get("id")

            # Find if there is an vlan bond and update name to that.
            for link in links:
                if (link.type != network_model.LINK_TYPE_BOND
                        or len(link.bond.members) != 1
                        or name not in link.bond.members):
                    continue

                # Verify this bond is not actually defined, somehow,
                # in the local config.
                linkInConfig = False
                for config_item2 in config:
                    if config_item2.get("id") == link.id:
                        linkInConfig = True
                        break

                # If this bond is not in local config, update name.
                if not linkInConfig:
                    name = link.id

            # Check subnets for DHCP configurations.
            dhcpv4Enabled = False
            dhcpv6Enabled = False
            subnets = config_item.get("subnets", [])
            for subnet in subnets:
                subnet_type = subnet.get("type")
                if subnet_type == "dhcp4":
                    dhcpv4Enabled = True
                elif subnet_type == "dhcp6":
                    dhcpv6Enabled = True

            # Get the adapters current state, ignoring disabled adapters.
            adapter = windows.WindowsUtils._get_network_adapter(name)
            if not adapter.NetEnabled:
                continue

            # Fix the network adapter's DHCP config.
            if dhcpv4Enabled:
                LOG.debug('Enabling DHCP4 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(
                    name,
                    True,
                    windows.AF_INET)
            else:
                LOG.debug('Disabling DHCP4 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(
                    name,
                    False,
                    windows.AF_INET)

            if dhcpv6Enabled:
                LOG.debug('Enabling DHCP6 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(
                    name,
                    True,
                    windows.AF_INET6)
            else:
                LOG.debug('Disabling DHCP6 on %s' % name)
                windows.WindowsUtils._fix_network_adapter_dhcp(
                    name,
                    False,
                    windows.AF_INET6)

            # If we're disabling DHCP, we should toggle the interface state.
            # Otherwise, its possible that DHCP already got an address.
            if not dhcpv4Enabled or not dhcpv6Enabled:
                adapter.Disable()
                adapter.Enable()

    def execute(self, service, shared_data):
        osutils = osutils_factory.get_os_utils()
        # If we are to configure the local network configuration once,
        # check if we already configured.
        if CONF.local_network_config.once:
            status = osutils.get_config_value(KEY)
            if status == 1:
                LOG.debug("Plugin '%s' execution already done, skipping", KEY)
                return base.PLUGIN_EXECUTION_DONE, False

        # Parse the network config file.
        network_data = self._get_network_data()
        if network_data is None:
            LOG.info('No data parsed.')
            return base.PLUGIN_EXECUTION_DONE, False

        # Parse the links and services from the configuration.
        network_details = network_utils.NetworkConfigParser.parse(network_data)

        # Have the network config plugin configure the network.
        networkconfig.NetworkConfigPlugin._process_network_details_v2(
            network_details)

        # Now that configurations are applied, interfaces have been created
        # and renamed. We need to go back and disable/enable DHCP where needed,
        # according to the configuration file.
        self._configure_interfaces_dhcp(network_data, network_details.links)

        # Set status of 1 to indicate the plugin has executed successfully.
        # This will allow network configurations to be returned to the OS if
        # configure once is set.
        osutils.set_config_value(KEY, 1)

        return base.PLUGIN_EXECUTION_DONE, False
