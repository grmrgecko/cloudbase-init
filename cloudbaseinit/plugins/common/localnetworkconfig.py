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
import time
import yaml

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit import exception
from cloudbaseinit.metadata.services import maasservice
from cloudbaseinit.models import network as network_model
from cloudbaseinit.osutils import factory as osutils_factory
from cloudbaseinit.osutils import windows
from cloudbaseinit.plugins.common import base
from cloudbaseinit.plugins.common import networkconfig
from cloudbaseinit.utils import network as network_utils

CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


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
    def _create_bond_for_bondless_vlans(links: list, networks: list):
        # It is possible to have a vlan attached to an individual interface,
        # without a bond being created. The network configuration code requires
        # that a network team is created for each interface that has vlans.
        # We create bonds for such interfaces, and move configurations to that
        # bond.

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
    def _prepare_and_clean_links(osutils, links: list, networks: list):
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
            elif link.type == network_model.LINK_TYPE_BOND:
                # Find the link in adapter list.
                foundBond = False
                for adapter in network_adapters:
                    if adapter[0] == link.id:
                        foundBond = True
                        break

                # Remove the bond if it exists.
                if foundBond and sys.platform == "win32":
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

    def _get_vlan_bond_name(name, config: list, links: list):
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
        return name

    @staticmethod
    def _configure_interfaces_dhcp(self, config: list, links: list):
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
            name = self._get_vlan_bond_name(
                config_item.get("id"), config, links)

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
        reboot_required = False

        # Get the OS utilities.
        osutils = osutils_factory.get_os_utils()

        # Enable disabled adapters to ensure all adapters are available
        # to configure.
        osutils.enable_disabled_network_adapters()

        # Parse the network config file.
        network_data = self._get_network_data()
        if network_data is None:
            LOG.info('No data parsed.')
            return base.PLUGIN_EXECUTION_DONE, reboot_required

        # Parse the links and services from the configuration.
        network_details = network_utils.NetworkConfigParser.parse(network_data)

        # Windows requires a team nic to be created before you can add vlans
        # to an interface. The network config plugin uses bonds to create team
        # nics, so we need to make a virtual bond for every interface that is
        # assigned vlans.
        self._create_bond_for_bondless_vlans(
            network_details.links, network_details.networks)

        # Interfaces that are on a bond in MaaS does not have subnets which
        # ends up going disabled. We need to re-enable the interfaces,
        # so that the bond can be created ontop of it.
        network_utils.NetworkConfigParser.\
            _enable_bond_physical_links(network_details.links)

        # Cleanup the link and network list, to ensure we do not have
        # stray networks.
        self._prepare_and_clean_links(
            osutils,
            network_details.links,
            network_details.networks)

        # Have the network config plugin configure the network.
        networkconfig.NetworkConfigPlugin._process_network_details_v2(
            network_details)

        # Now that configurations are applied, interfaces have been created
        # and renamed. We need to go back and disable/enable DHCP where needed,
        # according to the configuration file.
        self._configure_interfaces_dhcp(network_data, network_details.links)

        return base.PLUGIN_EXECUTION_DONE, reboot_required
