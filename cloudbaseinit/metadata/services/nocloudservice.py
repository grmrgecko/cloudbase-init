# Copyright 2020 Cloudbase Solutions Srl
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

from oslo_log import log as oslo_logging

from cloudbaseinit import conf as cloudbaseinit_conf
from cloudbaseinit.metadata.services import base
from cloudbaseinit.metadata.services import baseconfigdrive
from cloudbaseinit.utils import debiface
from cloudbaseinit.utils import network as network_utils
from cloudbaseinit.utils import serialization


CONF = cloudbaseinit_conf.CONF
LOG = oslo_logging.getLogger(__name__)


class NoCloudConfigDriveService(baseconfigdrive.BaseConfigDriveService):

    def __init__(self):
        super(NoCloudConfigDriveService, self).__init__(
            'cidata', CONF.nocloud.metadata_file,
            CONF.nocloud.userdata_file)
        self._meta_data = {}

    def get_user_data(self):
        return self._get_cache_data(self._userdata_file)

    def _get_meta_data(self):
        if self._meta_data:
            return self._meta_data

        raw_meta_data = self._get_cache_data(
            self._metadata_file, decode=True)
        try:
            self._meta_data = (
                serialization.parse_json_yaml(raw_meta_data))
        except serialization.YamlParserConfigError as ex:
            LOG.error("Metadata could not be parsed")
            LOG.exception(ex)

        return self._meta_data

    def get_host_name(self):
        return self._get_meta_data().get('local-hostname')

    def get_instance_id(self):
        return self._get_meta_data().get('instance-id')

    def get_public_keys(self):
        raw_ssh_keys = self._get_meta_data().get('public-keys')
        if not raw_ssh_keys:
            return []

        if isinstance(raw_ssh_keys, list):
            return raw_ssh_keys

        return [raw_ssh_keys[key].get('openssh-key') for key in raw_ssh_keys]

    def get_network_details(self):
        debian_net_config = self._get_meta_data().get('network-interfaces')
        if not debian_net_config:
            return None

        return debiface.parse(debian_net_config)

    def get_network_details_v2(self):
        try:
            raw_network_data = self._get_cache_data("network-config",
                                                    decode=True)
            network_data = serialization.parse_json_yaml(raw_network_data)
            if not network_data:
                LOG.info("V2 network metadata is empty")
                return
            if not isinstance(network_data, dict):
                LOG.warning("V2 network metadata is not a dictionary")
                return
        except base.NotExistingMetadataException:
            LOG.info("V2 network metadata not found")
            return
        except serialization.YamlParserConfigError:
            LOG.exception("V2 network metadata could not be deserialized")
            return

        return network_utils.NetworkConfigParser.parse(network_data)
