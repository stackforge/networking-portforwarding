# Copyright 2013 UnitedStack, Inc.
# Copyright 2014 INFN
# All rights reserved.
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
#

import abc
import six

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as qexception
from neutron.i18n import _LI
from neutron.plugins.common import constants
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class PortForwardingRuleNotFound(qexception.NotFound):
    message = _("Port Forwarding Rule %(port_forwarding_rule_id)s could not be"
                " found.")


class DuplicatedOutsidePort(qexception.InvalidInput):
    message = _("Outside port %(port)s has already been used.")


class InvalidInsideAddress(qexception.InvalidInput):
    message = _("inside address %(inside_addr)s does not match "
                "any subnets in this router.")


class InvalidProtocol(qexception.InvalidInput):
    message = _("Invalid Protocol, allowed value are: tcp, udp")


valid_protocol_values = [None, constants.TCP, constants.UDP]


def convert_port_to_string(value):
    if value is None:
        return
    else:
        return str(value)


def convert_protocol(value):
    if value is None:
        return
    if value.lower() in valid_protocol_values:
        return value.lower()
    else:
        raise InvalidProtocol()


def _validate_port_range(data, key_specs=None):
    if data is None:
        return
    data = str(data)
    ports = data.split(':')
    for p in ports:
        try:
            val = int(p)
        except (ValueError, TypeError):
            msg = _("Port '%s' is not a valid number") % p
            LOG.debug(msg)
            return msg
        if val <= 0 or val > 65535:
            msg = _("Invalid port '%s'") % p
            LOG.debug(msg)
            return msg


def _validate_ip_or_subnet_or_none(data, valid_values=None):
    if data is None:
        return None
    msg_ip = attributes._validate_ip_address(data, valid_values)
    if not msg_ip:
        return None
    msg_subnet = attributes._validate_subnet(data, valid_values)
    if not msg_subnet:
        return None
    return _("%(msg_ip)s and %(msg_subnet)s") % {'msg_ip': msg_ip,
                                                 'msg_subnet': msg_subnet}

validators = {'type:port_range': _validate_port_range,
              'type:ip_or_subnet_or_none': _validate_ip_or_subnet_or_none}

attributes.validators.update(validators)

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'portforwardings': {
            'id': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:uuid': None},
                   'is_visible': True, 'primary_key': True},
            'tenant_id': {'allow_post': True, 'allow_put': False,
                          'required_by_policy': True,
                          'is_visible': True},
            'router_id': {'allow_post': True, 'allow_put': False,
                          'required_by_policy': True,
                          'is_visible': True},
            'protocol': {'allow_post': True, 'allow_put': True,
                         'is_visible': True, 'default': None,
                         'convert_to': convert_protocol,
                         'validate': {'type:values': valid_protocol_values}},
            'inside_addr': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:ip_or_subnet_or_none': None},
                            'is_visible': True, 'default': None},
            'inside_port': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:port_range': None},
                            'convert_to': convert_port_to_string,
                            'default': None, 'is_visible': True},
            'outside_port': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:port_range': None},
                             'convert_to': convert_port_to_string,
                             'default': None, 'is_visible': True},
    }
}


class Portforwardings(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Port Forwarding"

    @classmethod
    def get_alias(cls):
        return "portforwarding"

    @classmethod
    def get_description(cls):
        return "Expose internal TCP/UDP port to external network"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/portforwarding/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2015-03-25T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
                            {}, RESOURCE_ATTRIBUTE_MAP)
        attributes.PLURALS.update(plural_mappings)
        LOG.info(_LI('PortForwarding_plural_mappings:%s'), plural_mappings)

        maps = resource_helper.build_resource_info(plural_mappings,
                                            RESOURCE_ATTRIBUTE_MAP,
                                            constants.L3_ROUTER_NAT,
                                            allow_bulk=True)
        LOG.info(_LI('PortForwarding_get_resources:%s'), maps)
        return maps


@six.add_metaclass(abc.ABCMeta)
class PortforwardingsPluginBase(object):

    @abc.abstractmethod
    def create_portforwarding(self, context, portforwarding):
        pass

    @abc.abstractmethod
    def update_portforwarding(self, context, id, portforwarding):
        pass

    @abc.abstractmethod
    def delete_portforwarding(self, context, id):
        pass

    @abc.abstractmethod
    def get_portforwardings(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        pass

    @abc.abstractmethod
    def get_portforwarding(self, context, id, fields=None):
        pass
