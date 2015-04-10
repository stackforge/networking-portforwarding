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

import netaddr
import sqlalchemy as sa

from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.extensions import portforwardings
from neutron.i18n import _LE
from neutron.i18n import _LI
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import orm
from sqlalchemy.orm import exc


LOG = logging.getLogger(__name__)


class PortForwardingRule(model_base.BASEV2, models_v2.HasId,
                         models_v2.HasTenant):

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"))

    router = orm.relationship(l3_db.Router,
                              backref=orm.backref("portforwarding_list",
                                                  lazy='joined',
                                                  cascade='delete'))
    outside_port = sa.Column(sa.Integer())
    inside_addr = sa.Column(sa.String(15))
    inside_port = sa.Column(sa.Integer())
    protocol = sa.Column(sa.String(4))
    __table_args__ = (sa.schema.UniqueConstraint('router_id',
                                                 'protocol',
                                                 'outside_port',
                                                 name='outside_port'),)


class PortForwardingDbMixin(l3_db.L3_NAT_db_mixin,
                            portforwardings.PortforwardingsPluginBase):
    """Mixin class to support nat rule configuration on router."""
    __native_bulk_support = True

    def _extend_router_dict_portforwarding(self, router_res, router_db):
        router_res['portforwardings'] = (
            PortForwardingDbMixin._make_extra_portfwd_list(
                router_db['portforwarding_list']))

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_router_dict_portforwarding'])

    def _validate_fwds(self, context, router, portfwds):
        query = context.session.query(models_v2.Network).join(models_v2.Port)
        networks = query.filter_by(device_id=router['id'])
        subnets = []
        for network in networks:
            subnets.extend(map(lambda x: x['cidr'], network.subnets))

        ip_addr, ip_net = netaddr.IPAddress, netaddr.IPNetwork
        for portfwd in portfwds:
            ip_str = portfwd['inside_addr']
            valid = any([ip_addr(ip_str) in ip_net(x) for x in subnets])
            if not valid:
                raise portforwardings.InvalidInsideAddress(inside_addr=ip_str)

    @staticmethod
    def _make_extra_portfwd_list(portforwardings):
        return [{'id': portfwd['id'],
         'outside_port': portfwd['outside_port'],
                 'inside_addr': portfwd['inside_addr'],
                 'inside_port': portfwd['inside_port'],
                 'protocol': portfwd['protocol']
                 }
                for portfwd in portforwardings]

    def _make_portforwarding_rule_dict(self, portforwarding_rule, fields=None):
        res = {'tenant_id': portforwarding_rule['tenant_id'],
               'id': portforwarding_rule['id'],
               'router_id': portforwarding_rule['router_id'],
               'protocol': portforwarding_rule['protocol'],
               'inside_addr': portforwarding_rule['inside_addr'],
               'inside_port': portforwarding_rule['inside_port'],
               'outside_port': portforwarding_rule['outside_port']
               }
        return self._fields(res, fields)

    def _get_rule(self, context, id):
        try:
            return self._get_by_id(context, PortForwardingRule, id)
        except exc.NoResultFound:
            raise portforwardings.PortForwardingRuleNotFound(
                                  port_forwarding_rule_id=id)

    def _create_bulk(self, resource, context, request_items):
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        context.session.begin(subtransactions=True)
        try:
            for item in items:
                obj_creator = getattr(self, 'create_%s' % resource)
                objects.append(obj_creator(context, item))
            context.session.commit()
        except Exception:
            context.session.rollback()
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("An exception occurred while creating "
                            "the %(resource)s:%(item)s"),
                          {'resource': resource, 'item': item})
        return objects

    def create_portforwarding_bulk(self, context, portforwarding):
        return self._create_bulk('portforwarding', context,
                                 portforwarding)

    def create_portforwarding(self, context, portforwarding):
        with context.session.begin(subtransactions=True):
            LOG.debug('create_portforwarding ->  portforwarding: %s' %
                      portforwarding)

            port = portforwarding['portforwarding']
            router = self._get_router(context, port['router_id'])

            try:
                    self._validate_fwds(context, router, [port])
                    rule = PortForwardingRule(
                            tenant_id=port['tenant_id'],
                            router_id=port['router_id'],
                            outside_port=port['outside_port'],
                            inside_addr=port['inside_addr'],
                            inside_port=port['inside_port'],
                            protocol=port['protocol'])
                    context.session.add(rule)
                    context.session.flush()
                    LOG.debug('router type: %s' % router)
                    self.notify_router_updated(context, router['id'])

                    return self._make_portforwarding_rule_dict(rule)
            except db_exc.DBDuplicateEntry as e:
                    LOG.info(_LI('Exception: %s'), e.inner_exception.message)
                    if 'outside_port' in e.columns:
                        raise portforwardings.DuplicatedOutsidePort(
                                port=port['protocol'] + ' ' +
                                port['outside_port'])
                    # NOTE: raise original exception directly if
                    #                 duplication not caused by identical ports
                    raise

    def update_portforwarding(self, context, id, portforwarding):
        try:
            rule = portforwarding['portforwarding']
            with context.session.begin(subtransactions=True):
                portforwarding_db = self._get_by_id(context,
                                                    PortForwardingRule, id)

                if 'inside_addr' in rule:
                    router = self._get_router(context,
                                              portforwarding_db['router_id'])
                    self._validate_fwds(context, router, [rule])

                portforwarding_db.update(rule)
                self.notify_router_updated(context,
                                           portforwarding_db['router_id'])

                return self._make_portforwarding_rule_dict(portforwarding_db)
        except db_exc.DBDuplicateEntry as e:
                    LOG.info(_LI('Exception: %s'), e.inner_exception.message)
                    if 'outside_port' in e.columns:
                        prot = portforwarding_db['protocol']
                        out_port = str(portforwarding_db['outside_port'])
                        if 'protocol' in rule:
                            prot = rule['protocol']
                        if 'outside_port' in rule:
                            out_port = rule['outside_port']
                        raise portforwardings.DuplicatedOutsidePort(
                                                port=prot + ' ' + out_port)
                    # NOTE: raise original exception directly if
                    #                 duplication not caused by identical ports
                    raise

    def delete_portforwarding(self, context, id):
        try:
            rule = self.get_portforwarding(context, id)
            router_id = rule['router_id']
            del_context = context.session.query(PortForwardingRule)
            del_context.filter_by(id=id).delete()
            self.notify_router_updated(context, router_id)
        except exc.NoResultFound:
            raise portforwardings.PortForwardingRuleNotFound(
                                  port_forwarding_rule_id=id)

    def get_portforwardings(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        return self._get_collection(context, PortForwardingRule,
                                    self._make_portforwarding_rule_dict,
                                    filters=filters, fields=fields)

    def get_portforwarding(self, context, id, fields=None):
        rule = self._get_rule(context, id)
        return self._make_portforwarding_rule_dict(rule, fields)
