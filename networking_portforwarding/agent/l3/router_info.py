# Copyright (c) 2014 Openstack Foundation
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

import netaddr

from oslo_log import log as logging

from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import utils as common_utils
from neutron.i18n import _LE, _LW

LOG = logging.getLogger(__name__)
INTERNAL_DEV_PREFIX = namespaces.INTERNAL_DEV_PREFIX
EXTERNAL_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX


class RouterInfo(object):

    def __init__(self,
                 router_id,
                 router,
                 agent_conf,
                 interface_driver,
                 use_ipv6=False):
        self.router_id = router_id
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.floating_ips = set()
        # Invoke the setter for establishing initial SNAT action
        self.router = router
        self.use_ipv6 = use_ipv6
        self.ns_name = None
        self.router_namespace = None
        if agent_conf.use_namespaces:
            ns = namespaces.RouterNamespace(
                router_id, agent_conf, interface_driver, use_ipv6)
            self.router_namespace = ns
            self.ns_name = ns.name
        self.iptables_manager = iptables_manager.IptablesManager(
            use_ipv6=use_ipv6,
            namespace=self.ns_name)
        self.routes = []
        self.portforwardings = []
        self.agent_conf = agent_conf
        self.driver = interface_driver
        # radvd is a neutron.agent.linux.ra.DaemonMonitor
        self.radvd = None

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)
        # Set a SNAT action for the router
        if self._router.get('gw_port'):
            self._snat_action = ('add_rules' if self._snat_enabled
                                 else 'remove_rules')
        elif self.ex_gw_port:
            # Gateway port was removed, remove rules
            self._snat_action = 'remove_rules'

    @property
    def is_ha(self):
        # TODO(Carl) Refactoring should render this obsolete.  Remove it.
        return False

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_interface_name(self, ex_gw_port):
        return self.get_external_device_name(ex_gw_port['id'])

    def _set_subnet_info(self, port):
        ips = port['fixed_ips']
        if not ips:
            raise Exception(_("Router port %s has no IP address") % port['id'])
        if len(ips) > 1:
            LOG.error(_LE("Ignoring multiple IPs on router port %s"),
                      port['id'])
        prefixlen = netaddr.IPNetwork(port['subnet']['cidr']).prefixlen
        port['ip_cidr'] = "%s/%s" % (ips[0]['ip_address'], prefixlen)

    def perform_snat_action(self, snat_callback, *args):
        # Process SNAT rules for attached subnets
        if self._snat_action:
            snat_callback(self._router.get('gw_port'),
                          *args,
                          action=self._snat_action)
        self._snat_action = None

    def _update_routing_table(self, operation, route):
        cmd = ['ip', 'route', operation, 'to', route['destination'],
               'via', route['nexthop']]
        ip_wrapper = ip_lib.IPWrapper(namespace=self.ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def routes_updated(self):
        new_routes = self.router['routes']

        old_routes = self.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug("Added route entry is '%s'", route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
            #replace success even if there is no existing route
            self._update_routing_table('replace', route)
        for route in removes:
            LOG.debug("Removed route entry is '%s'", route)
            self._update_routing_table('delete', route)
        self.routes = new_routes

    def get_ex_gw_port(self):
        return self.router.get('gw_port')

    def get_floating_ips(self):
        """Filter Floating IPs to be hosted on this agent."""
        return self.router.get(l3_constants.FLOATINGIP_KEY, [])

    def floating_forward_rules(self, floating_ip, fixed_ip):
        return [('PREROUTING', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', '-s %s -j SNAT --to %s' %
                 (fixed_ip, floating_ip))]

    def process_floating_ip_nat_rules(self):
        """Configure NAT rules for the router's floating IPs.

        Configures iptables rules for the floating ips of the given router
        """
        # Clear out all iptables rules for floating ips
        self.iptables_manager.ipv4['nat'].clear_rules_by_tag('floating_ip')

        floating_ips = self.get_floating_ips()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            # Rebuild iptables rules for the floating ip.
            fixed = fip['fixed_ip_address']
            fip_ip = fip['floating_ip_address']
            for chain, rule in self.floating_forward_rules(fip_ip, fixed):
                self.iptables_manager.ipv4['nat'].add_rule(chain, rule,
                                                           tag='floating_ip')

        self.iptables_manager.apply()

    def process_snat_dnat_for_fip(self):
        try:
            self.process_floating_ip_nat_rules()
        except Exception:
            # TODO(salv-orlando): Less broad catching
            raise n_exc.FloatingIpSetupException(
                'L3 agent failure to setup NAT for floating IPs')

    def _add_fip_addr_to_device(self, fip, device):
        """Configures the floating ip address on the device.
        """
        try:
            ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
            device.addr.add(ip_cidr)
            return True
        except RuntimeError:
            # any exception occurred here should cause the floating IP
            # to be set in error state
            LOG.warn(_LW("Unable to configure IP address for "
                         "floating IP: %s"), fip['id'])

    def add_floating_ip(self, fip, interface_name, device):
        raise NotImplementedError()

    def remove_floating_ip(self, device, ip_cidr):
        device.addr.delete(ip_cidr)
        self.driver.delete_conntrack_state(namespace=self.ns_name, ip=ip_cidr)

    def get_router_cidrs(self, device):
        return set([addr['cidr'] for addr in device.addr.list()])

    def process_floating_ip_addresses(self, interface_name):
        """Configure IP addresses on router's external gateway interface.

        Ensures addresses for existing floating IPs and cleans up
        those that should not longer be configured.
        """

        fip_statuses = {}
        if interface_name is None:
            LOG.debug('No Interface for floating IPs router: %s',
                      self.router['id'])
            return fip_statuses

        device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
        existing_cidrs = self.get_router_cidrs(device)
        new_cidrs = set()

        floating_ips = self.get_floating_ips()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            fip_ip = fip['floating_ip_address']
            ip_cidr = common_utils.ip_to_cidr(fip_ip)
            new_cidrs.add(ip_cidr)
            fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ACTIVE
            if ip_cidr not in existing_cidrs:
                fip_statuses[fip['id']] = self.add_floating_ip(
                    fip, interface_name, device)
                LOG.debug('Floating ip %(id)s added, status %(status)s',
                          {'id': fip['id'],
                           'status': fip_statuses.get(fip['id'])})

        fips_to_remove = (
            ip_cidr for ip_cidr in existing_cidrs - new_cidrs
            if common_utils.is_cidr_host(ip_cidr))
        for ip_cidr in fips_to_remove:
            self.remove_floating_ip(device, ip_cidr)

        return fip_statuses

    def configure_fip_addresses(self, interface_name):
        try:
            return self.process_floating_ip_addresses(interface_name)
        except Exception:
            # TODO(salv-orlando): Less broad catching
            raise n_exc.FloatingIpSetupException('L3 agent failure to setup '
                'floating IPs')

    def put_fips_in_error_state(self):
        fip_statuses = {}
        for fip in self.router.get(l3_constants.FLOATINGIP_KEY, []):
            fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
        return fip_statuses

    def create(self):
        if self.router_namespace:
            self.router_namespace.create()

    def delete(self):
        self.radvd.disable()
        if self.router_namespace:
            self.router_namespace.delete()

    def _internal_network_added(self, ns_name, network_id, port_id,
                                internal_cidr, mac_address,
                                interface_name, prefix):
        if not ip_lib.device_exists(interface_name,
                                    namespace=ns_name):
            self.driver.plug(network_id, port_id, interface_name, mac_address,
                             namespace=ns_name,
                             prefix=prefix)

        self.driver.init_l3(interface_name, [internal_cidr],
                            namespace=ns_name)
        ip_address = internal_cidr.split('/')[0]
        ip_lib.send_gratuitous_arp(ns_name,
                                   interface_name,
                                   ip_address,
                                   self.agent_conf.send_arp_for_ha)

    def internal_network_added(self, port):
        network_id = port['network_id']
        port_id = port['id']
        internal_cidr = port['ip_cidr']
        mac_address = port['mac_address']

        interface_name = self.get_internal_device_name(port_id)

        self._internal_network_added(self.ns_name,
                                     network_id,
                                     port_id,
                                     internal_cidr,
                                     mac_address,
                                     interface_name,
                                     INTERNAL_DEV_PREFIX)

    def internal_network_removed(self, port):
        interface_name = self.get_internal_device_name(port['id'])

        if ip_lib.device_exists(interface_name, namespace=self.ns_name):
            self.driver.unplug(interface_name, namespace=self.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def _get_existing_devices(self):
        ip_wrapper = ip_lib.IPWrapper(namespace=self.ns_name)
        ip_devs = ip_wrapper.get_devices(exclude_loopback=True)
        return [ip_dev.name for ip_dev in ip_devs]

    def _process_internal_ports(self):
        existing_port_ids = set(p['id'] for p in self.internal_ports)

        internal_ports = self.router.get(l3_constants.INTERFACE_KEY, [])
        current_port_ids = set(p['id'] for p in internal_ports
                               if p['admin_state_up'])

        new_port_ids = current_port_ids - existing_port_ids
        new_ports = [p for p in internal_ports if p['id'] in new_port_ids]
        old_ports = [p for p in self.internal_ports
                     if p['id'] not in current_port_ids]

        new_ipv6_port = False
        old_ipv6_port = False
        for p in new_ports:
            self._set_subnet_info(p)
            self.internal_network_added(p)
            self.internal_ports.append(p)
            if (not new_ipv6_port and
                    netaddr.IPNetwork(p['subnet']['cidr']).version == 6):
                new_ipv6_port = True

        for p in old_ports:
            self.internal_network_removed(p)
            self.internal_ports.remove(p)
            if (not old_ipv6_port and
                    netaddr.IPNetwork(p['subnet']['cidr']).version == 6):
                old_ipv6_port = True

        # Enable RA
        if new_ipv6_port or old_ipv6_port:
            self.radvd.enable(internal_ports)

        existing_devices = self._get_existing_devices()
        current_internal_devs = set(n for n in existing_devices
                                    if n.startswith(INTERNAL_DEV_PREFIX))
        current_port_devs = set(self.get_internal_device_name(port_id)
                                for port_id in current_port_ids)
        stale_devs = current_internal_devs - current_port_devs
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale internal router device: %s',
                      stale_dev)
            self.driver.unplug(stale_dev,
                               namespace=self.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def _list_floating_ip_cidrs(self):
        # Compute a list of addresses this router is supposed to have.
        # This avoids unnecessarily removing those addresses and
        # causing a momentarily network outage.
        floating_ips = self.get_floating_ips()
        return [common_utils.ip_to_cidr(ip['floating_ip_address'])
                for ip in floating_ips]

    def _plug_external_gateway(self, ex_gw_port, interface_name, ns_name):
        if not ip_lib.device_exists(interface_name, namespace=ns_name):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'],
                             interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.agent_conf.external_network_bridge,
                             namespace=ns_name,
                             prefix=EXTERNAL_DEV_PREFIX)

    def _external_gateway_added(self, ex_gw_port, interface_name,
                                ns_name, preserve_ips):
        self._plug_external_gateway(ex_gw_port, interface_name, ns_name)

        self.driver.init_l3(interface_name,
                            [ex_gw_port['ip_cidr']],
                            namespace=ns_name,
                            gateway=ex_gw_port['subnet'].get('gateway_ip'),
                            extra_subnets=ex_gw_port.get('extra_subnets', []),
                            preserve_ips=preserve_ips)
        ip_address = ex_gw_port['ip_cidr'].split('/')[0]
        ip_lib.send_gratuitous_arp(ns_name,
                                   interface_name,
                                   ip_address,
                                   self.agent_conf.send_arp_for_ha)

    def external_gateway_added(self, ex_gw_port, interface_name):
        preserve_ips = self._list_floating_ip_cidrs()
        self._external_gateway_added(
            ex_gw_port, interface_name, self.ns_name, preserve_ips)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        preserve_ips = self._list_floating_ip_cidrs()
        self._external_gateway_added(
            ex_gw_port, interface_name, self.ns_name, preserve_ips)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        self.driver.unplug(interface_name,
                           bridge=self.agent_conf.external_network_bridge,
                           namespace=self.ns_name,
                           prefix=EXTERNAL_DEV_PREFIX)

    def _process_external_gateway(self, ex_gw_port):
        # TODO(Carl) Refactor to clarify roles of ex_gw_port vs self.ex_gw_port
        ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or
                         self.ex_gw_port and self.ex_gw_port['id'])

        interface_name = None
        if ex_gw_port_id:
            interface_name = self.get_external_device_name(ex_gw_port_id)
        if ex_gw_port:
            def _gateway_ports_equal(port1, port2):
                def _get_filtered_dict(d, ignore):
                    return dict((k, v) for k, v in d.iteritems()
                                if k not in ignore)

                keys_to_ignore = set(['binding:host_id'])
                port1_filtered = _get_filtered_dict(port1, keys_to_ignore)
                port2_filtered = _get_filtered_dict(port2, keys_to_ignore)
                return port1_filtered == port2_filtered

            self._set_subnet_info(ex_gw_port)
            if not self.ex_gw_port:
                self.external_gateway_added(ex_gw_port, interface_name)
            elif not _gateway_ports_equal(ex_gw_port, self.ex_gw_port):
                self.external_gateway_updated(ex_gw_port, interface_name)
        elif not ex_gw_port and self.ex_gw_port:
            self.external_gateway_removed(self.ex_gw_port, interface_name)

        existing_devices = self._get_existing_devices()
        stale_devs = [dev for dev in existing_devices
                      if dev.startswith(EXTERNAL_DEV_PREFIX)
                      and dev != interface_name]
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale external router device: %s', stale_dev)
            self.driver.unplug(stale_dev,
                               bridge=self.agent_conf.external_network_bridge,
                               namespace=self.ns_name,
                               prefix=EXTERNAL_DEV_PREFIX)

        # Process SNAT rules for external gateway
        self.perform_snat_action(self._handle_router_snat_rules,
                                 interface_name)

    def external_gateway_nat_rules(self, ex_gw_ip, interface_name):
        rules = [('POSTROUTING', '! -i %(interface_name)s '
                  '! -o %(interface_name)s -m conntrack ! '
                  '--ctstate DNAT -j ACCEPT' %
                  {'interface_name': interface_name}),
                 ('snat', '-o %s -j SNAT --to-source %s' %
                  (interface_name, ex_gw_ip))]
        return rules

    def _empty_snat_chains(self, iptables_manager):
        iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        iptables_manager.ipv4['nat'].empty_chain('snat')

    def _add_snat_rules(self, ex_gw_port, iptables_manager,
                        interface_name, action):
        if action == 'add_rules' and ex_gw_port:
            # ex_gw_port should not be None in this case
            # NAT rules are added only if ex_gw_port has an IPv4 address
            for ip_addr in ex_gw_port['fixed_ips']:
                ex_gw_ip = ip_addr['ip_address']
                if netaddr.IPAddress(ex_gw_ip).version == 4:
                    rules = self.external_gateway_nat_rules(ex_gw_ip,
                                                            interface_name)
                    for rule in rules:
                        iptables_manager.ipv4['nat'].add_rule(*rule)
                    break

    def _handle_router_snat_rules(self, ex_gw_port,
                                  interface_name, action):
        self._empty_snat_chains(self.iptables_manager)

        self.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        self._add_snat_rules(ex_gw_port,
                             self.iptables_manager,
                             interface_name,
                             action)

    def process_external(self, agent):
        existing_floating_ips = self.floating_ips
        try:
            with self.iptables_manager.defer_apply():
                ex_gw_port = self.get_ex_gw_port()
                self._process_external_gateway(ex_gw_port)
                # TODO(Carl) Return after setting existing_floating_ips and
                # still call update_fip_statuses?
                if not ex_gw_port:
                    return

                # Process SNAT/DNAT rules and addresses for floating IPs
                self.process_snat_dnat_for_fip()

            # Once NAT rules for floating IPs are safely in place
            # configure their addresses on the external gateway port
            interface_name = self.get_external_device_interface_name(
                ex_gw_port)
            fip_statuses = self.configure_fip_addresses(interface_name)

        except (n_exc.FloatingIpSetupException,
                n_exc.IpTablesApplyException) as e:
                # All floating IPs must be put in error state
                LOG.exception(e)
                fip_statuses = self.put_fips_in_error_state()

        agent.update_fip_statuses(self, existing_floating_ips, fip_statuses)
