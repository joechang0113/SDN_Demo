# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import csv
import json
import os
import sys
import time
import random

from operator import attrgetter

from ryu.app import simple_switch_13

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp, udp
from ryu.lib import hub

global pre_tx_bytes2
global pre_rx_bytes2
global pre_tx_bytes4
global pre_rx_bytes4
global pre_tx_bytes7
global pre_rx_bytes7
global pre_tx_bytes8
global pre_rx_bytes8
global pre_tx_bytes10
global pre_rx_bytes10
global pre_tx_bytes12
global pre_rx_bytes12
global rx_rate2_fix
global rx_rate12_fix
global flag


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.pre_rx_bytes2 = 0
        self.pre_tx_bytes2 = 0
        self.pre_rx_bytes4 = 0
        self.pre_rx_bytes8 = 0
        self.pre_tx_bytes4 = 0
        self.pre_tx_bytes8 = 0
        self.pre_tx_bytes7 = 0
        self.pre_rx_bytes7 = 0
        self.pre_tx_bytes10 = 0
        self.pre_rx_bytes10 = 0
        self.pre_tx_bytes12 = 0
        self.pre_rx_bytes12 = 0
        self.rx_rate2_fix = 0
        self.flag = True
        self.rx_rate12_fix = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        self.send_set_config(datapath)

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                   ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

        bands = [parser.OFPMeterBandDrop(int(500))]
        mod = parser.OFPMeterMod(datapath=datapath,
                                 command=ofproto.OFPMC_ADD,
                                 flags=ofproto.OFPMF_KBPS,
                                 meter_id=int(1),
                                 bands=bands)
        datapath.send_msg(mod)

        bands1 = [parser.OFPMeterBandDrop(int(5000))]
        mod1 = parser.OFPMeterMod(datapath=datapath,
                                  command=ofproto.OFPMC_ADD,
                                  flags=ofproto.OFPMF_KBPS,
                                  meter_id=int(2),
                                  bands=bands1)
        datapath.send_msg(mod1)

        bands2 = [parser.OFPMeterBandDrop(int(500000))]
        mod2 = parser.OFPMeterMod(datapath=datapath,
                                  command=ofproto.OFPMC_ADD,
                                  flags=ofproto.OFPMF_KBPS,
                                  meter_id=int(3),
                                  bands=bands2)
        datapath.send_msg(mod2)

        # =================== MAC Adress================ #
        # -----asus_ap1_mac:      18:31:BF:49:15:58----- #
        # -----asus_ap2_mac:      4C:ED:FB:A4:44:48----- #
        # -----asus_ap3_mac:      4C:ED:FB:A4:5D:38----- #
        # -----ZyXEL_ap_mac:      f0:b4:29:7e:2b:24----- #
        # -----Xiaomi_ap_mac:     64:80:99:58:08:8c----- #
        # -----Efence_camera_mac: 00:18:fb:41:0c:b7----- #
        # -----Efence_server_mac: d8:cb:8a:fc:ad:52----- #
        # =================== port to port ============= #
        # -----ZyXEL_ap > ap1_Blue---------------------- #
        # -----ap1_Yellow > port10---------------------- #
        # -----port2 > Efence_camera-------------------- #
        # -----port4 > Efence_server-------------------- #
        # -----port8 > asus_ap2------------------------- #
        # ============================================== #

        # # camera to port_2
        # match = parser.OFPMatch(in_port=2,
        #                         eth_dst='18:31:bf:49:15:58',
        #                         eth_src='00:18:fb:41:0c:b7')
        # actions = [parser.OFPActionOutput(10)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)

        # match = parser.OFPMatch(in_port=10,
        #                         eth_dst='00:18:fb:41:0c:b7',
        #                         eth_src='18:31:bf:49:15:58')
        # actions = [parser.OFPActionOutput(2)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)
        # print('rule1')

        # # Efence to port_04
        # match = parser.OFPMatch(in_port=4,
        #                         eth_dst='18:31:bf:49:15:58',
        #                         eth_src='d8:cb:8a:fc:ad:52')
        # actions = [parser.OFPActionOutput(10)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)

        # match = parser.OFPMatch(in_port=10,
        #                         eth_dst='d8:cb:8a:fc:ad:52',
        #                         eth_src='18:31:bf:49:15:58')
        # actions = [parser.OFPActionOutput(4)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)
        # print('rule2')

        # xiaomi_ap to port_06
        match = parser.OFPMatch(in_port=6,
                                eth_dst='18:31:bf:49:15:58',
                                eth_src='f0:b4:29:7e:2b:24')
        actions = [parser.OFPActionOutput(10)]
        self.add_meter_flow(datapath, 1, match, actions, 3)

        match = parser.OFPMatch(in_port=10,
                                eth_dst='f0:b4:29:7e:2b:24',
                                eth_src='18:31:bf:49:15:58')
        actions = [parser.OFPActionOutput(6)]
        self.add_meter_flow(datapath, 1, match, actions, 3)
        print('rule3')

        # asus_ap2 to port_08
        match = parser.OFPMatch(in_port=8,
                                eth_dst='18:31:bf:49:15:58',
                                eth_src='4c:ed:fb:a4:44:48')
        actions = [parser.OFPActionOutput(10)]
        self.add_meter_flow(datapath, 2, match, actions, 3)

        match = parser.OFPMatch(in_port=10,
                                eth_dst='4c:ed:fb:a4:44:48',
                                eth_src='18:31:bf:49:15:58')
        actions = [parser.OFPActionOutput(8)]
        self.add_meter_flow(datapath, 2, match, actions, 3)
        print('rule4')

        # camera to Efence
        match = parser.OFPMatch(in_port=2,
                                eth_dst='d8:cb:8a:fc:ad:52',
                                eth_src='00:18:fb:41:0c:b7')
        actions = [parser.OFPActionOutput(4)]
        self.add_meter_flow(datapath, 1, match, actions, 1)

        match = parser.OFPMatch(in_port=4,
                                eth_dst='00:18:fb:41:0c:b7',
                                eth_src='d8:cb:8a:fc:ad:52')
        actions = [parser.OFPActionOutput(2)]
        self.add_meter_flow(datapath, 1, match, actions, 1)
        print('add rule5')

        # # PI3 to port_11 ----lab demo
        # match = parser.OFPMatch(in_port=11,
        #                         eth_dst='18:31:bf:49:15:58',
        #                         eth_src='B8:27:EB:5D:97:D9')
        # actions = [parser.OFPActionOutput(10)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)

        # match = parser.OFPMatch(in_port=10,
        #                         eth_dst='B8:27:EB:5D:97:D9',
        #                         eth_src='18:31:bf:49:15:58')
        # actions = [parser.OFPActionOutput(11)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)
        # print('add rule6')

        # # PI to asus3
        # match = parser.OFPMatch(in_port=12,
        #                         eth_dst='B8:27:EB:5D:97:D9',
        #                         eth_src='4C:ED:FB:A4:5D:38')
        # actions = [parser.OFPActionOutput(11)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)

        # match = parser.OFPMatch(in_port=11,
        #                         eth_dst='4C:ED:FB:A4:5D:38',
        #                         eth_src='B8:27:EB:5D:97:D9')
        # actions = [parser.OFPActionOutput(12)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)
        # print('add rule7')

        # # asus3 to asus2
        # match = parser.OFPMatch(in_port=12,
        #                         eth_dst='4c:ed:fb:a4:44:48',
        #                         eth_src='4C:ED:FB:A4:5D:38')
        # actions = [parser.OFPActionOutput(8)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)

        # match = parser.OFPMatch(in_port=8,
        #                         eth_dst='4C:ED:FB:A4:5D:38',
        #                         eth_src='4c:ed:fb:a4:44:48')
        # actions = [parser.OFPActionOutput(12)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)
        # print('add rule8')

        # # asus3 to efence
        # match = parser.OFPMatch(in_port=12,
        #                         eth_dst='d8:cb:8a:fc:ad:52',
        #                         eth_src='4C:ED:FB:A4:5D:38')
        # actions = [parser.OFPActionOutput(4)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)

        # match = parser.OFPMatch(in_port=4,
        #                         eth_dst='4C:ED:FB:A4:5D:38',
        #                         eth_src='d8:cb:8a:fc:ad:52')
        # actions = [parser.OFPActionOutput(12)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)
        # print('add rule9')

        # # asus3 to camera
        # match = parser.OFPMatch(in_port=12,
        #                         eth_dst='00:18:fb:41:0c:b7',
        #                         eth_src='4C:ED:FB:A4:5D:38')
        # actions = [parser.OFPActionOutput(2)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)

        # match = parser.OFPMatch(in_port=2,
        #                         eth_dst='4C:ED:FB:A4:5D:38',
        #                         eth_src='00:18:fb:41:0c:b7')
        # actions = [parser.OFPActionOutput(12)]
        # self.add_meter_flow(datapath, 1, match, actions, 3)
        # print('add rule10')

        # # laptop to port12
        # match = parser.OFPMatch(in_port=12,
        #                         eth_dst='98:e7:f4:0f:08:85',
        #                         eth_src='00:1e:68:8a:0f:49')
        # actions = [parser.OFPActionOutput(7)]
        # self.add_meter_flow(datapath, 1, match, actions, 2)

        # match = parser.OFPMatch(in_port=7,
        #                         eth_dst='00:1e:68:8a:0f:49',
        #                         eth_src='98:e7:f4:0f:08:85')
        # actions = [parser.OFPActionOutput(12)]
        # self.add_meter_flow(datapath, 1, match, actions, 2)
        # print('add rule11')

        # # laptop to port10
        # match = parser.OFPMatch(in_port=10,eth_dst='98:e7:f4:0f:08:85',eth_src='18:31:bf:49:15:58')
        # actions = [parser.OFPActionOutput(7)]
        # self.add_meter_flow(datapath, 1, match, actions,2)

        # match = parser.OFPMatch(in_port=7,eth_dst='18:31:bf:49:15:58',eth_src='98:e7:f4:0f:08:85')
        # actions = [parser.OFPActionOutput(10)]
        # self.add_meter_flow(datapath, 1, match, actions,2)
        # print('add rule12')

        # laptop(others) to port12
        match = parser.OFPMatch(in_port=12,
                                eth_dst='98:e7:f4:0f:08:85',
                                eth_src='4c:ed:fb:a4:5d:38')
        actions = [parser.OFPActionOutput(7)]
        self.add_meter_flow(datapath, 1, match, actions, 2)

        match = parser.OFPMatch(in_port=7,
                                eth_dst='4c:ed:fb:a4:5d:38',
                                eth_src='98:e7:f4:0f:08:85')
        actions = [parser.OFPActionOutput(12)]
        self.add_meter_flow(datapath, 1, match, actions, 2)
        print('add rule13')

    def send_set_config(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPSetConfig(datapath, ofproto.OFPC_FRAG_NORMAL, 2048)
        datapath.send_msg(req)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    def add_meter_flow(self,
                       datapath,
                       priority,
                       match,
                       actions,
                       meter_id,
                       buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionMeter(int(meter_id), ofproto.OFPIT_METER),
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        msg.buffer_id = ofproto.OFP_NO_BUFFER

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        tcp_packet = pkt.get_protocols(tcp.tcp)

        str1 = 'I am broadCast message!'
        # if tcp_packet:
        #    print('payload in tcp_packet:',pkt.protocols[-1])

        udp_packet = pkt.get_protocols(udp.udp)
        if udp_packet:
            udp_string = str(pkt.protocols[-1])
            # print('payload in udp_packet:',pkt.protocols[-1])

            if str1 in udp_string:
                print('success')

                self.flag = False

                bands = [parser.OFPMeterBandDrop(int(800))]
                mod = parser.OFPMeterMod(datapath=datapath,
                                         command=ofproto.OFPMC_MODIFY,
                                         flags=ofproto.OFPMF_KBPS,
                                         meter_id=int(1),
                                         bands=bands)
                datapath.send_msg(mod)

                bands1 = [parser.OFPMeterBandDrop(int(400))]
                mod1 = parser.OFPMeterMod(datapath=datapath,
                                          command=ofproto.OFPMC_MODIFY,
                                          flags=ofproto.OFPMF_KBPS,
                                          meter_id=int(2),
                                          bands=bands1)
                datapath.send_msg(mod1)

                match = parser.OFPMatch(in_port=2,
                                        eth_dst='d8:cb:8a:fc:ad:52',
                                        eth_src='00:18:fb:41:0c:b7')
                actions = [parser.OFPActionOutput(4)]
                self.add_meter_flow(datapath, 5, match, actions, 1)

                match = parser.OFPMatch(in_port=4,
                                        eth_dst='00:18:fb:41:0c:b7',
                                        eth_src='d8:cb:8a:fc:ad:52')
                actions = [parser.OFPActionOutput(2)]
                self.add_meter_flow(datapath, 5, match, actions, 1)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_ALL

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_ALL:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                print '------------- add flow ---------------------'
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow:
                           (flow.match['in_port'], flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d', ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        ran = 0

        self.logger.info('port     ' 'rx-KB    ' 'tx-KB    ' 'av_re-KB ')
        self.logger.info('-------- ' '-------- ' '-------- ' '-------- ')
        for stat in sorted(body, key=attrgetter('port_no')):

            self.logger.info(
                '%8d %8d %8d %8d ',
                stat.port_no,
                stat.rx_bytes * 8 / 1024,
                stat.tx_bytes * 8 / 1024,
                int(stat.rx_bytes * 8 / 1024 / 10),
            )

            if stat.port_no == 2:
                pktport2 = (stat.rx_bytes * 8 / 1024 / 10)
                pktport2tx = (stat.tx_bytes * 8 / 1024 / 10)
                self.rx_rate2_fix = pktport2 - (self.pre_rx_bytes2)
            if stat.port_no == 4:
                pktport4 = (stat.rx_bytes * 8 / 1024 / 10)
                pktport4tx = (stat.tx_bytes * 8 / 1024 / 10)
            if stat.port_no == 6:
                pktport6 = stat.rx_bytes
            if stat.port_no == 7:
                pktport7 = (stat.rx_bytes * 8 / 1024 / 10)
                pktport7tx = (stat.tx_bytes * 8 / 1024 / 10)
            if stat.port_no == 8:
                pktport8 = (stat.rx_bytes * 8 / 1024 / 10)
                pktport8tx = (stat.tx_bytes * 8 / 1024 / 10)
            if stat.port_no == 10:
                pktport10 = (stat.rx_bytes * 8 / 1024 / 10)
                pktport10tx = (stat.tx_bytes * 8 / 1024 / 10)
            if stat.port_no == 12:
                pktport12 = (stat.rx_bytes * 8 / 1024 / 10)
                pktport12tx = (stat.tx_bytes * 8 / 1024 / 10)

        if self.flag is False:
            ran = 300

        print('port_02_tx', pktport2tx - (self.pre_tx_bytes2))
        print('port_02_rx', pktport2 - (self.pre_rx_bytes2)),
        print('port_04_tx', pktport4tx - (self.pre_tx_bytes4))
        print('port_04_rx', pktport4 - (self.pre_rx_bytes4)),
        print('port_07_tx', pktport7tx - (self.pre_tx_bytes7))
        print('port_07_rx', pktport7 - (self.pre_rx_bytes7)),
        print('port_08_tx', pktport8tx - (self.pre_tx_bytes8))
        print('port_08_rx', pktport8 - (self.pre_rx_bytes8)),
        print('port_10_tx', pktport10tx - (self.pre_tx_bytes10))
        print('port_10_rx', pktport10 - (self.pre_rx_bytes10)),
        print('port_12_tx', pktport12tx - (self.pre_tx_bytes12))
        print('port_12_rx', pktport12 - (self.pre_rx_bytes12)),
        self.rx_rate2_fix = pktport2 - (self.pre_rx_bytes2)
        self.rx_rate12_fix = pktport12tx - (self.pre_tx_bytes12)

        localtime = time.asctime(time.localtime(time.time()))
        print('Time:', time.strftime('%Y/%m/%d %H:%M:%S', time.localtime()))

        dic = {
            'port2': [{
                'tx_rate':
                self.rx_rate2_fix + ran  # pktport2-(self.pre_rx_bytes2)
            }],
            'port7': [{
                'tx_rate': (self.rx_rate12_fix - random.randint(5, 39))
            }],
        }
        with open(
                "/home/pmcn/Documents/project/public/static/sdn_monitor_10.json",
                "w") as f:
            json.dump(dic, f, indent=2, sort_keys=True, separators=(',', ':'))

        self.pre_rx_bytes2 = pktport2
        self.pre_tx_bytes2 = pktport2tx
        self.pre_rx_bytes4 = pktport4
        self.pre_tx_bytes4 = pktport4tx
        self.pre_rx_bytes7 = pktport7
        self.pre_tx_bytes7 = pktport7tx
        self.pre_rx_bytes8 = pktport8
        self.pre_tx_bytes8 = pktport8tx
        self.pre_rx_bytes10 = pktport10
        self.pre_tx_bytes10 = pktport10tx
        self.pre_rx_bytes12 = pktport12
        self.pre_tx_bytes12 = pktport12tx
