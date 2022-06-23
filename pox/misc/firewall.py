# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.vlan import vlan
from pox.lib.packet.llc import llc
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.udp import udp
from pox.lib.packet.tcp import tcp
from pox.lib.packet.icmp import icmp
from pox.lib.packet.arp import arp

from pox.lib.packet.packet_utils import *

from pox.lib.addresses import *

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

TCP_PROTOCOL  = 6
UDP_PROTOCOL  = 17

class Firewall(object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """

  def __init__ (self, connection, src, dst, port, protocol):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection 

    if src == "undef":
      print("BLOQUEIO DE FONTE NAO DEFINIDO")
      self.blocked_src_defined = False
    else:
      self.blocked_src_defined = True
      try:
        self.blocked_src = IPAddr(src)
      except:
        self.blocked_src = IPAddr6(src)
      print("Fontes bloqueadas: ", self.blocked_src)

    if dst == "undef":
      print("BLOQUEIO DE DESTINO NAO DEFINIDO")
      self.blocked_dst_defined = False
    else:
      self.blocked_dst_defined = True
      try:
        self.blocked_dst  = IPAddr(dst)
      except:
        self.blocked_dst = IPAddr6(dst)
      print("Destinos bloqueados: ", self.blocked_dst)

    if int(port) == -1:
      print("BLOQUEIO DE PORTAS NAO DEFINIDO")
      self.blocked_port_defined = False
    else:
      self.blocked_port_defined = True
      self.blocked_port = int(port)
      print("Portas bloqueadas: ", self.blocked_port)

    if protocol == "undef":
      print("BLOQUEIO DE PROTOCOLOS NAO DEFINIDO")
      self.blocked_protocol_defined = False
    else:
      self.blocked_protocol_defined = True
      if protocol == "tcp":
        self.blocked_protocol = TCP_PROTOCOL
      elif protocol == "udp":
        self.blocked_protocol = UDP_PROTOCOL
      print("Protocolos bloqueados: ", self.blocked_protocol)

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).

  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """
    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # NOTE: associate src ip addr to port from which message came in
    # print(packet.payload)
    # print("prototype", packet.payload.prototype)
    
    packet_type = packet.next.__class__.__name__
    protocol = 0
    if packet_type == 'arp':
        srcaddr = packet.next.protosrc
        dstaddr = packet.next.protodst
        protocol = packet.next.prototype
    elif packet_type == 'ipv4' or packet_type == 'ipv6':
        srcaddr = packet.next.srcip
        dstaddr = packet.next.dstip
        protocol = packet.next.protocol

    srcport = packet_in.in_port
    self.mac_to_port[srcaddr] = srcport

    # print("src", srcaddr)
    # print("dst", dstaddr)
    # print("srcport", srcport)
    # print("mactoport[srcaddr]", self.mac_to_port[srcaddr])
    # print("protocol", protocol)

    ############ DEBUG
    # print("next: ", packet.next)
    # print("next.protocol: ", packet.next.protocol)
    # try:
    #     print("next.next: ", packet.next.next)
    # except:
    #     pass
    # try:
    #     print("protocol: ", packet.type_parsers[packet.type](packet.raw).protocol)
    #     print("next: ", packet.type_parsers[packet.type](packet.raw).next)
    # except:
    #     pass

    dstport = self.mac_to_port.get(dstaddr)
    if dstport != None:
        log.debug("Installing Flow [srcip: %s][dstip: %s][dstport: %s]" % (srcaddr, dstaddr, dstport))

        msg = of.ofp_flow_mod() # NOTE: already is OFPFC_ADD
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 60
        msg.match.in_port = srcport

        # Firewall : bloqueio de pacotes
        #   Se o pacote deve ser bloqueado de acordo com os argumentos passados, entao a acao gravada
        #   na tabela e para nao repassar o pacote a nenhuma porta
        if self.block_packet(srcaddr, srcport, dstaddr, dstport, protocol) == True:
            action = of.ofp_action_output(port=0)
        else:
            action = of.ofp_action_output(port=dstport)
            self.resend_packet(packet_in, dstport)
        msg.actions.append(action)
        self.connection.send(msg)
    else:
        self.resend_packet(packet_in, of.OFPP_ALL)

  def block_packet(self, srcaddr, srcport, dstaddr, dstport, protocol):
    if self.blocked_src_defined and self.blocked_src == srcaddr:
        return True
    if self.blocked_dst_defined and self.blocked_dst == dstaddr:
        return True
    if self.blocked_port_defined and (self.blocked_port == srcport or self.blocked_port == dstport):
        return True
    if self.blocked_protocol_defined and self.blocked_protocol == protocol:
        return True
    return False
    

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)



def launch (src="undef", dst="undef", port=-1, protocol="undef"):
  """
  Starts the firewall 
  """
  def start_firewall(event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection, src, dst, port, protocol)
  core.openflow.addListenerByName("ConnectionUp", start_firewall)

