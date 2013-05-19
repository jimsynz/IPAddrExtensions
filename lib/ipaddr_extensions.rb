# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Ruby IPAddr Extensions.
#
# The Initial Developer of the Original Code is James Harton.
# Portions created by the Initial Developer are Copyright (C) 2010
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#
# ***** END LICENSE BLOCK *****

require 'ipaddr'
require 'scanf'
require 'digest/sha1'

module Sociable
  module IPAddrExtensions

    def self.included(base)
      base.extend(ClassMethods)
      base.class_eval do
        alias_method :mask_without_a_care!, :mask!
        alias_method :mask!, :mask_with_a_care!
      end
    end

    # Return the bit length of the prefix
    # ie:
    #     IPAddr.new("2001:db8::/32").length
    #     => 32
    #     IPAddr.new("192.0.2.0/255.255.255.0").length
    #     => 24
    def length
      # nasty hack, but works well enough.
      @mask_addr.to_s(2).count("1")
    end

    # Modify the bit length of the prefix
    def length=(length)
      if self.ipv4?
        @mask_addr=((1<<32)-1) - ((1<<32-length)-1)
      elsif self.ipv6?
        @mask_addr=((1<<128)-1) - ((1<<128-length)-1)
      end
    end

    # Return an old-style subnet mask
    # ie:
    #     IPAddr.new("2001:db8::/32").subnet_mask
    #     => #<IPAddr: IPv6:ffff:ffff:0000:0000:0000:0000:0000:0000/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff>
    #     IPAddr.new("192.0.2.0/255.255.255.0").subnet_mask
    #     => #<IPAddr: IPv4:255.255.255.0/255.255.255.255>
    def subnet_mask
      @mask_addr.to_ip
    end

    # Return a "cisco style" subnet mask for use in ACLs:
    #
    #     IPAddr.new("2001:db8::/32").wildcard_mask
    #     => #<IPAddr: IPv6:0000:0000:ffff:ffff:ffff:ffff:ffff:ffff/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff>
    #     IPAddr.new("192.0.2.0/255.255.255.0").wildcard_mask
    #     => #<IPAddr: IPv4:0.0.0.255/255.255.255.255>
    def wildcard_mask
      if self.ipv4?
        (@mask_addr ^ IPAddr::IN4MASK).to_ip
      else
        (@mask_addr ^ IPAddr::IN6MASK).to_ip
      end
    end

    # Retrieve the first address in this prefix
    # (called a network address in IPv4 land)
    def first
      IPAddr.new(@addr & @mask_addr, @family)
    end

    # Retrieve the last address in this prefix
    # (called a broadcast address in IPv4 land)
    def last
      if @family == Socket::AF_INET
        IPAddr.new(first.to_i | (@mask_addr ^ IPAddr::IN4MASK), @family)
      elsif @family == Socket::AF_INET6
        IPAddr.new(first.to_i | (@mask_addr ^ IPAddr::IN6MASK), @family)
      else
        raise "unsupported address family."
      end
    end

    # Return an EUI-64 host address for the current
    # prefix (must be a 64 bit long IPv6 prefix).
    def eui_64(mac)
      if @family != Socket::AF_INET6
        raise Exception, "EUI-64 only makes sense on IPv6 prefixes."
      elsif self.length != 64
        raise Exception, "EUI-64 only makes sense on 64 bit IPv6 prefixes."
      end
      if mac.is_a? Integer
        mac = "%:012x" % mac
      end
      if mac.is_a? String
        mac.gsub!(/[^0-9a-fA-F]/, "")
        if mac.match(/^[0-9a-f]{12}/).nil?
          raise ArgumentError, "Second argument must be a valid MAC address."
        end
        e64 = (mac[0..5] + "fffe" + mac[6..11]).to_i(16) ^ 0x0200000000000000
        IPAddr.new(self.first.to_i + e64, Socket::AF_INET6)
      end
    end

    def eui_64?
      if @family != Socket::AF_INET6
        raise Exception, "EUI-64 only makes sense on IPv6 prefixes."
      #elsif self.length != 64
      #  raise Exception, "EUI-64 only makes sense on 64 bit IPv6 prefixes."
      end
      (self.to_i & 0x20000fffe000000) == 0x20000fffe000000
    end

    def mac
      if eui_64?
        network_bits = self.to_i & 0xffffffffffffffff
        top_chunk = network_bits >> 40
        bottom_chunk = network_bits & 0xffffff
        mac = ((top_chunk << 24) + bottom_chunk) ^ 0x20000000000
        result = []
        5.downto(0).each do |i|
          result << sprintf("%02x", (mac >> i * 8) & 0xff)
        end
        result * ':'
      end
    end

    # Call the original mask! method but don't allow it
    # to change the internally stored address, since we
    # might actually need that.
    def mask_with_a_care!(mask)
      original_addr = @addr
      mask_without_a_care!(mask)
      @addr = original_addr unless self.class.mask_by_default
      return self
    end

    MSCOPES = {
      1 => "INTERFACE LOCAL MULTICAST",
      2 => "LINK LOCAL MULTICAST",
      4 => "ADMIN LOCAL MULTICAST",
      5 => "SITE LOCAL MULTICAST",
      8 => "ORGANISATION LOCAL MULTICAST",
      0xe => "GLOBAL MULTICAST"
    }

    MDESTS = {
      1 => "ALL NODES",
      2 => "ALL ROUTERS",
      3 => "ALL DHCP SERVERS",
      4 => "DVMRP ROUTERS",
      5 => "OSPFIGP",
      6 => "OSPFIGP DESIGNATED ROUTERS",
      7 => "ST ROUTERS",
      8 => "ST HOSTS",
      9 => "RIP ROUTERS",
      0xa => "EIGRP ROUTERS",
      0xb => "MOBILE-AGENTS",
      0xc => "SSDP",
      0xd => "ALL PIM ROUTERS",
      0xe => "RSVP ENCAPSULATION",
      0xf => "UPNP",
      0x16 => "ALL MLDV2 CAPABLE ROUTERS",
      0x6a => "ALL SNOOPERS",
      0x6b => "PTP-PDELAY",
      0x6c => "SARATOGA",
      0x6d => "LL MANET ROUTERS",
      0xfb => "MDNSV6",
      0x100 => "VMTP MANAGERS GROUP",
      0x101 => "NTP",
      0x102 => "SGI-DOGFIGHT",
      0x103 => "RWHOD",
      0x104 => "VNP",
      0x105 => "ARTIFICIAL HORIZONS",
      0x106 => "NSS",
      0x107 => "AUDIONEWS",
      0x108 => "SUN NIS+",
      0x109 => "MTP",
      0x10a => "IETF-1-LOW-AUDIO",
      0x10b => "IETF-1-AUDIO",
      0x10c => "IETF-1-VIDEO",
      0x10d => "IETF-2-LOW-AUDIO",
      0x10e => "IETF-2-AUDIO",
      0x10f => "IETF-2-VIDEO",
      0x110 => "MUSIC-SERVICE",
      0x111 => "SEANET-TELEMETRY",
      0x112 => "SEANET-IMAGE",
      0x113 => "MLOADD",
      0x114 => "ANY PRIVATE EXPERIMENT",
      0x115 => "DVMRP on MOSPF",
      0x116 => "SVRLOC",
      0x117 => "XINGTV",
      0x118 => "MICROSOFT-DS",
      0x119 => "NBC-PRO",
      0x11a => "NBC-PFN",
      0x10001 => "LINK NAME",
      0x10002 => "ALL DHCP AGENTS",
      0x10003 => "LINK LOCAL MULTICAST NAME",
      0x10004 => "DTCP ANNOUNCEMENT",
    }

    # Returns a string describing the scope of the
    # address.
    def scope
      if @family == Socket::AF_INET
        if IPAddr.new("0.0.0.0/8").include? self
          "CURRENT NETWORK"
        elsif IPAddr.new("10.0.0.0/8").include? self
          "RFC1918 PRIVATE"
        elsif IPAddr.new("127.0.0.0/8").include? self
          "LOOPBACK"
        elsif IPAddr.new("168.254.0.0/16").include? self
          "AUTOCONF PRIVATE"
        elsif IPAddr.new("172.16.0.0/12").include? self
          "RFC1918 PRIVATE"
        elsif IPAddr.new("192.0.0.0/24").include? self
          "RESERVED (IANA)"
        elsif IPAddr.new("192.0.2.0/24").include? self
          "DOCUMENTATION"
        elsif IPAddr.new("192.88.99.0/24").include? self
          "6to4 ANYCAST"
        elsif IPAddr.new("192.168.0.0/16").include? self
          "RFC1918 PRIVATE"
        elsif IPAddr.new("198.18.0.0/15").include? self
          "NETWORK BENCHMARK TESTS"
        elsif IPAddr.new("198.51.100.0/24").include? self
          "DOCUMENTATION"
        elsif IPAddr.new("203.0.113.0/24").include? self
          "DOCUMENTATION"
        elsif IPAddr.new("224.0.0.0/4").include? self
          if IPAddr.new("239.0.0.0/8").include? self
            "LOCAL MULTICAST"
          else
            "GLOBAL MULTICAST"
          end
        elsif IPAddr.new("240.0.0.0/4").include? self
          "RESERVED"
        elsif IPAddr.new("255.255.255.255") == self
          "GLOBAL BROADCAST"
        else
          "GLOBAL UNICAST"
        end
      elsif @family == Socket::AF_INET6
        if IPAddr.new("2000::/3").include? self
          require 'scanf'
          if is_6to4?
            "GLOBAL UNICAST (6to4: #{from_6to4})"
          elsif is_teredo?
            "GLOBAL UNICAST (Teredo #{from_teredo[:client].to_s}:#{from_teredo[:port].to_s} -> #{from_teredo[:server].to_s}:#{from_teredo[:port].to_s})"
          elsif IPAddr.new("2001:10::/28").include? self
            "ORCHID"
          elsif IPAddr.new("2001:db8::/32").include? self
            "DOCUMENTATION"
          else
            "GLOBAL UNICAST"
          end
        elsif IPAddr.new("::/128") ==  self
          "UNSPECIFIED ADDRESS"
        elsif IPAddr.new("::1/128") == self
          "LINK LOCAL LOOPBACK"
        elsif IPAddr.new("::ffff:0:0/96").include? self
          a,b,c,d = self.to_string.scanf("%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%4x:%4x:%4x:%4x")
          "IPv4 MAPPED (#{a.to_s}.#{b.to_s}.#{c.to_s}.#{d.to_s})"
        elsif IPAddr.new("::/96").include? self
          a,b,c,d = self.to_string.scanf("%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%*4x:%4x:%4x:%4x:%4x")
          "IPv4 TRANSITION (#{a.to_s}.#{b.to_s}.#{c.to_s}.#{d.to_s}, deprecated)"
        elsif IPAddr.new("fc00::/7").include? self
          "UNIQUE LOCAL UNICAST"
        elsif IPAddr.new("fec0::/10").include? self
          "SITE LOCAL (deprecated)"
        elsif IPAddr.new("fe80::/10").include? self
          "LINK LOCAL UNICAST"
        elsif IPAddr.new("ff00::/8").include? self
          mscope,mdesta,mdestb = self.to_string.scanf("%*1x%*1x%*1x%1x:%*4x:%*4x:%*4x:%*4x:%*4x:%4x:%4x")
          mdest = (mdesta << 16) + mdestb
          s = "MULTICAST"
          if MSCOPES[mscope]
            s += " #{MSCOPES[mscope]}"
          end
          if MDESTS[mdest]
            s += " #{MDEST[mdest]}"
          end
          if multicast_from_prefix?
            s += " (prefix = #{prefix_from_multicast.to_string_including_length})"
          end
          s
        else
          "RESERVED"
        end
      end
    end

    # Some scope tests
    def local?
      self.scope.split(' ').member? 'LOCAL'
    end
    def unicast?
      !self.scope.split(' ').any? { |scope| ['BROADCAST', 'MULTICAST'].member? scope }
    end
    def multicast?
      self.scope.split(' ').member? 'MULTICAST'
    end
    def link?
      self.scope.split(' ').member? 'LINK'
    end
    def documentation?
      self.scope.split(' ').member? 'DOCUMENTATION'
    end
    def loopback?
      self.scope.split(' ').member? 'LOOPBACK'
    end
    def global?
      self.scope.split(' ').member? 'GLOBAL'
    end
    def private?
      self.scope.split(' ').member? 'PRIVATE'
    end
    def multicast_from_prefix?
      ipv6? && ('ff00::/8'.to_ip.include? self) && ((self.to_i >> 116) & 0x03 == 3)
    end

    # Returns the original prefix a Multicast address was generated from
    # see RFC3306
    def prefix_from_multicast
      if ipv6? && multicast_from_prefix?
        prefix_length = (to_i >> 92) & 0xff
        if (prefix_length == 0xff) && (((to_i >> 112) & 0xf) >= 2)
          # Link local prefix
          #(((to_i >> 32) & 0xffffffffffffffff) + (0xfe80 << 112)).to_ip(Socket::AF_INET6).tap { |p| p.length = 64 }
          return nil # See http://redmine.ruby-lang.org/issues/5468
        else
          # Global unicast prefix
          (((to_i >> 32) & 0xffffffffffffffff) << 64).to_ip(Socket::AF_INET6).tap { |p| p.length = prefix_length }
        end
      end
    end

    # Convert an IPv4 address into an IPv6
    # 6to4 address.
    def to_6to4
      if @family == Socket::AF_INET
        IPAddr.new((0x2002 << 112) + (@addr << 80), Socket::AF_INET6).tap { |p| p.length = 48 }
      end
    end

    # Return the space available inside this prefix
    def space
      self.last.to_i - self.first.to_i + 1
    end

    # Return usable address space inside this prefix
    def usable
      if ipv6?
        space
      else
        space - 2
      end
    end

    # Return likely reverse zones for the Address or prefix
    # (differs from reverse() because it will return the correct
    #  number of zones to adequately delegate the prefix).
    def reverses
      if @family == Socket::AF_INET
        if self.length == 32
          [ self.reverse ]
        else
          boundary = self.length % 8 == 0 && self.length != 0 ? self.length / 8 - 1 : self.length / 8
          divisor = (boundary + 1) * 8
          count = (self.last.to_i - self.first.to_i) / (1 << 32 - divisor)
          res = []
          (0..count).each do |i|
            octets = IPAddr.new(first.to_i + ((1<<32-divisor)*i), Socket::AF_INET).to_s.split('.')[0..boundary]
            res << "#{octets.reverse * '.'}.in-addr.arpa"
          end
          res
        end
      elsif @family == Socket::AF_INET6
        if self.length == 128
          [ self.reverse ]
        else
          boundary = self.length % 16 == 0 && self.length != 0 ? self.length / 4 - 1 : self.length / 4
          divisor = (boundary + 1) * 4
          count = (self.last.to_i - self.first.to_i) / (1 << 128-divisor)
          res = []
          (0..count).each do |i|
            baseaddr = self.first.to_i + (1<<128-divisor)*i
            octets = ("%032x" % baseaddr).split('')[0..boundary]
            res << octets.reverse * '.' + '.ip6.arpa'
          end
          res
        end
      end
    end

    # Extra quick tests
    def host?
      (@family == Socket::AF_INET && self.length == 32) ||
        (@family == Socket::AF_INET6 && self.length == 128)
    end

    def prefix?
      !self.host?
    end

    def to_string_including_length
      if host?
        to_s
      else
        "#{to_s}/#{length.to_s}"
      end
    end

    alias bitmask length

    def /(by)
      if self.ipv4?
        space = 1 << 32 - length
        if space % by == 0
          newmask = (((1<<32)-1) ^ (space/by-1)).to_s(2).count("1")
          (0..by-1).collect do |i|
            ip = (self.to_i + ((1 << 32 - newmask)*i)).to_ip(Socket::AF_INET)
            ip.length = newmask
            ip
          end
        else
          raise ArgumentError.new "Cannot evenly devide by #{by}"
        end
      elsif self.ipv6?
        space = 1 << 128 - length
        if space % by == 0
          newmask = (((1<<128)-1) ^ (space/by-1)).to_s(2).count("1")
          (0..by-1).collect do |i|
            ip = (self.to_i + ((1 << 128 - newmask)*i)).to_ip(Socket::AF_INET6)
            ip.length = newmask
            ip
          end
        else
          raise ArgumentError.new "Cannot evenly devide by #{by}"
        end
      end
    end

    def is_teredo?
      IPAddr.new("2001::/32").include? self
    end

    def from_teredo
      is_teredo? && { :server => IPAddr.new((@addr >> 64) & ((1<<32)-1), Socket::AF_INET), :client => IPAddr.new((@addr & ((1<<32)-1)) ^ ((1<<32)-1), Socket::AF_INET), :port => ((@addr >> 32) & ((1<<16)-1)) }
    end

    def is_6to4?
      IPAddr.new("2002::/16").include? self
    end
    def from_6to4
      x = self.to_string.scanf("%*4x:%4x:%4x:%s")
      IPAddr.new((x[0]<<16)+x[1], Socket::AF_INET)
    end

    module ClassMethods

      # By default IPAddr masks a non all-ones prefix so that the
      # "network address" is all that's stored.  This loses data
      # for some applications and isn't really necessary since
      # anyone expecting that should use #first instead.
      # This defaults to on to retain compatibility with the
      # rubycore IPAddr class.
      def mask_by_default
        # You can't use ||= for bools.
        if @mask_by_default.nil?
          @mask_by_default = true
        end
        @mask_by_default
      end
      def mask_by_default=(x)
        @mask_by_default = !!x
      end

      # Generate an IPv6 Unique Local Address using the supplied system MAC address.
      # Note that the MAC address is just used as a source of randomness, so where you
      # get it from is not important and doesn't restrict this ULA to just that system.
      # See RFC4193
      def generate_ULA(mac, subnet_id = 0, locally_assigned=true)
        now = Time.now.utc
        ntp_time = ((now.to_i + 2208988800) << 32) + now.nsec # Convert time to an NTP timstamp.
        system_id = '::/64'.to_ip.eui_64(mac).to_i # Generate an EUI64 from the provided MAC address.
        key = [ ntp_time, system_id ].pack('QQ') # Pack the ntp timestamp and the system_id into a binary string
        global_id = Digest::SHA1.digest( key ).unpack('QQ').last & 0xffffffffff # Use only the last 40 bytes of the SHA1 digest.

        prefix =
          (126 << 121) + # 0xfc (bytes 0..6)
          ((locally_assigned ? 1 : 0) << 120) + # locally assigned? (byte 7)
          (global_id << 80) + # 40 bit global idenfitier (bytes 8..48)
          ((subnet_id & 0xffff) << 64) # 16 bit subnet_id (bytes 48..64)

        prefix.to_ip(Socket::AF_INET6).tap { |p| p.length = 64 }
      end

    end

  end

  module StringIPExtensions
    def to_ip
      begin
        IPAddr.new(self.to_s)
      rescue ArgumentError => e
        raise ArgumentError, "invalid address #{self.inspect}"
      end
    end
  end
  module IntIPExtensions
    def to_ip(af=nil)
      if af.nil?
        ## If there is no address family specified then try to guess...
        if self.to_i > 0xffffffff
          # If the integer is bigger than any possible IPv4 address
          # then presume it's an IPv6 address
          af = Socket::AF_INET6
        else
          # otherwise presume it's IPv4
          af = Socket::AF_INET
        end
      end
      IPAddr.new(self.to_i, af)
    end
  end
end

class IPTuple

  attr_accessor :source_ip, :destination_ip, :ip_protocol, :source_port, :destination_port

  def initialize src_ip=nil, dst_ip=nil, ip_proto=nil, src_port=nil, dst_port=nil
    @source_ip = src_ip if src_ip.is_a? IPAddr
    @source_ip = src_ip.to_ip if src_ip.is_a? String
    @destination_ip = dst_ip if dst_ip.is_a? IPAddr
    @destination_ip = dst_ip.to_ip if dst_ip.is_a? String
    @ip_protocol = ip_proto if ip_proto.is_a? IPProtocol
    @ip_protocol = IPProtocol.new(ip_proto) if ip_proto.is_a? Integer
    @source_port = src_port if ((1..65535).include? src_port)
    @destination_port = dst_port if ((1..65535).include? dst_port)
  end

  def ipv4?
    if @source_ip && @destination_ip
      @source_ip.ipv4? && @destination_ip.ipv4?
    elsif @source_ip
      @source_ip.ipv4?
    elsif @destination_ip
      @destination_ip.ipv4?
    end
  end

  def ipv6?
    if @source_ip && @destination_ip
      @source_ip.ipv6? && @destination_ip.ipv6?
    elsif @source_ip
      @source_ip.ipv6?
    elsif @destination_ip
      @destination_ip.ipv6?
    end
  end
end

class IPProtocol
  # See http://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
  NUMBERS = (1..142).to_a + [ 255 ]
  NAMES = {
    0 => "HOPOPT",
    1 => "ICMP",
    2 => "IGMP",
    3 => "GGP",
    4 => "IPv4",
    5 => "ST",
    6 => "TCP",
    7 => "CBT",
    8 => "EGP",
    9 => "IGP",
    10 => "BBN-RCC-MON",
    11 => "NVP-II",
    12 => "PUP",
    13 => "ARGUS",
    14 => "EMCON",
    15 => "XNET",
    16 => "CHAOS",
    17 => "UDP",
    18 => "MUX",
    19 => "DCN-MEAS",
    20 => "HMP",
    21 => "PRM",
    22 => "XNS-IDP",
    23 => "TRUNK-1",
    24 => "TRUNK-2",
    25 => "LEAF-1",
    26 => "LEAF-2",
    27 => "RDP",
    28 => "IRTP",
    29 => "ISO-TP4",
    30 => "NETBLT",
    31 => "MFE-NSP",
    32 => "MERIT-INP",
    33 => "DCCP",
    34 => "3PC",
    35 => "IDPR",
    36 => "XTP",
    37 => "DDP",
    38 => "IDPR-CMTP",
    39 => "TP++",
    40 => "IL",
    41 => "IPv6",
    42 => "SDRP",
    43 => "IPv6-Route",
    44 => "IPv6-Frag",
    45 => "IDRP",
    46 => "RSVP",
    47 => "GRE",
    48 => "DSR",
    49 => "BNA",
    50 => "ESP",
    51 => "AH",
    52 => "I-NLSP",
    53 => "SWIPE",
    54 => "NARP",
    55 => "MOBILE",
    56 => "TLSP",
    57 => "SKIP",
    58 => "IPv6-ICMP",
    59 => "IPv6-NoNxt",
    60 => "IPv6-Opts",
    62 => "CFTP",
    64 => "SAT-EXPAK",
    65 => "KRYPTOLAN",
    66 => "RVD",
    67 => "IPPC",
    69 => "SAT-MON",
    70 => "VISA",
    71 => "IPCV",
    72 => "CPNX",
    73 => "CPHB",
    74 => "WSN",
    75 => "PVP",
    76 => "BR-SAT-MON",
    77 => "SUN-ND",
    78 => "WB-MON",
    79 => "WB-EXPAK",
    80 => "ISO-IP",
    81 => "VMTP",
    82 => "SECURE-VMTP",
    83 => "VINES",
    84 => "TTP",
    84 => "IPTM",
    85 => "NSFNET-IGP",
    86 => "DGP",
    87 => "TCF",
    88 => "EIGRP",
    89 => "OSPFIGP",
    90 => "Sprite-RPC",
    91 => "LARP",
    92 => "MTP",
    93 => "AX.25",
    94 => "IPIP",
    95 => "MICP",
    96 => "SCC-SP",
    97 => "ETHERIP",
    98 => "ENCAP",
    100 => "GMTP",
    101 => "IFMP",
    102 => "PNNI",
    103 => "PIM",
    104 => "ARIS",
    105 => "SCPS",
    106 => "QNX",
    107 => "A/N",
    108 => "IPComp",
    109 => "SNP",
    110 => "Compaq-Peer",
    111 => "IPX-in-IP",
    112 => "VRRP",
    113 => "PGM",
    115 => "L2TP",
    116 => "DDX",
    117 => "IATP",
    118 => "STP",
    119 => "SRP",
    120 => "UTI",
    121 => "SMP",
    122 => "SM",
    123 => "PTP",
    124 => "ISIS over IPv4",
    125 => "FIRE",
    126 => "CRTP",
    127 => "CRUDP",
    128 => "SSCOPMCE",
    129 => "IPLT",
    130 => "SPS",
    131 => "PIPE",
    132 => "SCTP",
    133 => "FC",
    134 => "RSVP-E2E-IGNORE",
    135 => "Mobility Header",
    136 => "UDPLite",
    137 => "MPLS-in-IP",
    138 => "manet",
    139 => "HIP",
    140 => "Shim6",
    141 => "WESP",
    142 => "ROHC",
    255 => "Reserved",
  }

  def initialize proto_num
    @number = proto_num if NUMBERS.member? proto_num
  end

  def to_ip
    @number
  end

  def to_s
    NAMES[@number]
  end

end

IPAddr.send(:include, Sociable::IPAddrExtensions)
String.send(:include, Sociable::StringIPExtensions)
Integer.send(:include, Sociable::IntIPExtensions)
