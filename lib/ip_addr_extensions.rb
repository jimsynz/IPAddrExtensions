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

module Mashd
  module Cc
    module IPAddrExtensions

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
      def length=(length)
        if self.ipv4?
          @mask_addr=((1<<32)-1) - ((1<<32-length)-1)
        elsif self.ipv6?
          @mask_addr=((1<<128)-1) - ((1<<128-length)-1)
        end
      end

      # Retrieve the first address in this prefix
      # (called a network address in IPv4 land)
      def first
        IPAddr.new(@addr & @mask_addr, @family)
      end
      alias :begin :first

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
      alias :end :last

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
          mac = mac.split(":").join.downcase
          if mac.match(/^[0-9a-f]{12}/).nil?
            raise ArgumentError, "Second argument must be a valid MAC address."
          end
          e64 = (mac[0..5] + "fffe" + mac[6..11]).to_i(16) ^ 0x0200000000000000
          IPAddr.new(self.first.to_i + e64, Socket::AF_INET6)
        end
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
          elsif IPAddr.new("14.0.0.0/8").include? self
            "PUBLIC DATA"
          elsif IPAddr.new("127.0.0.0/8").include? self
            "LOOPBACK"
          elsif IPAddr.new("128.0.0.0/18").include? self
            "RESERVED (IANA)"
          elsif IPAddr.new("168.254.0.0/16").include? self
            "AUTOCONF PRIVATE"
          elsif IPAddr.new("172.16.0.0/12").include? self
            "RFC1918 PRIVATE"
          elsif IPAddr.new("191.255.0.0/16").include? self
            "RESERVED (IANA)"
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
          elsif IPAddr.new("223.255.255.0/24").include? self
            "RESERVED (IANA)"
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
            if IPAddr.new("2002::/16").include? self
              x = self.to_string.scanf("%*4x:%4x:%4x:%*s")
              "GLOBAL UNICAST (6to4: #{IPAddr.new((x[0]<<16)+x[1], Socket::AF_INET6).to_s})"
            elsif IPAddr.new("2001::/32").include? self
              server_ip = IPAddr.new((@addr >> 64) & ((1<<32)-1), Socket::AF_INET)
              client_ip = IPAddr.new((@addr & ((1<<32)-1)) ^ ((1<<32)-1), Socket::AF_INET)
              udp_port = ((@addr >> 32) & ((1<<16)-1))
              "GLOBAL UNICAST (Teredo #{client_ip.to_s}:#{udp_port.to_s} -> #{server_ip.to_s}:#{udp_port.to_s})"
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
        self.scope.split(' ').member? 'UNICAST'
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

      # Convert an IPv4 address into an IPv6 
      # 6to4 address.
      def to_6to4
        if @family == Socket::AF_INET
          IPAddr.new((0x2002 << 112) + (@addr << 80), Socket::AF_INET6)
        else
          self
        end
      end

      # Return the space available inside this prefix
      def space
        self.last.to_i - self.first.to_i + 1
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
              res << "#{octets * '.'}.in-addr.arpa"
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

    end
    module StringIPExtensions
      def to_ip
        IPAddr.new(self.to_s)
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
end

IPAddr.send(:include, Mashd::Cc::IPAddrExtensions)
String.send(:include, Mashd::Cc::StringIPExtensions)
Integer.send(:include, Mashd::Cc::IntIPExtensions)
