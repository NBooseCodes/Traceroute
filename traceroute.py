# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
import socket
from math import floor
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:
    # #
    # Educational Resource: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
    # Educational Resource: https://networklessons.com/cisco/ccna-routing-switching-icnd1-100-105/traceroute
    #
    #
    # Inspired by: https://github.com/katieschaum/CS372/blob/main/Traceroute/Schaumlk_IcmpHelperLibrary.py#L639                                                                                                                 #
    # Author: Katie Schaum
    # Date Accessed: 11-27-2024#
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    packets_sent = 0
    packets_received = 0
    RTTs = []

    # round_trip_time = 0

    min_RTT = 0
    max_RTT = 0
    avg_RTT = 0

    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        isValid = False
        __icmpTarget = ""  # Remote Host
        __destinationIpAddress = ""  # Remote Host IP Address
        __header = b''  # Header after byte packing
        __data = b''  # Data after encoding
        __dataRaw = ""  # Raw string data before encoding
        __icmpType = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 5
        __ttl = 255  # Time to live
        round_trip_time = 0

        __DEBUG_IcmpPacket = False  # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #

        def get_isValid(self):
            return self.isValid

        def getRTT(self):
            return self.round_trip_time

        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def set_isValid(self, isValid):
            self.isValid = isValid

        def setRTT(self, RTT):
            self.round_trip_time = RTT

        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)  # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum  # Rotate and add

            answer = ~checksum  # Invert bits
            answer = answer & 0xffff  # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),  # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()  # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()  # packHeader() and encodeData() transfer data to their respective bit
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()  # Result will set new checksum value
            self.__packHeader()  # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            if icmpReplyPacket.getIcmpData() == self.getDataRaw():
                if icmpReplyPacket.getIcmpIdentifier() == self.getPacketIdentifier():
                    if icmpReplyPacket.getIcmpSequenceNumber() == self.getPacketSequenceNumber():
                        icmpReplyPacket.setIsValidResponse(True)
                        IcmpHelperLibrary.packets_received += 1
                        # May need to add more
            else:
                expected_data = self.getDataRaw()
                actual_data = icmpReplyPacket.getIcmpData()
                expected_seqnum = self.getPacketSequenceNumber()
                actual_seqnum = icmpReplyPacket.getIcmpSequenceNumber()
                expected_packetID = self.getPacketIdentifier()
                actual_id = icmpReplyPacket.getIcmpIdentifier()
                IcmpHelperLibrary.IcmpPacket_EchoReply(icmpReplyPacket)

                print(f'Invalid response.\n Expected Data: {expected_data} Actual Data: {actual_data} \n '
                      f'Expected ID: {expected_packetID} Actual ID: {actual_id} \n '
                      f'Expected Sequence Number: {expected_seqnum} Actual Sequence Number: {actual_seqnum}')

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):

            icmp_3_error_code_dict = {
                0: 'Net Unreachable',
                1: 'Host Unreachable',
                2: 'Protocol Unreachable',
                3: 'Port Unreachable',
                4: 'Fragmentation Needed and Don\'t Fragment Flag Set',
                5: 'Source Route Failed',
                6: 'Destination Network Unknown',
                7: 'Destination Host Unknown',
                8: 'Source Host Isolated',
                9: 'Communication with Destination Network is Administratively Prohibited',
                10: 'Communication with Destination Host is Administratively Prohibited',
                11: 'Destination Network Unreachable for Type of Service',
                12: 'Destination Host Unreachable for Type of Service',
                13: 'Communication Administratively Prohibited',
                14: 'Host Precedence Violation',
                15: 'Precedence cutoff in effect'
            }

            icmp_11_error_dict = {
                0: 'Time to Live exceeded in Transit',
                1: 'Fragment Reassembly Time Exceeded'
            }

            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            # print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 5
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)

                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()

                timeLeft = timeLeft - howLongInSelect

                self.setRTT(floor(1000 * (timeReceived - pingStartTime)))

                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]
                    self.setIcmpType(icmpType)
                    self.setIcmpCode(icmpCode)

                    if icmpType == 3:  # Destination Unreachable
                        code_meaning = icmp_3_error_code_dict[icmpCode]
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d: %s    Address: %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  code_meaning,
                                  addr[0]
                              )
                              )
                    elif icmpType == 11:  # Time Exceeded

                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d: %s    Address: %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  icmp_11_error_dict[icmpCode],
                                  addr[0]
                              )
                              )

                    elif icmpType == 0:  # Echo Reply
                        self.isValid = True
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        return  # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i + 1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        ICMP_seqnum_valid = False
        ICMP_data_valid = False
        ICMP_identifier_valid = False

        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        def getICMP_seqnum_valid(self):
            return self.ICMP_seqnum_valid

        def getICMP_data_valid(self):
            return self.ICMP_data_valid

        def getICMP_identifier_valid(self):
            return self.ICMP_identifier_valid

        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setICMP_seqnum_valid(self, ICMP_seqnum_valid):
            self.ICMP_seqnum_valid = ICMP_seqnum_valid

        def setICMP_data_valid(self, ICMP_data_valid):
            self.ICMP_data_valid = ICMP_data_valid

        def setICMP_identifier_valid(self, ICMP_identifier_valid):
            self.ICMP_identifier_valid = ICMP_identifier_valid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]

            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                  )

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        RTTs = []
        num_valid_packets = 0
        num_sent_packets = 0

        # We are pinging 4 times
        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            num_sent_packets += 1

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()  # Build IP


            if icmpPacket.isValid:
                num_valid_packets += 1
            remote_host = icmpPacket.getIcmpTarget()
            bytes_sent = len(icmpPacket.getDataRaw())
            RTT = floor(icmpPacket.getRTT() * 1000)
            TTL = icmpPacket.getTtl()
            #print(f'Reply from {remote_host}: bytes={bytes_sent} time={RTT}ms TTL={TTL}')
            RTTs.append(icmpPacket.getRTT())  # Get the RTT of this trial
            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data
        minimum_RTT = min(RTTs)
        maximum_RTT = max(RTTs)
        avg_RTT = (sum(RTTs) / len(RTTs))
        num_lost_packets = num_sent_packets - num_valid_packets
        packet_loss = 100 * (num_sent_packets - num_valid_packets) / num_sent_packets

        # Print stats for this ping
        print("Ping statistics for %s:" % icmpPacket.getIcmpTarget())
        print("Packets: Sent = %d, Received = %d, Lost = %d (%d percent Loss)" % (num_sent_packets, num_valid_packets,
                                                                                  num_lost_packets, packet_loss))
        print("Approximate Round Trip Times in milliseconds:\n Minimum = %0.f    Maximum = %0.f    Average = %0.f" % (
            minimum_RTT, maximum_RTT, avg_RTT))

    def __sendIcmpTraceRoute(self, host):
        """
        Goal is to trace the route from our IP address to the entered host address. Much of the Ping functionality is
        re-used here.
        """
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        print(f'Traceroute to ({host})')
        # Set a starting sequence number and ICMP Code
        TTL = 1
        packetSeqNum = 1
        IcmpType = 1  # Dummy start
        while TTL < 50 and IcmpType != 0:  # At 0, we have finished our trace and we want a max 30 hops
            for i in range(3):
                # Build packet
                traceroutePacket = IcmpHelperLibrary.IcmpPacket()
                traceroutePacket.setTtl(packetSeqNum)
                randomIdentifier = (os.getpid() & 0xffff)  # Technically not needed because there will be no fragmentation, but good practice
                # Some PIDs are larger than 16 bit

                packetIdentifier = randomIdentifier

                traceroutePacket.buildPacket_echoRequest(packetIdentifier, packetSeqNum)  # Build ICMP for IP payload
                traceroutePacket.setIcmpTarget(host)    # Set the host for this packet (remote host entered above)

                traceroutePacket.sendEchoRequest()  # Build IP
                print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0

                # Below are needed to print out stats
                remote_host = traceroutePacket.getIcmpTarget()
                bytes_sent = len(traceroutePacket.getDataRaw()) - 20    # Remove IP portion of message (20 bytes)
                RTT = traceroutePacket.getRTT()
                TTL = traceroutePacket.getTtl()
                IcmpType = traceroutePacket.getIcmpType()
                IcmpCode = traceroutePacket.getIcmpCode()
                TTL = traceroutePacket.getTtl()


                #print(f'TTL={TTL}    RTT={RTT}  Type={IcmpType}    Code={IcmpCode}   {traceroutePacket.getIcmpTarget()}')
                #print(f'Reply from {remote_host}: bytes={bytes_sent} time={RTT}ms TTL={TTL}')

                traceroutePacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                traceroutePacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            packetSeqNum += 1

    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line


    # icmpHelperPing.sendPing("192.168.1.254")
    # icmpHelperPing.traceRoute("200.10.227.250")
    # icmpHelperPing.traceRoute("www.google.com")
    icmpHelperPing.traceRoute("200.229.91.33")
    # icmpHelperPing.traceRoute("81.2.194.123")     # Czech IP Address
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("195.110.124.133")    # Italian IP Address


if __name__ == "__main__":
    main()
