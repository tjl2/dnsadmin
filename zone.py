# zone.py
import os
import re
import string
import socket
from recordtemplates import *

class Zone:
    """BIND DNS Zone class. Holds lists of other objects and can read and write
records to files.
"""
    
    def __init__(self, zone, debug=False):
        self.name = zone
        # Create empty lists for A, CNAME, PTR & MX records
        self.a     = []
        self.aaaa  = []
        self.cname = []
        self.hinfo = []
        self.mx    = []
        self.ns    = []
        self.ptr   = []
        self.srv   = []
        self.txt   = []
        # Create empty dictionary for SOA.
        self.soa = {
            'ttl':None, 'ns':None, 'email':None, 'serial':None,
            'refresh':None, 'retry':None, 'expiry':None, 'minttl':None
        }
        self.conf_entry = ''
        self.zone_file = '' # full path to zone file
        self.debug = debug

    def __cmp__(self, other):
        return cmp(self.name, other.name)

    def setSoa(self, ttl, ns, email, serial, refresh, retry, expiry, minttl):
        # Set up the start of authority details.
        self.soa['ttl'] = ttl
        self.soa['ns'] = ns
        self.soa['email'] = email
        self.soa['serial'] = serial
        self.soa['refresh'] = refresh
        self.soa['retry'] = retry
        self.soa['expiry'] = expiry
        self.soa['minttl'] = minttl

    def getSoa(self):
        "Output the SOA as a string, suitable for writing to a file"
        
        soaStr = """$TTL %s
%s IN SOA  %s %s (
    %s  ; serial number YYYYMMDDCC - LEAVE THIS, dnsadmin WILL MANAGE IT FOR YOU
    %s  ; refresh
    %s  ; retry
    %s  ; expiration
    %s  ; minimum ttl
    )""" % (self.soa['ttl'], self.name, self.soa['ns'], self.soa['email'],
        self.soa['serial'], self.soa['refresh'], self.soa['retry'],
        self.soa['expiry'], self.soa['minttl'])
        
        return soaStr
    
    def parse_zone_file(self, zoneFile=None):
        "Read a zone file and fill zone attributes with the contents"
        
        if zoneFile == None:
            zoneFile = self.zone_file
        
        try:
            zf = open(zoneFile, 'r')
            # Iterate through lines of zonefile.
            for line in zf:
                # pull out the $TTL line
                if line.startswith('$TTL'):
                    tokens = line.split()
                    self.soa['ttl'] = tokens[1].strip(string.whitespace)
                    break
            # Find the start and end positions of the SOA.
            zf.seek(0,2)
            endPos = zf.tell()
            zf.seek(0)
            while zf.tell() < endPos:
                lineStart = zf.tell()
                line = zf.readline()
                lineEnd = zf.tell()
                if line.find('(') > -1:
                    soaStart = lineStart
                if line.find(')') > -1:
                    soaEnd = lineEnd
                    break
                zf.seek(zf.tell())
            zf.seek(soaStart)
            # Read the SOA section
            soaTmp = zf.read(soaEnd - soaStart)
            # We need to reduce soaTmp to one line (soaStr).
            soaLines = soaTmp.split('\n');
            soaStr = ''
            # Remove all comments from soaLines.
            for line in soaLines:
                if line.find(';') > 0:
                    soaStr = soaStr + line[0:line.find(';')]
                else:
                    soaStr = soaStr + line
            soaStr = soaStr.lower()
            # Tokenize on whitespace
            soaTokensTmp = soaStr.split()
            # Remove list items that are just spaces from soaTokens
            soaTokens = []
            for token in soaTokensTmp:
                # Don't add any of the junk that isn't actual data
                if token != '' and token != 'in' and token != 'soa' \
                and token != '(' and token != ')':
                    soaTokens.append(token)

            # Assign our soa values
            self.soa['ns'] = soaTokens[1]
            self.soa['email'] = soaTokens[2]
            self.soa['serial'] = soaTokens[3]
            self.soa['refresh'] = soaTokens[4]
            self.soa['retry'] = soaTokens[5]
            self.soa['expiry'] = soaTokens[6]
            self.soa['minttl'] = soaTokens[7]
            # Now read in all the Resource Records
            zf.seek(soaEnd)
            rrTmp = zf.read()
            zf.close() # Finished with the zone file now
            # Read Resource Records into the relevant lists
            rrLines = rrTmp.split('\n')
            for rr in rrLines:
                # Search for A record
                if re.search(r"\s+in\s+a\s+", rr, re.IGNORECASE):
                    self.a.append(rr)
                # Search for AAAA record
                elif re.search(r"\s+in\s+aaaa\s+", rr, re.IGNORECASE):
                    self.aaaa.append(rr)
                # Search for CNAME record    
                elif re.search(r"\s+in\s+cname\s+", rr, re.IGNORECASE):
                    self.cname.append(rr)
                # Search for HINFO record
                elif re.search(r"\s+in\s+hinfo\s+", rr, re.IGNORECASE):
                    self.hinfo.append(rr)
                # Search for MX record
                elif re.search(r"\s+in\s+mx\s+", rr, re.IGNORECASE):
                    self.mx.append(rr)
                # Search for NS record
                elif re.search(r"\s+in\s+ns\s+", rr, re.IGNORECASE):
                    self.ns.append(rr)
                # Search for PTR record
                elif re.search(r"\s+in\s+ptr\s+", rr, re.IGNORECASE):
                    self.ptr.append(rr)
                # Search for SRV record
                elif re.search(r"\s+in\s+srv\s+", rr, re.IGNORECASE):
                    self.srv.append(rr)
                # Search for TXT record
                elif re.search(r"\s+in\s+txt\s+", rr, re.IGNORECASE):
                    self.txt.append(rr)
        except IOError:
            return False
    
    def zone_exists(self, zoneFile=None):
        "Check to see if our zone file exists."
        
        if zoneFile == None:
          zoneFile = self.zone_file
        
        if(os.path.isfile(zoneFile)):
            result = True
        else:
            result = False
        
        return result
        
    def write_to_conf(self, conf_path):
        "Write entry to BIND config file for this zone."
        
        rgxp_str = '"' + self.name[0:-1] + '"'
        zone_rgxp = re.compile(rgxp_str)
        
        # Set a flag of whether we actually needed to write to our config.
        # Start it set as True.
        written = True
        try:
            f = open(conf_path, 'a+t')
            # we need to first check that this isn't in the conf file already
            for line in f:
                if zone_rgxp.search(line):
                    # we have found filename in this line, set 'written' to False
                    written = False
                    break
                else:
                    written = True
            if written == True:
                f.write('\n')
                f.write(self.conf_entry)
                f.write('\n')
            f.close
        except IOError:
            raise IOError
        
        return written
    
    def write_zone_file(self, uid, gid):
      	"Write current zone contents to zone file."
      	
      	file_contents = self.getSoa()
        # output the NS records to file_contents
        if len(self.ns) > 0:
            for ns in self.ns:
                file_contents = file_contents + '\n' + ns
        # output the A records to file_contents
        if len(self.a) > 0:
            for a in self.a:
                file_contents = file_contents + '\n' + a
        # output the AAAA records to file_contents
        if len(self.aaaa) > 0:
            for aaaa in self.aaaa:
                file_contents = file_contents + '\n' + aaaa
        # output the CNAME records to file_contents
        if len(self.cname) > 0:
            for cname in self.cname:
                file_contents = file_contents + '\n' + cname
        # output the MX records to file_contents
        if len(self.mx) > 0:
            for mx in self.mx:
                file_contents = file_contents + "\n" + mx
        # output the PTR records to file_contents
        if len(self.ptr) > 0:
            for ptr in self.ptr:
                file_contents = file_contents + "\n" + ptr
        # output the SRV records to file_contents
        if len(self.srv) > 0:
            for srv in self.srv:
                file_contents = file_contents + "\n" + srv
        # output the TXT records to file_contents        
        if len(self.txt) > 0:
            for txt in self.txt:
                file_contents = file_contents + "\n" + txt
                
      	try:
            f = open(self.zone_file, 'w+t')
            f.write(file_contents)
            f.write('\n')
            f.close
        except IOError:
            raise IOError
        
        # chown the zone file
        try:
            os.chown(self.zone_file, uid, gid)
        except IOError:
            raise IOError
    
    def add_default_records(self, record_type, ip=None):
        # Look for Default.* lists to see what defaults should be set up.
        # These are all pulled in from our 'recordtemplates' import
        if record_type.upper() == 'A' and len(Defaults.A) > 0:
            # create an A record object for each default
            for a in Defaults.A:
                a_record = A()
                a_record.src = a
                if ip == None:
                  raise Exception('No IP address supplied for A record.')
                else:
                  a_record.tgt = ip
                # add this A record to our zone's list
                self.a.append(a_record.out())
        
        if record_type.upper() == 'AAAA' and len(Defaults.AAAA) > 0:
            # create an AAAA record object for each default
            for aaaa in Defaults.AAAA:
                aaaa_record = AAAA()
                aaaa_record.src = aaaa
                if ip == None:
                  raise Exception('No IP address supplied for AAAA record.')
                else:
                  aaaa_record.tgt = ip
                # add this A record to our zone's list
                self.aaaa.append(aaaa_record.out())

        if record_type.upper() == 'CNAME' and len(Defaults.CNAME) > 0:
            # create a CNAME record object for each default
            for cname in Defaults.CNAME:
                cname_record = CNAME()
                # Defaults.CNAME contains lists, each list has alias in [0]
                # and target in [1]
                cname_record.src = cname[0]
                cname_record.tgt = cname[1]
                # add this CNAME record to our zone's list
                self.cname.append(cname_record.out())
        
        if record_type.upper() == 'MX' and len(Defaults.MX) > 0:
            # create an MX record for each default
            for mx in Defaults.MX:
                mx_record = MX()
                # Defaults.MX contains lists, each has src in [0],
                # preference in [1] and tgt in [2]
                mx_record.src = mx[0]
                mx_record.pref = mx[1]
                mx_record.tgt = mx[2]
                # add this MX record to our zone's list
                self.mx.append(mx_record.out())
        
        if record_type.upper() == 'NS' and len(Defaults.NS) > 0:
            # create an NS record for each default
            for ns in Defaults.NS:
                ns_record = NS()
                # Defaults.NS contains lists, each has a src in [0] and
                # tgt in [1]
                ns_record.src = ns[0]
                ns_record.tgt = ns[1]
                # add this NS record to our zone's list
                self.ns.append(ns_record.out())
                
        if record_type.upper() == 'TXT' and len(Defaults.TXT) > 0:
            # create an TXT record for each default
            for txt in Defaults.TXT:
                txt_record = TXT()
                # Defaults.TXT contains lists, each has a src in [0] and
                # tgt in [1]
                txt_record.src = txt[0]
                txt_record.tgt = txt[1]
                # add this NS record to our zone's list
                self.txt.append(txt_record.out())
        

class ResourceRecord:
    """A basic resource record superclass. Attributes:
    [ src ttl rrclass rrtype tgt comment ]
    'src' is the terminology for the hostname, the source.
    'tgt' is the terminology for the target address.
    """

    spaceReplace = '_'  # this can be used to replace spaces when necessary.

    def __init__( self ):
        # set up some empty strings
        self.src = ''
        self.ttl = ''
        self.rrclass = 'IN'  # this will always be INternet for my purposes
        self.rrtype = ''
        self.tgt = ''
        self.comment = ''


    def getSrc( self ):
        "Output the source in valid zone record format."

        return self.src.lower()


    def getTtl( self ):
        "Output the TTL in valid zone record format."
        # needs to take care of H, D, W & M?
        return self.ttl


    def getRrclass( self ):
        "Output the resource record class."
        
        return self.rrclass.upper()


    def getRrtype( self ):
        "Output the resource record type."
        
        return self.rrtype.upper()


    def getTgt( self ):
        "Output the resource record target."
        
        return self.tgt.lower()


    def getComment( self ):
        "Output any comments for this resource record."
        
        if self.comment == '':
            commStr = ''
        elif self.comment[0] != ';':
            commStr = '; ' + self.comment
        else:
            commStr = self.comment
        
        return commStr


    def setSrc( self, srcStr, fqdn=0 ):
        """Set the source attribute (src) for this resource record. Optional arg, 'fqdn'
        lets us know if we have been given a fully qualified domain name.
        """
        
        # if we have been told we have a fqdn, append a '.' if necessary
        if fqdn != 0:
            if srcStr[-1] != '.':
                self.src = srcStr.lower() + '.'
            else:
                self.src = srcStr.lower()
        else:
            self.src = srcStr.lower()


    def setTgt( self, tgtStr, fqdn=0 ):
        """Set the target attribute (tgt) for this resource record. Optional
    argument, 'fqdn' lets us know if we have been given a fully qualified domain name.
    """
        
        # if we have been told we have a fqdn, append a '.' if necessary
        if fqdn != 0:
            if tgtStr[-1] != '.':
                self.tgt = tgtStr + '.'
            else:
                self.tgt = tgtStr
        else:
            self.tgt = tgtStr

    def setRrclass( self, rrclassString ):
        "Set the rrclass attribute."
        
        self.rrclass = rrclassString.upper()

    def setRrtype( self, rrtypeString ):
        "Set the rrtype attribute."
        
        self.rrtype = rrtypeString.upper()

    def setTtl( self, ttlString ):
        "Set the ttl attribute."
        
        self.ttl = ttlString

    def setComment(self, commentString):
        "Set the comment attribute."
        
        if commentString == '':
            self.comment = ''
        elif commentString[0] != ';':
            self.comment = '; ' + commentString
        else:
            self.comment = commentString

    def out( self ):
        "Returns the attributes as a resource record formatted string."
        
        rrstring = self.getSrc() + '\t' + self.getTtl() + '\t' + self.getRrclass() + ' ' + self.getRrtype() + '\t' + self.getTgt() + ' ' + self.getComment()
        
        return rrstring

## END ResourceRecord class

class A(ResourceRecord):
    "'A' resource record definition. attributes: [ src ttl rrclass rrtype='A' tgt ]"
    
    def __init__( self ):
        ResourceRecord.__init__( self )
        self.rrtype = 'A'
    
    def getSrc( self ):
        "Output the resource record source in valid BIND format."
        # we need to make sure we put a '.' on the end of our 'src', if it isn't '@' - no easy way to test for just a host name, so we must always have a full domain
        if self.src != '@' and  self.src != '' and self.src[-1] != '.':
            src = self.src + '.'
        else:
            src = self.src
    
        return ResourceRecord.getSrc( self )
    
    def setTgt( self, tgtStr ):
        "Set the target attribute (tgt) for this resource record. Function modified for A record to test if this is an IP address."
        
        # need to check that we have 4 '.' characters and need to check that the strings between each '.' are numeric
        dotNum = tgtStr.count( '.' )
        octets = tgtStr.split( '.' )
        if dotNum != 3:
            # raise an exception
            raise Exception("Invalid A.tgt")
        for octet in octets:
            if not octet.isdigit():
                # raise an exception
                raise Exception("Invalid A.tgt")
        
        # if no exceptions were raised above, set the tgt
        self.tgt = tgtStr

## END class A

class AAAA(ResourceRecord):
    "'AAAA' IPv6 resource record definition. attributes [ src ttl rrclass rrtype='AAAA' tgt ]"

    def __init__( self ):
        ResourceRecord.__init__( self )
        self.rrtype = 'AAAA'

    def getSrc( self ):
        "Output the resource record source in valid BIND format."
        # we need to make sure we put a '.' on the end of our 'src', if it isn't '@' - no easy way to test for just a host name, so we must always have a full domain
        if self.src != '@' and  self.src != '' and self.src[-1] != '.':
            src = self.src + '.'
        else:
            src = self.src
        return ResourceRecord.getSrc( self )

    def setTgt( self, tgtStr ):
        "Set the target attribute (tgt) for this resource record (an IPv6 address). Function modified for AAAA record to test for valid IPv6 address."
        if self.check_ipv6( tgtStr ) == False:
            raise Exception("Invalid AAAA.tgt")
        # If no exception raised, set the tgt
        self.tgt = tgtStr

    def check_ipv6( self, tgtStr ):
        try:
            socket.inet_pton( socket.AF_INET6, tgtStr )
            return True
        except:
            return False

## END class AAAA

class CNAME(ResourceRecord):
    "'CNAME' resource record definition. attributes: [ src ttl rrclass rrtype='CNAME' tgt ]"
    
    def __init__( self ):
        ResourceRecord.__init__( self )
        self.rrtype = 'CNAME'
    
## END class CNAME

class HINFO(ResourceRecord):
    "'HINFO' resource record definition. attributes: [ src ttl rrclass rrtype='HINFO' cpu os ]"
    
    def __init__(self):
        ResourceRecord.__init__(self)
        self.rrtype = 'HINFO'
        # hinfo records don't have target, but 'cpu' & 'os'
        self.cpu = ''
        self.os = ''
    
    def getCpu(self):
        "Output the HINFO CPU information."
        
        return self.cpu.replace(' ', self.spaceReplace )
    
    def getOs( self ):
        "Output the HINFO OS information."
        
        return self.os.replace(' ', self.spaceReplace)
        
    def setCpu(self, cpuStr):
        "Set the cpu attribute for this record."
        
        self.cpu = cpuStr.replace(' ', self.spaceReplace)
        
    def setOs(self, osStr):
        "Set the os attribute for this record."
        
        self.os = osStr.replace(' ', self.spaceReplace)
    
    def out(self):
        "Returns the resource record as a string. Modified for HINFO, as tgt does not apply."
        
        rrstring = self.getSrc() + ' ' + self.getTtl() + '\t' + self.getRrclass() + ' ' + self.getRrtype() + sp
        rrstring = rrstring + self.getCpu + ' ' + self.getOs() + ' ' + self.getComment()
                    
        return rrstring

## END class HINFO

class MX ( ResourceRecord ):
    "'MX' resource record definition. attributes: [ src ttl rrclass rrtype='MX' pref tgt ]"
    
    def __init__( self ):
        ResourceRecord.__init__( self )
        self.rrtype = 'MX'
        self.pref = '10' # default to a preference of 10
    
    def getPref( self ):
        "Return the MX preference."
        
        return self.pref
    
    def setPref( self, prefStr ):
        "Set the pref attribute of the MX resource record."
        
        if not prefStr.isdigit():
            # raise an exception
            raise Exception("Invalid MX.pref")
        else:
            self.pref = prefStr

    def out( self ):
        "Returns the resource record as a string. Modified for MX, as pref also needs to be displayed."
        
        rrstring = self.getSrc() + '\t' + self.getTtl() + '\t' + self.getRrclass() + ' ' + self.getRrtype() + '\t'
        rrstring = rrstring + self.getPref() + ' ' + self.getTgt() + ' ' + self.getComment()
        
        return rrstring

## END class MX

class NS ( ResourceRecord ):
    "'NS' resource record definition. attributes: [src ttl rrclass rrtype='NS' target]"
    
    def __init__( self ):
        ResourceRecord.__init__( self )
        self.rrtype = 'NS'

## END class NS

class PTR ( ResourceRecord ):
    "'PTR' resource record definition. attributes: [ src ttl rrclass rrtype='PTR' target ]"
    
    def __init__( self ):
        ResourceRecord.__init__( self )
        self.rrtype = 'PTR'
    
    # JUST MAKE THIS A STANDARD RESOURCE RECORD, DON'T DO ANYTHING FANCY
    #def setSrc( self, srcStr ):
    #    "Set the src attribute for this resource record. Modified for PTR to format a given IP address correctly."
    #    
    #    # need to check that we have 4 '.' characters and need to check that the strings between each '.' are numeric
    #    dotNum = srcStr.count( '.' )
    #    octets = srcStr.split( '.' )
    #    if dotNum != 3:
    #        # raise an exception
    #        raise "Invalid PTR.src", srcStr
    #    for octet in octets:
    #        if not octet.isdigit():
    #            # raise an exception
    #            raise "Invalid PTR.src", srcStr
    #    # we got a proper IP, now convert to in-addr.arpa format
    #    self.src = octets[3] + '.' + octets[2] + '.' + octets[1] + '.' + octets[0] + '.in-addr.arpa.'
## END class PTR

class SRV ( ResourceRecord ):
    "'SRV' resource record definition. attributes: [src ttl rrclass rrtype='SRV' priority weight port target]"
    
    def __init__(self):
        ResourceRecord.__init__(self)
        self.rrtype = 'SRV'
        self.priority = 0
        self.weight = 0
        self.port = ''

    def getPriority(self):
        "Return the priority attribute of the SRV resource record."
        return self.priority
    
    def setPriority(self, priority):
        "Set the priority attribute of the SRV resource record."
        if not priority.isdigit():
            raise Exception("Invalid SRV.priority")
        else:
            self.priority = priority
    
    def getWeight(self):
        "Return the weight attribute of the SRV resource record."
        return self.weight
    
    def setWeight(self, weight):
        "Set the weight attribute of the SRV resource record."
        if not weight.isdigit():
            raise Exception("Invalid SRV.weight")
        else:
            self.weight = weight
    
    def getPort(self):
        "Return the port attribute of the SRV resource record."
        return self.port

    def setPort(self, port):
        "Set the port attribute of the SRV resource record."
        if not port.isdigit():
            raise Exception("Invalid SRV.port")
        else:
            self.port = port

    def out(self):
        "Returns the SRV resource record as a string."
        rrstring = self.getSrc() + '\t' + self.getTtl() + '\t' + self.getRrclass() + ' ' + self.getRrtype() + '\t'
        rrstring = rrstring + self.getPriority() + ' ' + self.getWeight() + ' ' + self.getPort() + ''
        rrstring = rrstring + self.getTgt() + ' ' + self.getComment()
        return rrstring

## END class SRV

class TXT ( ResourceRecord ):
    "'TXT' resource record definition. attributes: [src ttl rrclass rrtype='TXT' txt-strings]"
    def __init__(self):
        ResourceRecord.__init__(self)
        self.rrtype = 'TXT'
    
    def getTgt(self):
        "This getTgt function ensures that the tgt (txt-strings) value is returned in quotes"
        txtString = '"%s"' % self.tgt
        
        return txtString
        
## END class TXT

#class WKS ( ResourceRecord ):
## END class WKS
