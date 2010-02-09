# recordtemplates.py
# PLEASE NOTE THAT THIS IS A PYTHON FILE - DO NOT CHANGE THE TABBING!

class Defaults:
    # Modify these lists to set up a template of resource records that
    # should be set up when a new zone is added. Any strings you provide
    # in here should be valid zone data (e.g. fully qualified domains
    # should end with '.', host names should not).
    
    # Insert strings for A records here. Each entry will
    # be resolved to the IP provided with the zone.
    A = ['@', 'mail', 'ftp', 'www']
    
    # Insert lists of strings here.
    # e.g: [['ftp', 'www'], ['smtp', 'mail']]
    CNAME = []
    
    # Insert lists of strings here. Each list should be of the
    # format ['domain', 'preference', 'mailserver']
    # e.g: [['@', '10', 'mx1'], ['@', '20', 'mx2']]
    MX = [['@', '10', 'mail']]
    
    # Insert lists of strings for NS records here.
    # e.g.: ['@', 'ns1.example.com']
    NS = [['@', 'ns1.example.com.'],
          ['@', 'ns2.example.com.']]
    
    # Insert lists of strings for TXT records here. Each
    # list should be ['domain', 'text']. For example, an
    # SPF text entry record could be: ['@', 'v=spf1 a mx ~all']
    TXT = [['@', 'v=spf1 a mx ~all']]
