import json
from jsonrpclib import Server
import math
import sys
import tempfile
import time
from pathlib import Path
import urllib.request
import uuid

# Set to allow unverified Self-Signed cert for eAPI call
import ssl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

# helper to call the webservice and parse the response
def webApiGet(methodName, instanceName, clientRequestId):
    ws = 'https://endpoints.office.com'
    requestPath = ws + '/' + methodName + '/' + instanceName + '?clientRequestId=' + clientRequestId
    request = urllib.request.Request(requestPath)
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode())

def updateO365Endpoints():
    # path where client ID and latest version number will be stored
    datapath = Path(tempfile.gettempdir() + '/endpoints_clientid_latestversion.txt')
    # print(datapath)
    # fetch client ID and version if data exists; otherwise create new file
    if datapath.exists():
        with open(datapath, 'r') as fin:
            clientRequestId = fin.readline().strip()
            latestVersion = fin.readline().strip()
    else:
        clientRequestId = str(uuid.uuid4())
        latestVersion = '0000000000'
        with open(datapath, 'w') as fout:
            fout.write(clientRequestId + '\n' + latestVersion)
    # call version method to check the latest version, and pull new data if version number is different
    version = webApiGet('version', 'Worldwide', clientRequestId)
    if version['latest'] > latestVersion:
        print('New version of Office 365 worldwide commercial service instance endpoints detected')
        # write the new version number to the data file
        with open(datapath, 'w') as fout:
            fout.write(clientRequestId + '\n' + version['latest'])
        # invoke endpoints method to get the new data
        endpointSets = webApiGet('endpoints', 'Worldwide', clientRequestId)
        # filter results for Allow and Optimize endpoints, and transform these into tuples with port and category
        flatIps = []
        for endpointSet in endpointSets:
            if endpointSet['category'] in ('Optimize', 'Allow'):
                ips = endpointSet['ips'] if 'ips' in endpointSet else []
                # IPv4 strings have dots while IPv6 strings have colons
                ip4s = [ip for ip in ips if '.' in ip]
                if 'tcpPorts' in endpointSet:
                    protocol = 'tcp'
                    ports = endpointSet['tcpPorts']
                elif 'udpPorts' in endpointSet:
                    protocol = 'udp'
                    ports = endpointSet['udpPorts']
                else:
                    protocol = 'ip'
                    ports = ''
                flatIps.extend([{'prefix': ip, 'protocol': protocol, 'ports': ports} for ip in ip4s])
    else:
        print('Office 365 worldwide commercial service instance endpoints are up-to-date')
        sys.exit()
    return flatIps

def eapiSetup(ip):
    # Setup switch eAPI connection with hard-coded creds
    url_string = 'https://{}:{}@{}/command-api'.format('eapi-user', 'Arista123!', ip)
    switch_req = Server(url_string)
    return switch_req

def parseCurrentAcl(ip, aclName):
    # Pull currentl ACL config for PBR and parse to key info for comparison
    switchInstance = eapiSetup('10.100.100.1')
    currentAcl = switchInstance.runCmds(1, ['enable', 'show ip access-lists REDIRECT'])[1]['aclList'][0]['sequence']
    currentAces = []
    for aclEntry in currentAcl:
        subnet = aclEntry['ruleFilter']['destination']['ip']
        binMask = aclEntry['ruleFilter']['destination']['mask']
        if binMask == 4294967295:
            mask = '/32'
        else:
            mask = '/' + str(32 - int((math.log((4294967296 - binMask), 2))))
        prefix = subnet + mask
        if aclEntry['ruleFilter']['protocol'] == 0:
            protocol = 'ip'
        elif aclEntry['ruleFilter']['protocol'] == 6:
            protocol = 'tcp'
        elif aclEntry['ruleFilter']['protocol'] == 17:
            protocol = 'udp'
        ports = (',').join([str(i) for i in aclEntry['ruleFilter']['dstPort']['ports']])
        currentAces.extend([{'prefix': prefix, 'protocol': protocol, 'ports': ports}])
    return currentAces

def addAclEntries(ip, aclName, aclContent):
    # Send ACL Commands to switch via eAPI
    t = time.localtime()
    configSessionId = time.strftime('%Y%m%d%H%M%S', t)
    switchInstance = eapiSetup(ip)
    for newAce in aclContent:
        switchInstance.runCmds(1, ['enable', 'configure session ACL-UPDATE-' + configSessionId, 'ip access-list ' + aclName, newAce])
        print('New ACE created: ' + newAce)
    switchInstance.runCmds(1, ['enable', 'configure session ACL-UPDATE-' + configSessionId, 'ip access-list ' + aclName, 'resequence'])
    switchInstance.runCmds(1, ['enable', 'configure session ACL-UPDATE-{} commit'.format(configSessionId)])
    switchInstance.runCmds(1, ['enable', 'copy running-config startup-config'])

def removeAclEntries(ip, aclName, aclContent):
    # Send ACL Commands to switch via eAPI
    t = time.localtime()
    configSessionId = time.strftime('%Y%m%d%H%M%S', t)
    switchInstance = eapiSetup(ip)
    for oldAce in aclContent:
        switchInstance.runCmds(1, ['enable', 'configure session ACL-UPDATE-' + configSessionId, 'ip access-list ' + aclName, oldAce])
        print('Old ACE removed: ' + oldAce)
    switchInstance.runCmds(1, ['enable', 'configure session ACL-UPDATE-' + configSessionId, 'ip access-list ' + aclName, 'resequence'])
    switchInstance.runCmds(1, ['enable', 'configure session ACL-UPDATE-{} commit'.format(configSessionId)])
    switchInstance.runCmds(1, ['enable', 'copy running-config startup-config'])

def writeConfig(ip):
    # Save Config
    switchInstance = eapiSetup(ip)
    switchInstance.runCmds(1, ['enable', 'copy running-config startup-config'])

def main():
    # Check if 0365 Endpoints have updated and if so, return current valid endpoints
    currentO365Ips = updateO365Endpoints()
    # Pull out current ACE for comparison from switch with set IP and ACL named REDIRECT
    currentAclEntries = parseCurrentAcl('10.100.100.1', 'REDIRECT')
    newAclConfig = []
    for ace in currentO365Ips:
        if ace in currentAclEntries:
            print('ACE exists for {} {} ports {}...skipping entry'.format(ace['prefix'], ace['protocol'], ace['ports']))
        else:
            if ace['protocol'] == 'ip':
                newAclConfig.extend([('permit ip any {}').format(ace['prefix'])])
            else:
                combinedPorts = ace['ports'].replace(',', ' ')
                newAclConfig.extend([('permit {} any {} eq {}').format(ace['protocol'], ace['prefix'], combinedPorts)])
    if newAclConfig != []:
        addAclEntries('10.100.100.1', 'REDIRECT', newAclConfig)
    else:
        print('No new ACL entries needed.')
    # Parse out extraneous ACL entries for removal and delete
    oldAclEntries = []
    for ace in currentAclEntries:
        if ace in currentO365Ips:
            continue
        else:
            if ace['protocol'] == 'ip':
                oldAclEntries.extend([('no permit ip any {}').format(ace['prefix'])])
            else:
                combinedPorts = ace['ports'].replace(',', ' ')
                oldAclEntries.extend([('no permit {} any {} eq {}').format(ace['protocol'], ace['prefix'], combinedPorts)])
    if oldAclEntries != []:
        removeAclEntries('10.100.100.1', 'REDIRECT', oldAclEntries)
    else:
        print('No ACL entries require removal')
    if newAclConfig != [] and oldAclEntries != []:
        writeConfig('10.100.100.1')
        print('ACL Configuration updated and saved.')

if __name__ == '__main__':
    main()