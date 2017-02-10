
# Author: Michael Everett, F5 Networks
# Description: Simple script to detect Client SSL Profiles vulnerable to
#              ticketbleed vulnerability (CVE-2016-9244), and optionally
#              mitigate.
# Requirements: F5 Python SDK
# Date: 2/9/2017

from f5.bigip import ManagementRoot
from icontrol.exceptions import iControlUnexpectedHTTPError
import argparse
import requests
import json
import logging

# Logging
logger = logging.getLogger(__name__)
filehdlr = logging.FileHandler('ticketbleed_detect.log')
stdhdlr = logging.StreamHandler()
#formatter = logging.Formatter(' %(asctime)s %(message)s')
#filehdlr.setFormatter(formatter)
#stdhdlr.setFormatter(formatter)
logger.addHandler(filehdlr)
logger.addHandler(stdhdlr)
logger.setLevel(logging.INFO)

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


def load_bigip(f5_host,f5_user,f5_pass):

    try:
        bigip = ManagementRoot(f5_host, f5_user, f5_pass)
    except iControlUnexpectedHTTPError, e:
        logger.info("Error Connecting to {0}:{1}".format(f5_host,e))
        return None

    return bigip

#def is_version_vuln(bigip):
    # checks if the version of bigip is vulernable

def get_affected_profs(bigip):
    affected_profs=[]
    cssl_profs = bigip.tm.ltm.profile.client_ssls.get_collection()

    for cssl_prof in cssl_profs:
        if cssl_prof.sessionTicket == "enabled":
            affected_profs.append(cssl_prof.name)

    return affected_profs


def get_affected_vs(bigip, affected_profs):
    affected_vs_s= []
    vslist = bigip.tm.ltm.virtuals.get_collection()

    for vs in vslist:
        vs_profs = vs.profiles_s.get_collection(requests_params={'params':
                                                '$select=name'})

        vs_profs_l = []
        for vs_prof in vs_profs:
            vs_profs_l.append(vs_prof['name'])

        matched = list(set(vs_profs_l).intersection(affected_profs))

        if len(matched) > 0:
            affected_vs = (vs.name, matched)
            affected_vs_s.append(affected_vs)

    return affected_vs_s


def modify_cssl_profs(bigip, affected_profs):
    '''Set the SessionTickets to disabled for affected profiles'''
    logger.info("Disabling Session Tickets:")
    for prof in affected_profs:
        cssl_prof = bigip.tm.ltm.profile.client_ssls.client_ssl.load(name=prof, partition='Common')
        logger.info("--> Disabled sessionTickets, Profile: {0}".format(cssl_prof.name))
        cssl_prof.sessionTicket = 'disabled'
        cssl_prof.update()


def log_it(bigip, affected_profs, affected_vs):
    ''' Log profiles and virtuals affected for each bigip'''
    logger.info("")
    logger.info("---------------------------------------------------------------")
    logger.info("BIG-IP Hostname: {0}, Version:{1}".format(bigip.hostname, bigip.tmos_version))
    logger.info("---------------------------------------------------------------")
    logger.info("Client SSL Profiles with TLS Session Tickets Enabled:")
    for prof in affected_profs:
        logger.info("-->{0}".format(prof))
    logger.info("")
    logger.info("Virtual Servers w/ affected Client SSL Profiles:")
    for vs in affected_vs:
        for p in vs[1]:
            logger.info("-->VS:{0}, Profile: {1}".format(vs[0],p))
    logger.info("")


def main():
    usage = "Usage: %prog [options]"
    parser = argparse.ArgumentParser(usage)
    parser.add_argument('-c', '--bigip_creds',
                        help="Name of file containing F5 BIG-IP systems, and credentials",
                        dest='creds', default='bigip_creds.json')
    parser.add_argument('-m', '--mitigate', action='store_true', default='False',
                        dest='mitigate', help="If set, script will modify config")

    options = parser.parse_args()

    if options.creds is None:
        print "Please provide input file with bigip systems to check"
        parser.print_help()
        exit(-1)

    with open(options.creds, 'r') as f:
        bigip_creds = json.load(f)
    f.close()


    for bigip_cred in bigip_creds:

        bigip = load_bigip(bigip_cred, bigip_creds[bigip_cred]['username'],
                bigip_creds[bigip_cred]['password'])

        if not bigip is None:
            affected_profs = get_affected_profs(bigip)
            affected_vs = get_affected_vs(bigip, affected_profs)
            log_it(bigip, affected_profs, affected_vs)

            if options.mitigate == True and len(affected_profs) > 0:
                modify_cssl_profs(bigip, affected_profs)

if __name__ == '__main__':
    main()

