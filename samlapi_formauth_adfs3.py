#!/usr/bin/python

import sys
import boto
#import boto.sts
#import boto.s3
#import boto.ec2
import requests
import getpass
import ConfigParser
import base64
import logging
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urlparse import urlparse, urlunparse
from pprint import pprint
from pypac import PACSession, get_pac
from requests.auth import HTTPProxyAuth
import os

#################################################################
#Setting nbcu proxy
#pac = get_pac(url='http://proxy.inbcu.com:7070/proxy.pac', allowed_content_types=['application/x-ns-proxy-autoconfig'])
#pac = get_pac(url='http://proxy.inbcu.com:7070/proxy.pac')
#session = PACSession(pac)
#session.get('https://google.com')
#print (session.get)
#proxy = 'http://proxy.inbcu.com:80'

#os.environ['http_proxy'] = proxy 
#os.environ['HTTP_PROXY'] = proxy
#os.environ['https_proxy'] = proxy
#os.environ['HTTPS_PROXY'] = proxy


##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-west-2'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = False

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://adfs.inbcu.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'

# Uncomment to enable low level debugging
#logging.basicConfig(level=logging.DEBUG)

##########################################################################

# Get the federated credentials from the user
#print "Username:",
print ("Username:")
username = raw_input()
password = getpass.getpass()
print ('')

# Initiate session handler
session = requests.Session()

# Programmatically get the SAML assertion`
# Opens the initial IdP url and follows all of the HTTP302 redirects, and
# gets the resulting login page
formresponse = session.get(idpentryurl, verify=sslverification)

# Debug the response if needed
print ("==================formresponse text start of line=========================")
print (formresponse.text)
print ("==================formresponse text end of line=========================")

# Capture the idpauthformsubmiturl, which is the final url after all the 302s
idpauthformsubmiturl = formresponse.url

print ("==================IDP Form Submit start of line=========================")
print (idpauthformsubmiturl)
print ("==================IDP Form Submit end of line=========================")

# Parse the response and extract all the necessary values
# in order to build a dictionary of all of the form values the IdP expects
formsoup = BeautifulSoup(formresponse.text.decode('utf8'))
payload = {}

for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    if "user" in name.lower():
        #Make an educated guess that this is the right field for the username
        payload[name] = username
    elif "email" in name.lower():
        #Some IdPs also label the username field as 'email'
        payload[name] = username
    elif "pass" in name.lower():
        #Make an educated guess that this is the right field for the password
        payload[name] = password
    else:
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

# Debug the parameter payload if needed
# Use with caution since this will print sensitive output to the screen
#print payload

# Some IdPs don't explicitly set a form action, but if one is set we should
# build the idpauthformsubmiturl by combining the scheme and hostname 
# from the entry url with the form action target
# If the action tag doesn't exist, we just stick with the 
# idpauthformsubmiturl above
for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
    action = inputtag.get('action')
    loginid = inputtag.get('id')
    if (action and loginid == "loginForm"):
        parsedurl = urlparse(idpentryurl)
        idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

# Performs the submission of the IdP login form with the above post data
response = session.post(
    idpauthformsubmiturl, data=payload, verify=sslverification)

# Debug the response if needed
#print (response.text)

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password

# Decode the response and extract the SAML assertion
soup = BeautifulSoup(response.text.decode('utf8'))
print ("=======Soup======")
print (soup)
assertion = ''

# Look for the SAMLResponse attribute of the input tag (determined by
# analyzing the debug print lines above)
for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        #Assertion Scrapper
        print ("==========================Assertion Value Start =========================")
        print(inputtag.get('value'))
        print ("==========================Assertion Value End=========================")
        assertion = inputtag.get('value')
        
# Better error handling is required for production use.
if (assertion == ''):
    #TODO: Insert valid error checking/handling
    print ('Response did not contain a valid SAML assertion')
    sys.exit(0)

# Debug only
#print(base64.b64decode(assertion))

# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print ("")
if len(awsroles) > 1:
    i = 0
    print ("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print ('[', i, ']: ', awsrole.split(',')[0])
        i += 1
    print ("Selection: "),
    selectedroleindex = raw_input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print ('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

print (role_arn)
print (principal_arn)
# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto.sts.connect_to_region(region)
token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = ConfigParser.RawConfigParser()
config.read(filename)

# Put the credentials into a saml specific section instead of clobbering
# the default credentials
if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)
config.set('saml', 'aws_access_key_id', token.credentials.access_key)
config.set('saml', 'aws_secret_access_key', token.credentials.secret_key)
config.set('saml', 'aws_session_token', token.credentials.session_token)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print ('\n\n----------------------------------------------------------------')
print ('Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.').format(filename)
print ('Note that it will expire at {0}.').format(token.credentials.expiration)
print ('After this time, you may safely rerun this script to refresh your access key pair.')
print ('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).')
print ('----------------------------------------------------------------\n\n')

# Use the AWS STS token to list all of the S3 buckets
s3conn = boto.s3.connect_to_region(region,
                     aws_access_key_id=token.credentials.access_key,
                     aws_secret_access_key=token.credentials.secret_key,
                     security_token=token.credentials.session_token)

buckets = s3conn.get_all_buckets()

print ('Simple API example listing all S3 buckets:')    
print(buckets)

# Use the AWS STS token to list all of the EC2 Instances
ec2conn = boto.ec2.connect_to_region(region,
                     aws_access_key_id=token.credentials.access_key,
                     aws_secret_access_key=token.credentials.secret_key,
                     security_token=token.credentials.session_token)
reservations = ec2conn.get_all_instances()
#pprint (reservations)

#for reservation in reservations:    
#    print region+':',reservation.instances

#for vol in ec2conn.get_all_volumes():
 #   print region+':',vol.id
