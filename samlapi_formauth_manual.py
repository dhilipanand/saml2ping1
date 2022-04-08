#!/usr/bin/python

import sys
import boto.sts
import boto.s3
import boto.ec2
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

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-west-2'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'



##########################################################################

# Enter Assertion from the Mozilla SAML Tracer
#print "Enter Role ARN:",
role_arn = "arn:aws:iam::201492179008:role/Administrator"

#print "Enter Principal ARN:",
principal_arn = "arn:aws:iam::201492179008:saml-provider/adfs.inbcu.com"

#print "Input Assertion:",
assertion = ''

# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto.sts.connect_to_region(region)
token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

# Print the Access & Secret Key 
print "AWS Access Key ID: ", token.credentials.access_key
print "AWS Secret Access Key", token.credentials.secret_key
print "AWS Session Token", token.credentials.session_token