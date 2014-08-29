#!/usr/bin/env python

import argparse
import base64
import configparser
import colorama
from colorama import Fore, Style
import datetime
import getpass
import hashlib
import hmac
import time
import json
import keyring
import os
import requests
import urllib.parse
import sys

STASH_CONTAINER_NAME = "stash_container"

def print_error(error):
    print (Style.BRIGHT + Fore.RED + "ERROR: " +
           Fore.GREEN + error +
           Style.NORMAL + Fore.RESET)

def config_dir():
    pass

def get_config_filename():
    homedir = os.getenv('HOME')
    configfile = os.path.join(homedir, '.stash')
    return configfile

def read_config():
    configfile = get_config_filename()

    config = configparser.RawConfigParser()
    config.read(configfile)

    username = config.get('storage', 'username')
    region = config.get('storage', 'region')
    apikey = keyring.get_password('stash', username)

    return username, apikey, region

def write_config(username, apikey, region, storageurl):

    config = configparser.RawConfigParser()

    config.add_section("storage")
    config.set("storage", "username", username)
    config.set("storage", "region", region)

    filename = get_config_filename()

    with open(filename, 'w') as configfile:
        config.write(configfile)

    # todo: store the token in keyring as cache?
    keyring.set_password('stash', username, apikey)

def parse_iso_8601(date):
    formatstr = "%Y-%m-%dT%H:%M:%S.%fZ"
    return datetime.datetime.strptime(date, formatstr)

def do_auth(username, apikey, use_cache=True):

    if use_cache:
        token_expires = keyring.get_password('stash', 'tokenexpires')
        token = keyring.get_password('stash', 'token')
        ep_text = keyring.get_password('stash', 'endpoints')

        if token_expires and token and ep_text:
            expires_date = parse_iso_8601(token_expires)
            now = datetime.datetime.utcnow()

            if now < expires_date:
                # we should be good, just re-use the
                # token
                return token, json.loads(ep_text)

    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    hdrs = {
        'Content-Type': 'application/json'
    }

    body = {
        "auth":
        {
            "RAX-KSKEY:apiKeyCredentials":
            {
                "username": username,
                "apiKey": apikey
            }
        }
    }

    resp = requests.post(url, data=json.dumps(body), headers=hdrs)

    if resp.ok:
        output = resp.json()

        token = output['access']['token']['id']
        expires_text = output['access']['token']['expires']

        # Cache the token and expiry in the keyring
        keyring.set_password('stash', 'tokenexpires', expires_text)
        keyring.set_password('stash', 'token', token)

        # now find the block storage endpoints
        sc = output['access']['serviceCatalog']


        # Find all of the object store endpoints
        os_endpoints = [service['endpoints'] for
            service in sc if service['type'] == 'object-store'][0]

        ep_text = json.dumps(os_endpoints)
        keyring.set_password('stash', 'endpoints', ep_text)

        return token, os_endpoints

    elif resp.status_code == 401:
        print (Fore.RED, "Invalid username/API key?")
        return False

def has_stash_container(token, url):

    url = url + '/' + STASH_CONTAINER_NAME

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.head(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to check for stash container")

def create_stash_container(token, url):

    url = url + '/' + STASH_CONTAINER_NAME

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.put(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to create stash container")

def file_exists(token, url, filename):
    """Shares the specified file"""

    print ("Sharing '{0}' from your stash".format(filename))

    url = url + '/' + STASH_CONTAINER_NAME
    url = url + '/' + encode_filename(filename)

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.head(url, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to stash a file")

def create_temp_url(key, url, filename, duration):

    path = urllib.parse.urlparse(url).path

    method = "GET"
    object_path = path + "/" + STASH_CONTAINER_NAME + "/" + encode_filename(filename)

    # duration is expressed in hours
    expires = int(time.time() + duration*60)

    hmac_body = "{0}\n{1}\n{2}".format(
        method, expires, object_path)

    sig = hmac.new(bytes(key, 'utf-8'), bytes(hmac_body, 'utf-8'),
        hashlib.sha1).hexdigest()

    return "{0}/{1}/{2}?temp_url_sig={3}&temp_url_expires={4}&filename={5}".format(
        url, STASH_CONTAINER_NAME, encode_filename(filename), sig, expires,
        urllib.parse.quote_plus(filename))

def read_temp_url_key(token, url):

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.head(url, headers=hdrs)

    if output.ok:
        return output.headers.get('X-Account-Meta-Temp-Url-Key')

def do_share_file(token, url, filename, duration):
    if not file_exists(token, url, filename):
        print_error("File '{0}' not found".format(filename))
        return

    key = read_temp_url_key(token, url)

    if not key:
        print_error("""You must set a temp url key to enable sharing""")
        return

    temp_url = create_temp_url(key, url, filename, duration)

    print ("Share this URL: ")
    print (temp_url)

def do_configure(identityhost):
    username = input("Username: ")
    apikey = input("API Key: ")

    token, endpoints = do_auth(username, apikey, use_cache=False)

    # check each cloud files endpoints for a stash container.
    # At this point, the user is only allowed to have one
    cont_found = False
    region = None
    url = None

    print ("Checking all regions for an existing stash container...")
    for endpoint in endpoints:
        region = endpoint['region']
        publicurl = endpoint['publicURL']

        cont_found = has_stash_container(token, publicurl)

        if cont_found:
            print ("Found a stash container in {0}".format(region))
            break

    if not cont_found:
        print ("No existing stash containers found, so let's create one.")

        regions = [ep['region'] for ep in endpoints]

        while True:
            region = input("Enter a region to use [empty to list]: ")

            if not region.strip():
                for region in regions:
                    print (region)
                continue

            region = region.upper()

            if region not in regions:
                print ("Region not found:", region)
            else:
                # We found a valid region, look up the URL
                publicurl = [ep for ep in endpoints
                    if ep['region'] == region][0]['publicURL']

                break

    if not cont_found:
        create_stash_container(token, publicurl)

    assert publicurl is not None
    assert region is not None

    # Now let's store that stuff in the config
    write_config(username, apikey, region, publicurl)

def get_default_filename():
    pass

def do_fetch_file(token, url, filename, outfile):
    """Fetches the specified object"""

    outfile = outfile or filename

    print ("Fetching '{0}' -> '{1}'".format(filename, outfile))

    url = url + '/' + STASH_CONTAINER_NAME
    url = url + '/' + encode_filename(filename)

    hdrs = {
        'X-Auth-Token': token
    }

    with open(outfile, 'wb') as of:
        output = requests.get(url, stream=True, headers=hdrs)

        length = int(output.headers['content-length'])
        bytes_completed = 0
        prev_completed = None

        for chunk in output.iter_content(chunk_size=4096):
            if chunk:
                bytes_completed += len(chunk)


                of.write(chunk)

                pct_complete = ((1000 * bytes_completed) // length) / 10

                if pct_complete == prev_completed:
                    continue

                prev_completed = pct_complete

                pct = int(79 * bytes_completed / length)

                sys.stdout.write("\r[%s%s]" % ('=' * pct, ' ' * (79-pct)) )
                sys.stdout.write(' ')
                sys.stdout.write(str(pct_complete))
                sys.stdout.write("%")
                sys.stdout.flush()

        print()

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to stash a file")

    print ("Finished stashing...")

def do_upload_file(token, url, filename):
    """Stashes the specified local file"""

    print ("Stashing your item...")

    _, fname = os.path.split(filename)

    url = url + '/' + STASH_CONTAINER_NAME
    url = url + '/' + encode_filename(fname)

    hdrs = {
        'X-Auth-Token': token
    }

    with open(filename, 'rb') as infile:
        output = requests.put(url, data=infile, headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to stash a file")

    print ("Finished stashing...")

def encode_filename(filename):
    b64 = base64.b64encode(bytes(filename, 'utf-8'))
    return b64.decode('utf-8')

def decode_filename(encoded):
    b = bytes(encoded, 'utf-8')
    decoded_bytes = base64.b64decode(b)
    return decoded_bytes.decode('utf-8')

def do_delete_object(token, url, filename):
    """Stashes the specified local file"""
    print ("Deleting file '{0}'".format(filename))

    _, fname = os.path.split(filename)

    url = url + '/' + STASH_CONTAINER_NAME
    url = url + '/' + encode_filename(fname)

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.delete(url, headers=hdrs)

    if output.status_code == 404:
        print_error ("File not stashed: " + filename)
        return False
    elif output.ok:
        print ("File '{0}' was deleted from stash".format(filename))
        return True
    else:  # something else happened
        raise Exception("Other error trying to delete file")

    print ("Finished stashing...")


def do_list_stashes(token, url):

    url = url + '/' + STASH_CONTAINER_NAME

    hdrs = {
        'X-Auth-Token': token
    }

    params = {
        "format": "json"
    }

    output = requests.get(url, headers=hdrs, params=params)

    if output.status_code == 404:
        return False
    elif output.ok:

        print (Style.BRIGHT)

        body = output.json()

        print ("==============")
        print ("Stashed Items:")
        print ("==============")

        for x in range(0, len(body)):
            item = body[x]

            number = "{0}[{1}]{2}".format(
                Fore.GREEN, x, Fore.RESET
            )

            filename = decode_filename(item['name'])
            size = item['bytes']

            size = Fore.CYAN + " {" + str(size) + " bytes}"

            print (number, Fore.BLUE + filename + size + Fore.RESET)
    else:
        raise Exception("Unable to list stash container contents")

def main():

    # parse some arguments so that we
    # can determine which way to go.
    parser = argparse.ArgumentParser(
        prog = "stash",
        description = """
            Quickly and easily share
            and store files using Open Stack's
            Swift
        """,
        epilog = """
            Written by Jamie Painter, Rackspace Hosting
        """
    )

    parser.add_argument("-k", "--identity", dest="identityhost",
                        help="Override the default Keystone hostname")

    parser.add_argument("-l", "--list", dest="list", default=False,
                        nargs="?",
                        help="List stashed files")

    parser.add_argument("-f", "--fetch", dest="fetch",
                        help="Fetch the specified file")

    parser.add_argument("-d", "--delete", dest="delete",
                        help="Delete the specified file")

    parser.add_argument("-o", "--output", dest="outfile",
                        help="When fetching, write to this file")

    parser.add_argument("-s", "--share", dest="share",
                        help="Share this file via temporary URL")

    parser.add_argument("-t", "--duration", dest="duration",
                        default=24,
                        help="Duration (in hours) to share a file.")

    parser.add_argument("-c", "--configure", dest="configure",
                        nargs="?",
                        default=False,
                        help="Configure stash")

    parser.add_argument("-i", "--info", dest="info",
                        nargs="?",
                        help = "Show configuration information")

    parser.add_argument("-n", "--no-auth-cache", dest="authcache",
                        default=True, nargs="?",
                        help="Don't use auth cache for this request")

    parser.add_argument("filename", nargs="?",
                        help="The file to stash")

    args = parser.parse_args()

    if args.configure is not False:
        do_configure(args.identityhost)
        exit(0)

    username, apikey, region = read_config()
    token, endpoints = do_auth(username, apikey, args.authcache)

    # find the storage url we care about
    storageurl = [ep for ep in endpoints
        if ep['region'] == region][0]['publicURL']

    # Should we list?
    if args.list is not False:
        do_list_stashes(token, storageurl)
        exit(0)

    if args.fetch:
        do_fetch_file(token, storageurl, args.fetch, args.outfile)
        exit(0)

    if args.delete:
        do_delete_object(token, storageurl, args.delete)
        exit(0)

    if args.share:
        do_share_file(token, storageurl, args.share, args.duration)
        exit(0)

    if not args.filename:
        print_error("Give me something to stash.")

    else:
        # legit commands, mapped to handle functions
        do_upload_file(token, storageurl, args.filename)

    print (Style.NORMAL)

if __name__ == '__main__':
    main()
