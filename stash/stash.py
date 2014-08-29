#!/usr/bin/env python

import argparse
import colorama
from colorama import Fore, Style
import datetime
import getpass
import time
import json
import keyring
import os
import requests
import sys

import stash.config
import stash.util
import stash.eyeoh

def do_share_file(token, url, filename, duration):
    if not stash.eyeoh.file_exists(token, url, filename):
        stash.util.print_error("File '{0}' not found".format(filename))
        return

    key = stash.eyeoh.read_temp_url_key(token, url)

    if not key:
        stash.util.print_error("""You must set a Temp URL key first.""")
        return

    temp_url = stash.util.create_temp_url(key, url, filename, duration)

    print ("Share this URL: ")
    print (temp_url)

def do_configure(identityhost):
    username = input("Username: ")
    apikey = input("API Key: ")

    token, endpoints = stash.eyeoh.do_auth(username,
        apikey, use_cache=False)

    # check each cloud files endpoints for a stash container.
    # At this point, the user is only allowed to have one
    cont_found = False
    region = None
    url = None

    print ("Checking all regions for an existing stash container...")
    for endpoint in endpoints:
        region = endpoint['region']
        publicurl = endpoint['publicURL']

        cont_found = stash.eyeoh.has_stash_container(token, publicurl)

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
        stash.eyeoh.create_stash_container(token, publicurl)

    assert publicurl is not None
    assert region is not None

    # Now let's store that stuff in the config
    stash.config.write_config(username, apikey, region, publicurl)

def do_fetch_file(token, url, filename, outfile):
    """Fetches the specified object"""

    outfile = outfile or filename

    print ("Fetching '{0}' -> '{1}'".format(filename, outfile))

    url = url + '/' + stash.eyeoh.STASH_CONTAINER_NAME
    url = url + '/' + stash.util.encode_filename(filename)

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


    _, fname = os.path.split(filename)

    url = url + '/' + stash.eyeoh.STASH_CONTAINER_NAME
    url = url + '/' + stash.util.encode_filename(fname)

    hdrs = {
        'X-Auth-Token': token
    }

    it = stash.eyeoh.upload_in_chunks(filename, 1024)

    output = requests.put(url, data=stash.eyeoh.IterableToFileAdapter(it),
        headers=hdrs)

    if output.status_code == 404:
        return False
    elif output.ok:
        return True
    else:  # something else happened
        raise Exception("Unable to stash a file")

    print ("Finished stashing...")


def do_delete_object(token, url, filename):
    """Stashes the specified local file"""
    print ("Deleting file '{0}'".format(filename))

    _, fname = os.path.split(filename)

    url = url + '/' + stash.eyeoh.STASH_CONTAINER_NAME
    url = url + '/' + stash.util.encode_filename(fname)

    hdrs = {
        'X-Auth-Token': token
    }

    output = requests.delete(url, headers=hdrs)

    if output.status_code == 404:
        stash.util.print_error ("File not stashed: " + filename)
        return False
    elif output.ok:
        print ("File '{0}' was deleted from stash".format(filename))
        return True
    else:  # something else happened
        raise Exception("Other error trying to delete file")

    print ("Finished stashing...")


def do_list_stashes(token, url):

    url = url + '/' + stash.eyeoh.STASH_CONTAINER_NAME

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

            filename = stash.util.decode_filename(item['name'])
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

    parser.add_argument("filename", nargs="*",
                        help="The file to stash")

    args = parser.parse_args()

    if args.configure is not False:
        do_configure(args.identityhost)
        exit(0)

    username, apikey, region = stash.config.read_config()
    token, endpoints = stash.eyeoh.do_auth(username, apikey, args.authcache)

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
        stash.util.print_error("Give me something to stash.")

    else:
        # legit commands, mapped to handle functions
        for filename in args.filename:
            do_upload_file(token, storageurl, filename)

    print (Style.NORMAL)

if __name__ == '__main__':
    main()
