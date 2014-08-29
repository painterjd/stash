
import base64
from colorama import Style, Fore
import datetime
import hashlib
import hmac
import urllib

def print_error(error):
    print (Style.BRIGHT + Fore.RED + "ERROR: " +
           Fore.GREEN + error +
           Style.NORMAL + Fore.RESET)

def parse_iso_8601(date):
    formatstr = "%Y-%m-%dT%H:%M:%S.%fZ"
    return datetime.datetime.strptime(date, formatstr)

def create_temp_url(key, url, filename, duration):

    path = urllib.parse.urlparse(url).path

    method = "GET"
    object_path = path + "/" + STASH_CONTAINER_NAME + "/" + \
        encode_filename(filename)

    # duration is expressed in hours
    expires = int(time.time() + duration*60)

    hmac_body = "{0}\n{1}\n{2}".format(
        method, expires, object_path)

    sig = hmac.new(bytes(key, 'utf-8'), bytes(hmac_body, 'utf-8'),
        hashlib.sha1).hexdigest()

    fmt = "{0}/{1}/{2}?temp_url_sig={3}&temp_url_expires={4}&filename={5}"

    return fmt.format(url, STASH_CONTAINER_NAME, encode_filename(filename),
        sig, expires, urllib.parse.quote_plus(filename))

def encode_filename(filename):
    b64 = base64.b64encode(bytes(filename, 'utf-8'))
    return b64.decode('utf-8')

def decode_filename(encoded):
    b = bytes(encoded, 'utf-8')
    decoded_bytes = base64.b64decode(b)
    return decoded_bytes.decode('utf-8')

