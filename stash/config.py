
import configparser
import keyring
import os

def get_config_filename():
    homedir = os.getenv('HOME')
    configfile = os.path.join(homedir, '.stash')
    return configfile

def read_config():
    configfile = get_config_filename()

    if not os.path.exists(configfile):
        print ("Error: not config found. Run: ")
        print ("  stash --configure")
        exit(1)

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
