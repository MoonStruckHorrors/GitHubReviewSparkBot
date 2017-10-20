#!/usr/bin/python3

import requests
import time
import datetime
import json
import configparser
from logger import Logger

# Global Vars - Read these from config
github_access_token = ""
bot_access_token = ""
bot_self_id = "" # ID of the Spark Bot
botmemfile = "" # Dumping the JSON, keeps track of which PRs are already parsed
sleep_time = -1 # Time in seconds between polling
log_level = "" #
log_file = ""
github_pull_url = ""
smefile=""

# Sessions
spark_session = requests.Session() # requests Session for Spark
github_session = requests.Session() # requests Session for Github

# Static endpoints
spark_msg = "https://api.ciscospark.com/v1/messages"

# Dynamic endpoints - Configurable
github_pulls = "" # GitHub Pulls endpoint
github_pull_files = "" # Endpoint for files in a specific PR ( {0} )

# Logging
logger=None

# General global vars
sme_dir_dict={} # dir - sme mapping dict

def loadConfig():
    global log_file, log_level, github_access_token, bot_access_token
    global bot_self_id, github_pulls, github_pull, sleep_time
    global log_file, botmemfile, log_level, github_pull_url,smefile
    global github_pull_files
    try:
        config = configparser.ConfigParser()
        config.read("rbot.ini")
        github_access_token = config['Tokens']['github_access_token']
        bot_access_token = config['Tokens']['bot_access_token']
        bot_self_id = config['Tokens']['bot_self_id']
        github_pulls = config['RepoInfo']['github_pulls']
        github_pull_files = config['RepoInfo']['github_pull_files']
        github_pull_url = config['RepoInfo']['github_pull_url']
        sleep_time = int(config['General']['sleep_time'])
        log_file = config['General']['LogFile']
        botmemfile = config['General']['BotMemFile']
        log_level = int(config['General']['LogLevel'])
        smefile = config['General']['SMEData']
    except configparser.Error as err:
        print("Couldn't Load Config, Error: {0}\nExiting..".format(err))
        exit(1)
    if log_level not in [10, 20, 30, 40, 50]:
        print("Invalid LogLevel in Config file, defaulting to DEBUG")
        log_level = 10
    
    # Since we have the tokens from the config
    spark_session.headers['Authorization'] = "Bearer " + bot_access_token
    github_session.headers['Authorization'] = "token " + github_access_token

def initLogging():
    global logger
    logger = Logger(log_level, log_file)

def watch_pull_requests():
    while 1:
        open_prs = get_open_pulls()
        if open_prs is None:
            continue
        logger.info("Checking if there are any unchecked Pull Requests")
        pending_prs = get_pending_prs(open_prs)
        if pending_prs is not None:
            logger.info("Action might be required on some Pull Requests")
            logger.info("New PRs: {0}".format(pending_prs))
            # Populate the Dir/SME data dict
            get_sme_dir_dict()
            # Iterate over all the pending Pull Requests
            prs_processed = []
            for prid in pending_prs:
                logger.info("Processing Pull Request #{0}".format(prid))
                flist = get_pr_files(prid)
                if flist is not None:
                    logger.info("Iterating over the file list in Pull Request #{0}".format(prid))
                    sme_notif_dict={}
                    # Iterate over the files and build the dict {sme: file_list}
                    for f in flist:
                        sme_lst = get_smes_for_file(f)
                        if sme_lst is not None:
                            logger.info("SMEs to be notified for file: {0}".format(sme_lst))
                            for sme in sme_lst:
                                if sme not in sme_notif_dict:
                                    sme_notif_dict[sme] = [f]
                                else:
                                    sme_notif_dict[sme].append(f)
                        else:
                            logger.info("No SMEs to be notified for file: {0}".format(f))
                    
                    # If there are no SMEs to be notified, continue
                    if len(sme_notif_dict) == 0:
                        logger.info("No SMEs to be notified for the Pull Request #{0}".format(prid))
                        prs_processed.append(prid)
                        continue
                    
                    # Notifying SMEs
                    logger.info("Initiating Notifications for SMEs")
                    for sme in sme_notif_dict:
                        send_out_notif(sme, sme_notif_dict[sme], prid)
                        prs_processed.append(prid)
                else:
                    logger.info("Couldn't proceed with processing Pull Request #{0}, continuing".format(prid))
                    continue
            # Add the processed PRs to BotMemory file
            if len(prs_processed) == 0:
                logger.info("New Pull Requests found. But not processed for some reason.")
                continue

            logger.info("Updating the BotMemory file")
            with open(botmemfile, "r+") as memfile:
                try:
                    memfile_json = json.load(memfile)
                except json.decoder.JSONDecodeError:
                    memfile_json = {}
            
            if 'checkedPRs' in memfile_json:
                logger.debug("BotMemory exists, appending")
                for pr in prs_processed:
                    memfile_json['checkedPRs'].append(pr)
            else:
                logger.debug("BotMemory doesn't exist, creating fresh")
                memfile_json['checkedPRs'] = prs_processed
            
            logger.debug("Writing to BotMemory")
            with open(botmemfile, "w") as memfile:
                json.dump(memfile_json, memfile)
        else:
            logger.info("No new Pull Requests. No action required")
        logger.info("Sleeping for " + str(sleep_time))
        time.sleep(sleep_time)

def get_open_pulls():
    """Returns a list of all the open Pull Requests"""
    try:
        logger.info("Sending GET to fetch all the open Pull Requests - {0}".format(github_pulls))
        resp = github_session.get(github_pulls)
    except requests.exceptions.RequestException as err:
        logger.error("GET failed for {0}, Error: {1}".format(github_pulls, err))
    
    if resp.status_code == 200:
        resp_json = resp.json()
        pr_ids = []
        for pr in resp_json:
            pr_ids.append(pr['number'])
        return pr_ids
    else:
        logger.warning("GET didn't 'get' 200, Response Received: {0}".format(resp.status_code))
        return None

def get_pending_prs(lst):
    """Returns the PRs where notification needs to be sent. None otherwise
        lst: List maintained in Memory (Stale in case of a crash)
    """
    with open(botmemfile, "r+") as memfile:
        try:
            memfile_json = json.load(memfile)
        except json.decoder.JSONDecodeError as err:
            memfile_json = {}
            logger.error("Bot Memory file: {0} didn't exist. Was created.".format(botmemfile))

    try:
        memlst = memfile_json['checkedPRs']
    except KeyError as err:
        memlst = []
        logger.warning("Bot Memory file: {0} has invalid data. Would be recreated".format(botmemfile))
        logger.warning("Error: {0}".format(err))
    
    difflst = [x for x in lst if x not in memlst]

    if len(difflst) == 0:
        logger.info("No PRs need to be checked")
        return None
    else:
        return difflst

def get_sme_dir_dict():
    """Reads smefile and prepares the dictionary containing Dirs - SME mapping """
    global sme_dir_dict, smefile
    with open(smefile, "r+") as fl:
        for line in fl:
            logger.debug("Parsing line: {0}".format(line))
            dirs,smes = line.split(":")
            dirs = dirs.strip()
            dirs = dirs.split(",")
            smes = smes.strip()
            smes = smes.split(",")
            logger.debug("Dirs in this line:{0}".format(dirs))
            logger.debug("SMEs in this line:{0}".format(smes))
            for d in dirs:
                sme_dir_dict[d] = smes

def get_pr_files(prid):
    """ GETs the files modified for a Pull Request """
    global github_pull_files
    try:
        logger.info("Sending GET to get files modified in Pull Request #{0}".format(prid))
        resp = github_session.get(github_pull_files.format(str(prid)))
    except requests.exceptions.RequestException as err:
        logger.error("GET failed for {0}, Error: {1}".format(github_pull_files.format(str(prid)), err))
        return None
    fnames=[]
    if resp.status_code == 200:
        logger.info("Preparing list of files from the GET response")
        resp_json = resp.json()
        for fobj in resp_json:
            fnames.append(fobj['filename'])
        return fnames
    else:
        logger.warning("GET didn't 'get' 200, Response Received: {0}".format(resp.status_code))
        return None

def get_smes_for_file(fl):
    """This method takes a directory and returns the list of SMEs associated with it"""
    global sme_dir_dict
    res_smelst=[]
    logger.debug("Finding SMEs for {0}".format(fl))
    for sdir in sme_dir_dict:
        if fl.startswith(sdir) == True:
            for sme in sme_dir_dict[sdir]:
                res_smelst.append(sme)
      
    if len(res_smelst) == 0:
        res_smelst = None
    return res_smelst

def send_out_notif(sme, flst, prid):
    """ This method sends out notification with the filelist and PR URL """
    msg = "**SME -- Review Alert**: {0}{1} requires your review.\n\n".format(github_pull_url, prid)
    msg = msg + "You're getting this because you're listed as SME for these modified files in this Pull Request: "
    for fl in flst:
        msg =  msg + "- *" + fl + "*\n\n"
    logger.info("Sending notification to " + sme)
    send_to_person(msg, sme)

def send_to_person(txt, person):
    person = person +  "@cisco.com"
    payload = {'toPersonEmail': person, 'text': txt, 'markdown': txt}
    logger.info("Sending [" + txt + "] to : " + person)
    spark_session.post(spark_msg, data=payload)

def main():
    loadConfig()
    initLogging()
    logger.info("===== Bot Session Start =====")
    watch_pull_requests()

if __name__ == "__main__":
    main();