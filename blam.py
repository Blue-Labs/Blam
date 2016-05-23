#!/usr/bin/env python3

__version__  = '3.0.26'
__author__   = 'David Ford <david@blue-labs.org>'
__email__    = 'david@blue-labs.org'
__date__     = '2016-May-23 14:56E'
__license__  = 'Apache 2.0'

"""
#########################################3
##
##   TODO list
##
##     1.
##     2.  smtp callback verification
##     3.  reputation scoring
##     4.  make a last-seen column in prefs, update it when incoming matches
##     5.  immediate NOTIFY for spam prefs changes instead of when instancing
##

bugs:

Reputation:
    store the IP
    want a reputation value (good sends, bad sends), age averaged (timestamps)
    store bad hostname attempts (timestamps)

CREATE TABLE reputation (
    ip          inet,
    event_ts    timestamp,
    charisma    int                     ; base charisma of 10, lower means more unliked, higher means more liked
                                        ; 0 means hated, 20 means loved
                                        ; each row is a modifier, either positive or negative
);

CREATE TABLE blam (
    ts_now        timestamp,
    ts_milter     timestamp,
    qid           varchar,
    ip            inet,
    helo          varchar,
    quitcode      integer,
    quitreason    varchar,
    quitlocation  varchar,
    macros        varchar,
    recipients    varchar
);



http://www.inmotionhosting.com/support/email/email-troubleshooting/smtp-and-esmtp-error-code-list (better)
http://www.iana.org/assignments/smtp-enhanced-status-codes/smtp-enhanced-status-codes.xhtml
http://www.ietf.org/rfc/rfc1893.txt (good for enhanced #)



Todo:
  - if there's no reply-to header and no MX record for the From:, we ought to score it almost as spam

# SQL widgets
timestamp, qid, conx ip, quit code, quit short, quit reason, quit location, macros

CREATE TABLE blam (
    ts_milter    TIMESTAMP,
    qid          VARCHAR,
    ip           INET,
    helo         VARCHAR,
    quitcode     INT,
    quitshort    VARCHAR,
    quitreason   VARCHAR,
    quitlocation VARCHAR,
    recipients   VARCHAR[],
    mail_from    VARCHAR
);

CREATE TABLE blam_macros (
    ts_now       TIMESTAMP,
    key          VARCHAR,
    value        VARCHAR
);

CREATE TABLE blam_headers (
    ts_now       TIMESTAMP,
    key          VARCHAR,
    value        VARCHAR
);

"""

import asyncore
import configparser
import cssutils
import daemon
import datetime
import email
import fcntl
import html
import inspect
import io
import ipaddress
import locale
import logging
import logging.handlers
import netaddr
import os
import ppymilter
import pwd
import re
import socket
import spf
import ssl
import string
import subprocess
import sys
import textwrap
import time
import traceback

import dns.resolver
import dns.reversename
import dns.exception
import psycopg2
import psycopg2.extras
import psycopg2.extensions

from urllib.request import urlopen

from email.utils    import getaddresses
from collections    import Counter
from lxml           import etree
from lxml.cssselect import CSSSelector

# bluelabs modules
sys.path.append('/var/bluelabs/python')
import cams, dfw, arf


# we love BS4, but OMGWTF
# https://gist.github.com/FirefighterBlu3/db3b8962c44291cd19e0#file-bs4-no-html-translations-py
import bs4.dammit
import bs4.builder._htmlparser
from bs4 import BeautifulSoup

# when analyzing spam, we always run into situations where the sender tries
# hard to obfuscate their input in order to sneak by spam detecting engines.
# instead of "ABC", they'll use HTML Entity references; &#65;&#66;&#67; in
# order to extract the viewer readable segments, we need a parser.  most
# parsers try to be smart and clean things up.  BeautifulSoup and lxml are
# two common parsers.  lxml is largely compiled C so we can't tweak it very
# easily.

# step #1
# BeautifulSoup insists on always doing entity substitution and there's no
# way to politely tell it to fuck off.  override the hex->int and
# word->symbol conversions, simply append our data to the growing stack
_handle_data = bs4.builder._htmlparser.BeautifulSoupHTMLParser.handle_data
bs4.builder._htmlparser.BeautifulSoupHTMLParser.handle_charref   = lambda cls,s: _handle_data(cls, '&#'+s+';')
bs4.builder._htmlparser.BeautifulSoupHTMLParser.handle_entityref = lambda cls,s: _handle_data(cls, '&'+s+';')

# step #2
# BeautifulSoup insists on further ensuring printed data is always tidy and
# semantically correct, thus it ALWAYS does entity substitution even after
# we refused to do it above.  the below ensures the __str__ methods don't
# attempt to mangle the serialized data.  this simply returns the original
# matched input when the substitution methods are called
bs4.dammit.EntitySubstitution._substitute_html_entity = lambda o: o.group(0)
bs4.dammit.EntitySubstitution._substitute_xml_entity  = lambda o: o.group(0)
# end of BS4 OMGWTF


cookieprocessing = True

# turn off logging in cssutils
cssutils.log.setLevel(logging.CRITICAL)

#from sqlalchemy import create_engine
#from sqlalchemy.orm import sessionmaker
#from sqlalchemy.event import listen
#from sqlalchemy.ext.declarative import declarative_base

#Base    = declarative_base()
#engine  = create_engine('postgresql+pypostgresql://xxx@vss.vpn:5432/sendmail')
#Session = sessionmaker(bind=engine)
#Session.configure(bind=engine)
#session = Session()

#writer = codecs.getwriter('utf8')(sys.stdout.buffer)


# not really used at the moment, here as a reminder
locale.setlocale(locale.LC_ALL, 'en_US.utf-8')
encoding = locale.getpreferredencoding()

ansi     = ppymilter.base.ANSI
last_st  = ('0.0.0.0',0)
ansiloop = ('red','green','yellow','blue','magenta','cyan','white','bblack','bred','bgreen','byellow','bblue','bmagenta','bcyan','bwhite')
ansime   = enumerate(ansiloop)
wrapper  = textwrap.TextWrapper(initial_indent='', subsequent_indent=' '*16+ansi['bwhite']+'│  '+ansi['none'], width=180, expand_tabs=False, replace_whitespace=False)

spam_dict = {'success':1, 'market':2, 'marketing':2, 'markting':2, 'merchant':1, 'sephora.fr':1, 'affipro':1, 'b2b':1,
             'mailpalmaresduweb.com':1, 'replica':1, 'promotion':1, 'target':.25, 'replica':1, 'freestuff':1,
             'diversify':1, 'business':1, 'offers':1, 'offres':1, 'exclusive':2, 'confirm your':3, 'resolution':3,
             'exclusif':1, 'services':1, 'replica':1, 'promotion':1, 'exclusively here':5, 'last chance':5,
             'grow your':3, 'small business':2, 'funding':2, 'redeem':1, 'rewards':1, 'receepts':5, 'valid online':2,
             'voucher':2, 'comfort of your':5, 'it might be too late':2, 'open now':4, 'capital':2, 'start-up':2,
             'small business':2, 'loan':2, 'approval rating':2, "global who's who":10, '\d+ days only!':3,
             'work.from.home':5, 'work.at.home':5, 'change careers':3, 'medical coding':5, 'perks of':2, 'business class':2,
             'must have':2, 'soldier':1, 'us army':1, 'survival tool':2, 'protect your loved':2, 'starbucks':1, 'coffee':1,
             'reward':1, 'reward.?points':1, 'going to expire':1, 'will expire':1, 'notice':1, 'notice #\d+':5, 'go here':1, 'claim your':1,
             'complimentary':1, 'follow the link':1, 'redeem':1, 'olive.?garden':1, 'bonus':1, 'simply visit':1,

             'stylish ideas':2, 'ideas for your':2, 'outdated kitchen':10, 'kitchen ideas':4, 'flashlight':3,
             'mothers day':2, 'you still have time':2, 'get there in time':2, 'order today':2, 'luxury':2, 'premium':1, 'elite':1,
             'ad listings':8,

             'singh web-services':15,
             'slater.net.com.group':15,
             'tomlinson quick-net':15,

             # vacuums
             'best vacuums?':3, 'vacuum cleaners?':3, 'upright':.5, 'canister':.5, 'bagless':2, 'cordless':.5, 'cleaning capacity':2,


             # phishing
             'user quota exceeded':15, 'will be closed':2, 'click here':8, 'increase your storage':5, 'in next 24(hrs|hours)':3,
             'proper verification':4, 'access your':2, 'domain security':3, 'free registration':1, 'xerox':5,
             'workcentre pro':5, 'please open the attached':5, 'account':1, 'account for verification':15,
             'reward balance':5, 'trust fund':5, 'send your identity':5,

             'i am following up with you':5, 'if you are interested':2, 'entry level':2, 'promotional':2, 'click on the link':3,
             'demo of our':3,

             # scam
             'sterling power':10, 'lg wave':10, 'has been deposited':2, 'bonds':1, 'cash':1, 'passport':1,
             'activate your account':2,

             # sex
             'f\*ckbuddy':10, 'f\*ck':10, 'fuck':3, 'hookup':3, 'into commitment':3,
             'look at my hot photos':25, 'please find me here':5, 'luckyrusdate.ru':20, 'my name is':8,
             'do you want to be with me':10, 'orgasm':3,

             # school
             'diploma':8, 'degree':2, 'university':1, 'mba':2, 'm.b.a.':5, 'career':1, 'back to school':1,
             'back to school':2, 'graduate':1, 'job advancement':5, 'one year program':5,

             'quality cigars':5,
             'watches':2, 'credit card':2, 'contract':1, 'pimsleur approach':15, 'pimsleurapproach':8,
             'production capacity':1, 'price':1, 'sales':1, 'eharmony':3,'drugstore':2,'cheapest':1,
             'cash':3, 'loan':3, 'breaking news':5, 'best price':2, 'home and office':2,
             'our courier couldnt make the delivery of parcel to you at ':99,
             '263yutdz':99,
             'must.see':3, 'cops use these':3,

             # vacations
             'cruise':1, 'cruises':2, 'caribbean':2, 'alaskan':2, 'vacation':.5, 'luxury':1, 'luxury liner':4,
             'resorts?':4, 'mexico':4, 'cheap vacation':5, 'all.?inclusive':5, 'booking now':5, 'island vacation':5,
             'private jets?':4, 'crowded airports?':4, 'dream.vacation':3, 'summer camp':5,

             # deals
             'savings':1, 'sponsored ads':5, 'last minute deals':3, 'great deals':2, 'save up to':1.8, 'featured ads':10,
             'most affordable':4, 'affordable':1, 'view the offer':5, 'free trial':5, 'check prices':5, 'limited supply':10,
             'limited production':10, 'claim your':3, 'voucher':3, 'gift ?card':5, 'claim here':8, 'dr. oz':10,
             'dealerships':3, 'need to go':3, 'find.out.more':3, 'learn more':2, 'wave goodbye':2,
             'respond to this notice':3, 'more inventory':1, 'need to clear':1, 'drive away':1, 'little to nothing':1,
             'before they are gone':1,

             # save/make money
             '<p>order r:\d+':99,
             'earn at home':5, 'risk free':5, 'money making':5, 'save money':4, 'earn immediately':5, 'higher salary':5,
             'you qualify':5, 'claim your':5, 'bank':3, 'loan':3, 'income':3, 'financial plan':8, 'hgtv-home':10,
             'reduced payment':1, 'banking':5, 'investment':5, 'monthly payment':2, 'your coverage':2, 'policy':.5,
             'saving money':3, 'overpaying for':3, 'additional.charges':2,

             # jobs
             'abundant openings':3,

             # insurance
             'insurance':2, 'lifeinsurance':3, 'life[ -]insurance':3, 'life[ -]policy':3, 'insurance offer':3, 'medicare':5,
             'open enrollment':5, 'aarp':2, 'humana':1, 'blue cross':1, 'aetna':1, 'cigna':1, 'unicare':1, 'life policy':5,
             'important information':5, 'fantastic':1, 'older americans?':1,
             'payments':1, 'click here':3, 'FHA-? ?approved':1, 'term life':5, 'aig direct':2,

             'perfect shave':5,

             '=?koi8-r':1,
             'mail.ru':2, '\w+\.ninja\W':2,

             'not displaying correctly':2, 'view it in your browser':2, 'view more info':3,
             'this email has been protected by yac':20,

             'discreet fun':10, 'cheating men and women':10, 'secret affair':10,
             'printer ink':15,
             'never lose your keys':15,

             'hvac':3, 'a/c':3, 'multiroom a/c':2, 'air conditioners?':2, 'ac system':2, 'central air':2, 'hvac':2, 'cooling':2, 'cooling costs':5,
             'energy efficient':3, 'pella windows':8, 'thermostat':3, 'cool and comfortable':3, 'ductless':2, 'central air':2,

             'voip':2,

             'roof(-| )repair':10, 'roofing specials':10, 'home.repair':3, 'home.warranty':3, 'coverate':1,

             # tax
             'irs':5, 'irs account':18, 'tax payment':3, 'irs-service':18, 'internal revenue service':5,

             # removal instructions and "opt out here"
             'your privacy is important to us':5, 'update( \w+|) here':5, 'stop/forego':15, 'this-link':10,
             'go here to':15, 'visit here to':15, 'visit us here to':15, 'go here for':15, 'solicite':15, 'aqui':5, 'aquí':5,
             'to be removed':10, 'message discharge instructions':10, 'unsubscribe':.5, 'as unwanted':1, 'unsub.now':10,
             'to not see messages form us':18, 'U-R-L':10, 'prefer not to receive future emails, Unsubscribe Here':5,
             'responder esta invitación':5, 'recibir actualizaciones al respecto':15, 'responda con el asunto':15,
             'para darse de baja de esta lista de suscripción':25, 'to now end':10, 'viewingads':10, '_go-here':10,
             'physicalmailing':10, 'your delete directions':8, 'suspension of mail\w*':10, 'cease any future correspondence':10,
             'halt future delivery':10, 'you can end mess':10, 'future e-notices':10, 'to stop receiving':8,
             'to end information':10, 'inform us by letter':5, 'opt.?out':10, 'stop receiving messages':10, 'preferences':.5,
             'this message was sent to':2, 'want to receive (these |)emails from us':2, 'end messsages':10, 'navigate here':5,
             'no desea recibir':10, 'list removal':5, 'sent to the wrong person':5, 'report spam':5, 'signed up in error':5,
             'remove at this location':10, 'from-future sends':10, 'remove-from sender':10, 'stop these messages':10,
             'for list-removal':10, 'to not get these':10, 'cease further messages':10, 'remove here':5, 'redact':2,
             'message sent by':2, 'visit here':2, 'redact from':2, 'click on the':3, 'wish to receive':3, 'end.messages':3,
             'modify your preferences':3, 'retract.messages':10, 'discontinue receiving this':10,

             'refrain from future messages':8, 'to stop information':8,

             'looking to.(quit|end).(future|further|these).\w+ads\W':10,
             'if you would.(prefer|rather).quit.(future|further|these).\w+ads\W':10,
             'if you want to end messaging':10,
             'you can.quit these scoreads-':10,
             'you can end-future repairads':10,
             "if you'd rather not.get these healthyads":10,
             'Want to change how you receive these emails':10,

             # address at bottom of email
             'po box.*?,\s?austin tx':15,
             'p o b o x':15, 'pobox':8, 'pobox\d+':8,
             '15547 hazel road morrison il':15,
             '1748 olympic ave':15,
             '2331 east lake drive':15,
             'katz web-creations 6001 rt b':15,
             '1748 olympic avenue_westw00d':15, '1748 olympic ave':15,
             '6506 pine trail #4-pinley park-il':15,
             '101 e. carroll rd, south whitley, in 46787':15,
             '7471 n. camino':15,
             '3.?7.?3.?3.?w.?o.?o.?d.?v.?i.?e.?w':15,
             '6506 pine trail':15,
             'tinley park, il 60477':15,
             '761 soap hollow rd':15,
             '2885 sanford ave s.w. #37719':15,

             'old folk saying':2, 'proverb':2,

             # health and medical
             'studies show':15, 'a recent [\w-]+( [\w]+|) study':15, 'clinically proven':15, 'medical billing':5, 'medical coder':5,
             'do you( or a loved one|) suffer':15, 'loved ones':5, 'health.related':5, 'copd':5, 'meds':4, 'cheap meds':20,
             'sugar':5, 'diabetes':5, 'insulin':5, 'starch':5, 'blood sugar':5, 'diabetics':5, 'glucose':5, 'meds online':20,
             'high blood pressure':5, 'illness':5, 'age related':5, 'dementia':5, 'symptoms':1, 'pharmacy online':20,
             'boost your \w+':5, 'brain booster':5, 'brain-pill':5, 'thin waist':5, 'skinny waist':5, 'remedies':1, 'disease':1,
             'skin cancer':5, 'cancer':2, 'melanoma':5, 'diagnosis':1, 'chemo':1, 'mesothelioma':15, 'asbestos':5,
             'blood pressure':8, 'medical':1, 'alcoholism':2, 'detox':2, 'alcohol dependence':2, 'stroke':2, 'liver disease':2,
             'health':2, 'rehabilitation':2, 'restore your':5, 'recover from':2, 'hearing loss':10, 'implant':2, 'no surgery':5,
             'arthritis':5, 'walk in baths?':8, 'limited mobility':5, 'therapeutic':5, 'medicine':1, 'health care':1, 'drugstore':3,
             'viagra':8, 'cialis':8, 'propecia':8, 'malextra':8, 'dxt':8, 'pfizer':10, 'botox':8, 'levitra':8, 'belly(\s|-)fat':8,
             'vigara':8, 'cilais':8, 'pharmacy':5, 'med shoppe':15, 'levtira':8, 'weight(\s|-)loss':8, 'diet':5, 'exercise':5,
             'hearing aids?':1, 'pain':1, 'prescription':8, 'less wrinkles':8, 'anti(\s|-)aging':5, 'international pharmacy':20,

             'safegenericsshop.ru':60, 'globalherbalgroup.ru':60,


             'img src="https?://[\w.]+\?email=':50,

             # credit checks, background checks
             'equifax':3, 'experian':3, 'consumer alert':3, 'conspiracy':3, 'scandal':3, 'controversial':3, 'fox\s*news':15,
             'public records?':3, 'background reports?':3, 'background records?':3, 'background search':3, 'public details?':3,
             'background quer(y|ies)':3, 'information search(?:es|)':3, 'background checks?':3, 'background-records':5,
             'criminal file':3, 'background.lookups?':3, 'history checks?':3, 'history hunts?':3, 'open records':3,
             'perspective records':3, 'notification':1, 'records notice':3, 'review notification':8, 'in your area':8,
             'trained contractors':8, 'major local networks':8, 'your scores.have(.recently|).changed':8,
             'credit score':2, 'debts':2, 'credit':2, 'consolidate':1, 'monthly payment':2, 'low rate':2,
             'debt analysis':5, 'credit counselor':2, 'consolidated credit':5,
             'spending power':10, 'score notification':3, 'this notification':3, 'score.update':3, 'action.required':3,

             'exclusively':3, 'limitless':3,
             'auto(motive|)( \w+) warranty':10, 'auto(motive|)( \w+) service':10, 'warranty':5, 'guarantee':5,
             'auto(-| )coverage':10, 'auto liquidation':10, 'compare rates':5, 'get rates':5, 'autoinsurance':10,
             'savings':3, 'a-?d-?v-?e-?r-?t-?i-?s-?e-?m-?e-?n-?t':10, 'local dealerships':10, 'dealerships':8, 'vehicles':2,
             'new and used':5, 'large selection of':3, 'specials end':3,
             'service plan':5, 'retirement planning':10, 'homeowners?':10, 'home equity':10, 'mortgage':10,
             'free\s*shipping':3,
             'certificate':1, 'certificadas':5,
             'kidney beans':8, 'as seen on tv':50, 'coupon':2,
             'end notification':8, 'specials end':3, '\d+% off':2, 'new and used':5,
             'new or used car':10, 'at your local dealer':10, 'oil change':2, 'auto\s*repair':2,

             'new invention':5, 'selling out quickly':5, 'while( stock is|) available':5, "before it's too late":5,
             'by invitation only':5, 'special proposition':5, 'you have been selected':5, 'revelation':2, 'news is spreading':5,
             'important information':5, 'free sample':5, 'visit here now':5,
             'professional':1, 'increase in value':1, 'cosmetic':1, 'contractor':1, 'affordable':1,

             # white on white
             'background-color:\s*#FFFFFF;\s*color:\s*#FFFFFF;':8,
             'color:\s*#FFFFFF;\s*background-color:\s*#FFFFFF;':8,

             # greetings
             'hello':.5, 'good\s+day':.5, 'good\s+evening':.5, 'good\s+afternoon':.5,
             'how\s+are\s+you':1, 'what\'?s\s+new':1, 'what\'?s\s+up':1,

             # tiny text
             'font-size:\s*xx-small;':8,


             # shitball domains
             'cblc-nonlinesconsumers\d+.link':50,
             'http://aimg\.xingcloud\.com/bdh\.js':50,

             'alt="please turn images on"':50,


             # lots of words with excess spaces
             #'\w\w+\s\s+':.095,

             # lots of blank lines
             '\n{5}':10,
             '<br><br><br><br><br><br><br>':15,

             # /////////////
             '/{30,}':5,

             # white text on white background
             'color:\s*#(?:ffffff|fff);\s*background-color:\s*#(?:ffffff|fff);':15,

             '={20,}':3, '-{20,}':3,

             # tiny tiny text/none
             'font-size:\s*xx-small;':10,
             'display:\s*none':1,

             # well known spam url format
             '/20621320/vuxtxu':50,
             '/20621317/':50,
             '/[a-z]{20}/[\d]{36}':10,
             '263yutdzeumt9cul_ol"></map></a>':50,
             '/dc/55ec676f05bbf1742d4ce07b87a67902/21320':50,
             '/l/l[ct]\d+[a-z]+\d+[a-z]+\d+[a-z]+/':50, # href
             '/im/[\da-z]{10}//im/[\da-z]{36}/img\d{8}.gif':50, # corresponding img
             '/\d{4}-\d{3}-\d{4}-\d{7}/':50,
             'https?://[^/]+/0s3b522sas2':50,
             'a02c12fde9db1c4b266925b85139272e':5,

             'i would directly like to request you':10,
             'acquire additional income online':10,
             'this is building a major stur':10,
             'make money':2,

             # emphasized url
             '>{6,}\shttp':15,
             '\*{6,}\shttp':15,

             'concrete':1, 'voted best product':5, 'cut your electric':5,
             }

# not really used yet
unknown_local_attempts = {} # dictionary of IP:{'ts':dt, 'count':attempts}
incomplete_connections = {} # dictionary of IP:{'ts':[dt,],} for all incomplete SMTP transactions for the last hour
recent_msgids          = {} # dictionary of recent msg-ids to prevent multiple spams of same ID

rfc1918 = netaddr.IPSet()
[rfc1918.add(x) for x in ('127.0.0.0/8','10.0.0.0/8','172.16.0.0/16','192.168.0.0/16')]


# use this instead of a real DFW instance during unit testing
class VoidDFW():
    grace_score = 10


def pickansi():
    global ansime

    try:
        i = next(ansime)[1]
    except:
        ansime = enumerate(ansiloop)
        i = next(ansime)[1]

    return ppymilter.base.ANSI[i]


class PidFile(object):
    """Context manager that locks a pid file.  Implemented as class
    not generator because daemon.py is calling .__exit__() with no parameters
    instead of the None, None, None specified by PEP-343."""
    # pylint: disable=R0903

    def __init__(self, path):
        self.path = path
        self.pidfile = None

    def __enter__(self):
        self.pidfile = open(self.path, "a+")
        try:
            fcntl.flock(self.pidfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            raise SystemExit("Already running according to " + self.path)
        self.pidfile.seek(0)
        self.pidfile.truncate()
        self.pidfile.write(str(os.getpid()))
        self.pidfile.flush()
        self.pidfile.seek(0)
        return self.pidfile

    def __exit__(self, exc_type=None, exc_value=None, exc_tb=None):
        try:
            self.pidfile.close()
        except IOError as err:
            # ok if file was just closed elsewhere
            if err.errno != 9:
                raise
        os.remove(self.path)



def check_wblist(pme, prefs, localusers, targets, wblist):
    __found = False
    for user in localusers:
        for _t in targets:
            pme('   {:<14} checking if [{},$global] sets {}'.format(wblist,user,_t))
            __found = prefs.match(wblist, _t, user)
            if __found:
                pme('   {}found{}'.format(ansi['bblue'],ansi['none']))
                break
        if __found:
            break

    if __found:
        return True,__found
    else:
        return None,None


class Prefs:
    def __init__(self):
        self.rules = []

    def add(self, *args):
        if isinstance(args, tuple) and isinstance(args[0], list):
            args = args[0]
        elif isinstance(args[0], str):
            args = [args]

        for t,u,r in args:
            _or = r
            t   = t.lower()
            u   = u.lower()
            r   = r.lower()

            if r.startswith('@'):
                r = '*'+r

            r = r.replace('.','\.')
            r = r.replace('+', '\+')
            r = r.replace('*','.*')

            try:
                pr = re.compile(r)
            except:
                rfe = 'rule compilation failed for: user:{}, type:{}, rule:{}'.format(u,t,_or)
                raise Exception(rfe)

            self.rules.append( {'matchtype':t, 'username':u, 'rule':pr, 'original_rule':_or} )


    def __repr__(self):
        return repr({'matchtype':self.matchtype, 'username':self.username, 'rule':self.rule, 'original_rule':self.rule_o})


    def match(self, matchtype, address, username=None):
        '''
        test for the rule in the preferences list. if no username is specified, only look in the $global
        if a username is specified, look first for the username match, then in $global. whitelist overrides
        blacklist

        return:
            None   - not found
            True   - found
        '''

        # early fail
        matchtypes = {'whitelist', 'whitelist_to','whitelist_auth','whitelist_from','blacklist', 'blacklist_to','blacklist_from'}
        if not matchtype in matchtypes:
            raise Exception("invalid type type '{}', must be in: {}".format(matchtype, matchtypes))

        stype = [matchtype]
        if '_' in matchtype:
            stype.append(matchtype.split('_')[0])

        address = address.lower()

        if username:
            username = username.lower()

        for rule in self.rules:
            if not rule['matchtype'] in stype:
                continue

            if not rule['username'] in (username,'$global'):
                continue

            if rule['rule'].search(address):
                return rule


class DB():
    live     = False
    conn     = None
    prefsdb  = None

    def __init__(self, config, logger):
        self.conn      = None
        self.prefsconn = None
        self.config    = config
        self.logger    = logger

        self.prepared_statements = dict()
        self._build()

        '''
        logger.info ('initializing queue database')

        s3db = sqlite3.connect(self.spool, timeout=60, isolation_level='DEFERRED', detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        sqlite3.register_adapter(datetime.datetime, self._adapt_datetime)

        s3c       = s3db.cursor()
        self.s3db = s3db
        self.s3c  = s3c

        try:
            s3db.execute('select * from blamq where 1=2')
        except:
            s3db.execute('create table blamq (ts timestamp, data)')
        finally:
            s3db.execute('PRAGMA synchronous = OFF')
            s3db.execute('PRAGMA journal_mode = MEMORY')

        logger.info('sqlite3 spool db is ready')
        '''


    def _adapt_datetime(self, ts):
        return ts.strftime('%s.%f')


    def _psql_prepare_blam_statements(self):
        with self.conn.cursor() as c:
            try:
                cols = 'ts_now,ts_milter,qid,ip,helo,quitcode,quitshort,quitreason,quitlocation,recipients,mail_from'

                txt  = '''PREPARE insert_stats AS INSERT INTO blam ('''+cols+''') VALUES
                 ( $1::text::timestamp, $2::text::timestamp, $3::text, $4::text::inet, $5::text, $6::int, $7::text, $8::text, $9::text, $10::text[], $11::text) '''
                c.execute(txt)

                txt    = '''PREPARE insert_macros AS INSERT INTO blam_macros (ts_now,key,value) VALUES ($1::timestamp, $2::text, $3::text)'''
                c.execute(txt)

                txt    = '''PREPARE insert_headers AS INSERT INTO blam_headers (ts_now,key,value) VALUES ($1::timestamp, $2::text, $3::text)'''
                c.execute(txt)
                self.logger.debug('prepared statements readied')

            except Exception as e:
                self.logger.error('failed to prepare statements: {}'.format(e))


    def _build(self):
        self.live    = False
        logger       = self.logger

        if not self.conn:
            logger.info ('Reconnecting to blam DB')
            try:
                uri = self.config['main']['db uri']
                self.conn      = psycopg2.connect(uri)
                self.prefsconn = self.conn
                self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            except Exception as e:
                logger.error ('failed to connect to psql db: {}'.format(e))

        if self.conn:
            self._psql_prepare_blam_statements()

        if self.prefsconn:
            logger.info('checking for/making prefs tables')
            self._psql_create_prefs_table()
            logger.info('checking for/making prefs rules')
            self._psql_create_prefs_rules()
            logger.info('getting prefs')
            self.get_prefs()
            logger.info('prefs loaded')

        if self.conn:
            self.live = True


    def reconnect(self):
        self.live = False
        self._build()


    def close(self):
        self.conn.close()


    # whitelist/blacklist preferences
    def _psql_create_prefs_table(self):
        with self.prefsconn.cursor() as c:
            logger = self.logger

            try:
                c.execute('select * from userprefs where 1=2')
            except:
                tdef = '''
 username    character varying             not null,
 preference  character varying             not null,
 value       character varying             not null,
 note        character varying,
 prefid      integer                       not null default nextval('userprefs_prefid_seq'::regclass),
 modified    timestamp without time zone   default now(),
 modifier    character varying
                   '''
                c.execute('create table userprefs ({})'.format(tdef))
                logger.info('created new preferences table')


    def _psql_create_prefs_rules(self):
        ops    = {'insert','update','delete'}
        logger = self.logger

        with self.prefsconn.cursor() as c:

            try:
                for op in ops:
                    s = 'CREATE OR REPLACE RULE "prefs_{upper}" AS ON {upper} TO "userprefs" DO NOTIFY "{lower}"'
                    s = s.format(upper=op.upper(), lower=op)
                    c.execute(s)
            except Exception as e:
                logger.warning ('failed to create rules/listen, please fix: {}'.format(e))

            c.execute('LISTEN insert')
            c.execute('LISTEN update')
            c.execute('LISTEN delete')

        logger.info('PSQL LISTEN rules created')


    def check_notified(self):
        if self.prefsconn.notifies:
            while self.prefsconn.notifies:
                self.prefsconn.notifies.pop(0)
            self.logger.info(ansi['bmagenta']+'Re-fetching preferences'+ansi['none'])
            self.get_prefs()


    def get_prefs(self):
        logger = self.logger

        if not self.prefsconn:
            logger.warn('no connection to prefs db')
            return

        self.prefs   = None
        rows         = []
        logger.info ('loading black/whitelists')

        try:
            cols      = 'preference,username,value'
            prefcols  = {'whitelist_from','whitelist_auth','whitelist_to','blacklist_from','blacklist_to'}
            prefs     = "('"+ "','".join(prefcols) +"')"
            txt       = '''SELECT '''+cols+''' from userprefs where preference in '''+prefs+''' order by preference,username,value'''
            with self.prefsconn.cursor() as c:
                c.execute(txt)
                rows = c.fetchall()
            logger.info('Loaded {} pref rules'.format(len(rows)))
            self.prefs = Prefs()
            self.prefs.add([r for r in rows])
        except Exception as e:
            logger.error ('error fetching prefs: {}'.format(e))


    """
    # launched in Thread to periodically process
    def queue_manager(self):
        logger = self.logger
        db3    = sqlite3.connect(self.spool, isolation_level='DEFERRED', detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        db     = self.conn
        c      = db3.cursor()

        while True:
            c.execute('select count(*) from blamq')
            rc = c.fetchall()
            rc = rc[0][0]
            logger.info ('SQL3 DB has {} rows awaiting transfer'.format(rc))

            if rc > 0:
                # try pgsql connection
                if not self.conn:
                    logger.warning ('psql database not live, aborting')
                    self.reconnect()
                else:
                    try:
                        self.conn.execute('SELECT now()')
                    except Exception as e:
                        logger.info ('reconnecting due to psql error: {}'.format(e))
                        traceback.print_exc(limit=5)
                        sys.stdout.flush()
                        sys.stderr.flush()
                        self.reconnect()

                    self.dequeue()

            time.sleep(10)


    def dequeue(self):
        logger = self.logger
        # we have to use our own cursor when in a different thread
        db3    = sqlite3.connect(self.spool, isolation_level='DEFERRED', detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        db     = self.conn
        c      = db3.cursor()
        db3.execute('PRAGMA synchronous = OFF')
        db3.execute('PRAGMA journal_mode = MEMORY')

        # load local store rows
        try:
            c.execute('select * from blamq order by ts asc limit 100')
        except Exception as e:
            logger.error ('error selecting: {}'.format(e))
            db3.close()
            return

        rows = c.fetchall()
        logger.info ('{} rows to transfer'.format(len(rows)))

        _dt = []
        ids = [x[0] for x in rows]
        logger.debug('Dequeuing and storing event ids: {}'.format(ids))
        for row in rows:
            ts = row[0]
            _dt.append( ts )
            stats,macros,headers = pickle.loads(row[1])

            # store in pgsql
            #with db.xact():
            if 1:
                ps = self.prepared_statements['stats']
                ps(stats['ts_now'], stats['ts_milter'], stats['qid'], stats['ip'], stats['helo'], stats['quitcode'], stats['quitshort'], stats['quitreason'], stats['quitlocation'], stats['recipients'], stats['mail_from'])

                if macros:
                    ps = self.prepared_statements['macros']
                    ps.load_rows(macros)

                if headers:
                    ps = self.prepared_statements['headers']
                    ps.load_rows(headers)

        # delete from blamq if successful
        logger.debug ('delete cache of what we just transferred')
        x = c.executemany('delete from blamq where ts = ?', self.get_stamps(_dt))
        logger.debug ('done flushing cache. {}'.format(x))

        # purge local store

        #c.execute('vacuum')
        #db3.commit()

    def get_stamps(self, stamps):
        for ts in stamps:
            yield tuple([ts,])
    """

def get_local_username(address, retry=True):
    #print('get local username for: {}'.format(address))
    __orig = address
    while True: # look for full addr+ext@dom.com
        try:
            address = subprocess.check_output(['postmap','-q', address, '/etc/postfix/virtual-aliases']).decode().strip()
        except:
            break

    if '+' in address.split('@',1)[0]: # reduce addr+ext@dom.com to addr@dom.com
        l,d = address.split('@',1)
        l = l.split('+',1)[0]
        address = get_local_username(l+'@'+d)

    if '@' in address and address == __orig and retry: # check for @foo.org
        l,d = address.split('@',1)
        _ = get_local_username('@'+d, False)
        if _[0] == '@':
            _ = l+_
        address = _

    if not retry: # if we were sub'd in, return
        return address

    if '@' in address: # get username part of localpart
        address,d = address.split('@',1)
        address = address.split('+',1)[0]

    while True: # now reduce usernames
        try:
            address = subprocess.check_output(['postmap','-q', address, '/etc/postfix/aliases']).decode().strip()
        except:
            break

    # check for excess punctuation in address as it may be an expansion, if so
    # just return None so we don't try to find a non-existent username nor
    # unintentionally do an SQL injection. note, this will fail for utf8 rich
    # usernames.
    legits=[]
    address = ', ' in address and address.split(', ') or address
    address = isinstance(address, list) and address or [address]

    for a in address:
        if '@' in a:
            #print('ultra sub',a)
            a = get_local_username(a)
            #print('got back:',a)
            if isinstance(a, list):
                legits += a
                continue
        try:
            re.fullmatch('[\w_.-]+', a).groups()
        except:
            pass

        if isinstance(a, str):
            legits.append(a)

    return legits


class BlamMilter(ppymilter.server.PpyMilter):
    def __init__(self, socktuple=None, additional={}, unittest=False):
        ppymilter.PpyMilter.__init__(self)

        self.unittest = unittest

        # set up memory IO stream to write any detail to
        self.iolog             = io.StringIO()
        self.logname           = None

        if not socktuple:
            socktuple=('0.0.0.0',-1)
        self.st                = socktuple

        if not (additional and 'logger' in additional):
            additional['logger'] = logging.getLogger('/Blam')
        self.logger = additional['logger']

        if not (additional and 'config' in additional):
            additional['config'] = []
        if not (additional and 'db' in additional):
            additional['db'] = None
            self.printme('No DB instance provided, no preferences available', level=logging.WARNING)
        if not (additional and 'dfw' in additional):
            additional['dfw'] = None
            self.printme('No Distributed Firewall instance provided', level=logging.WARNING)
        if not (additional and 'cams' in additional):
            additional['cams'] = None
            self.printme('No CAMS interface registered', level=logging.INFO)
        if not (additional and 'resolver' in additional):
            additional['resolver'] = dns.resolver.Resolver()
            self.printme('DNS Resolver not configured at startup, this will lead to rapid exhaustion of /dev/urandom', level=logging.WARNING)

        # static, won't change under an RSET condition
        self.config            = additional['config']
        self.db                = additional['db']
        self.dfw               = additional['dfw']
        self.cams              = additional['cams']
        self.resolver          = additional['resolver']

        # reset dfw logger to my printme. this is quite a hack mish mash right now and will eventually get recoded
        if unittest:
            self.dfw = VoidDFW()
        if self.dfw:
            self.dfw._logger.set_printer(self.printme)
            self.dfw._logparent    = self

        # under certain conditions, our instance may exist for a very long if someone is trying a DoS attack
        # to keep sockets open. we need to set a last-changed timestamp and figure out how to deal with this
        # complex situation
        self.last_active       = datetime.datetime.utcnow()

        self.mycolor           = pickansi()
        self.tlds              = update_tlds(self.config, self.logger)

        self.poison            = ('david-removepoison', 'david+yourfreepresent')

        # these need to go away, make the remote do authentication
        self.pre_approved      = ('vselab.security-carpet.com', 'vss.vpn.blue-labs.org', 'vss.security-carpet.com',
                                  'icinga.security-carpet.com',
                                  'Ranger.Blue-Labs.org', 'Mustang.Blue-Labs.org', 'ovas-master.wh.verio.net',
                                  'pandora.vpn.blue-labs.org','ovas-master.vpn.security-carpet.com','BRW1FB2A7',
                                  )
        self.re_from           = re.compile('.*<(.+?@[^>]+)(?:\s\(.*?\))')

        self.CanAddHeaders()	# define what actions we might use
        self.CanQuarantine()

        self.mailfrom_tried    = False
        self.has_aborted       = False
        self.has_closed        = False

        self.headers           = []
        self.macros            = {}
        self.stored_macros     = {}
        self.stored_recipients = []
        self.stored_headers    = []
        self.subject_chad      = ''
        self.email_msg         = None
        self.stored_email_msg  = None

        # track session layers; normally only a depth of two, the initial connection and for
        # STARTTLS sessions, another layer. we'll use a dictionary that will normally have
        # at least a session named 0, and another named 1 for STARTTLS sessions. this will
        # help ease the tracking of
        self.session_layers    = {}
        self.session_depth     = 0

        self._init_resettable(initall=True)
        self.printme('## instanced ##', console=True)
        if self.unittest:
            self.printme('UNIT TEST being performed')


    def _init_resettable(self, abort=False, initall=False):
        #self.printme('doing resettable, abort={}, initall={}, has_aborted={}, len(macros)={}/{}'.format(abort,initall,self.has_aborted, len(self.macros),len(self.stored_macros)), console=True)

        # store forever
        self.helo_chad              = ('helo' in self.__dict__ and self.helo) and self.helo[-1] or ''

        if self.stored_headers:
            for k,v in self.stored_headers:
                if k =='Subject':
                    self.subject_chad       = v

        if self.macros:
            self.stored_macros      = self.macros
        if self.email_msg:
            self.stored_email_msg   = self.email_msg

        # reset on RSET
        self.macros                 = {}              # global, values can change during cycles
        self.headers                = []              # per message
        self.actions                = []              # per message
        self.recipients             = []              # per message
        self._from                  = None            # per message (From)
        self.mail_from              = None            # per message (MAIL FROM)
        self.punished               = False           # per message
        self.mta_code               = -1              # global
        self.mta_short              = None            # global
        self.mta_reason             = None            # global
        self.reasons                = []              # per message
        self.email_msg              = None            # per message

        if not abort:
            self.client_address     = None            # global
            self.client_port        = None            # global
            self.hostname           = None            # global

        # these are ONLY changed at the very beginning and very end of the SMTP conversation and will maintain state
        # across all inner conversation phases
        if initall:
            self.helo               = []              # global
            self.penalties          = []              # global and per message, needs split up
            self.dfw_penalty        = 0               # global and per message, needs split up
            self.abort_count        = 0               # global
            self.failed_rcptto      = 0               # per message

            # record log statements in memory until our logname has a qid then we'll open a logfile on disk and flush
            # our memory backed log to file
            if not self.iolog:
                self.iolog          = io.StringIO()   # global (does postfix give multiple queue ids, one per msg?)
            self.logname            = None            # global

        if initall or (self.has_aborted and not self.mailfrom_tried):
            self.do_db_store        = True            # global
            self.starttls           = False           # global
            self.short_circuit      = False           # global
            self.authenticated      = False           # global
            self.whitelisted        = False           # per message
            self.blacklisted        = False           # per message
            self.spf_authorized     = False           # per message
            self.in_dnsbl           = False           # per message

            # store across resets
            self.stored_payload     = b''             # per message

            # state trackers for spam triggers, don't erase these on multi-email transactions. once a bad guy, always a bad guy
            # yes, this might hurt innocent guys...hmm. reset these after the headers are added on an email?
            self.greetings          = {}              # deprecated
            self.was_kicked         = False           # global
            self.early_punish       = False           # global
            self.left_early         = True            # global
            self.last_qid           = ''              # possibly per message if multi message

        self.processed_headers      = False           # per message
        self._datetime              = datetime.datetime.utcnow() # global

        self.payload                = b''             # per message
        self.getting_body           = False           # is this needed?
        self.quit_location          = None            # global
        self.quit_shorttext         = None            # is this used?
        self.android_mail_client    = False           # is this needed?


    def print_sep(self):
        global last_st

        if not last_st == self.st:
            self.logger.info('{}{}┤{}'.format('─'*16,ansi['bwhite'],ansi['none']), extra={'src':'', 'port':''})
        last_st = self.st


    def printme(self, data, level=logging.INFO, console=False):
        if self.unittest:
            console = True

        # get caller's python filename
        _blam = inspect.stack()[1].filename == __file__
        #_st = ('','')
        _st = self.st
        #if not _blam:
        #    _st = self.st
        #    del self.st

        printed=False
        if console:
            if _blam:
                self.print_sep()
            try:
                self.logger.log(level, data)
                printed=True
            except:
                print('is level fucked? data={} {}={!r}'.format(data, type(level),level))

        try:

            if self.iolog:
                self.iolog.write('{} {}:{} {}\n'.format(datetime.datetime.utcnow().strftime('%F %T'), _st[0], _st[1], data))
            elif self.logname:
                self.logname.write('{} {}:{} {}\n'.format(datetime.datetime.utcnow().strftime('%F %T'), _st[0], _st[1], data))
            elif not printed: # don't print to console 2x
                # we may print messages from dfw or cams and there's no logfile for this
                # we need to scour code and make a programatic way to validate this before ignoring this msg
                if _blam:
                    self.logger.log(logging.ERROR, '\x1b[1;31m### no iolog or logname! ###\x1b[0m')
                    self.logger.log(logging.ERROR, inspect.stack()[1])
                self.logger.log(logging.ERROR, data)
        except ValueError: # happens on closed logfiles
            pass
        except Exception as e:
            print(e.__class__)
            print(e.__class__.__name__)
            print(e)
            traceback.print_exc(limit=5)

        #if not _blam:
        #    self.st = _st


    def cams_notify(self, msg):
        if self.cams:
            try:
                self.cams.notify(msg)
            except:
                t,v,tb = sys.exc_info()
                self.printme('failed cams notify: {}'.format(v), level=logging.WARNING)
        elif not self.unittest:
            self.printme('No CAMS instance?', console=True)


    def print_as_pairs(self, pairs, bkeys=None, indention=4, console=False):
        for k in sorted(pairs):
            if isinstance(pairs, dict):
                v = pairs[k]
            else:
                k,v = k
            _cp  = (bkeys and k in bkeys) and ansi['bwhite'] or ansi['bblack']
            _ind = ' '*indention
            _f   = _ind+' {}{:<20.20} {}'.format(_cp, k, v)+ansi['none']
            self.printme (_f, console=console)


    def mod_dfw_score(self, value=0, reason='', resetto=None, ensure_positive_penalty=False):
        old = self.dfw_penalty

        if ensure_positive_penalty:
            # this is set when we insist on penalizing to a certain value, for example
            # when SPF is valid but we need to penalize to grace_score because of the use
            # of a poisoned address
            if self.dfw_penalty < 0:
                self.dfw_penalty = 0
            self.dfw_penalty += value

        else:
            if not resetto is None:
                self.dfw_penalty = resetto
            else:
                self.dfw_penalty += value

        self.dfw_penalty = round(self.dfw_penalty, 2)

        if not old == self.dfw_penalty:
            if reason:
                if value > 0:
                    self.penalties.append(reason)
                reason = ': ' + reason
            self.printme('DFW score {:>6.2f} \u21e8 {:>6.2f}{}'.format(old, self.dfw_penalty, reason), console=True)


    def db_store(self):
        # this gets called on each Abort(), we do so intentionally so we store any changed macros, headers, etc

        self.db.check_notified()
        with self.db.conn.cursor() as c:
            # check for notifications before trampling them

            ts_milter = '{b}' in self.macros and self.macros['{b}'] or self._datetime
            qid       = '{i}' in self.macros and self.macros['{i}'] or ''

            (code,short,reason) = self.getFinis()
            if not code:
                code = -1
            if not short:
                short = ''
            if not reason:
                reason = ''
            reason.replace('\033[31m☠\033[0m ', '')

            if self.client_address.startswith('IPv6:'):
                address = self.client_address[5:]
            else:
                address = self.client_address

            # delete "xxx" from the _from
            if self._from:
                try:
                    x = re.search('<([\w\d._+-]+@[\w\d._+-]+)>', self._from).group(1)
                except:
                    x = self._from
                self._from = x.lstrip().rstrip().rstrip('>').lstrip('<')

            # this needs to store both MAIL FROM and From
            stats = {'ts_now':self._datetime, 'ts_milter':ts_milter, 'qid':qid, 'ip':address, 'helo':str(self.helo), 'quitcode':code, 'quitshort':short, 'quitreason':reason, 'quitlocation':self.quit_location, 'recipients':self.recipients, 'mail_from':self.mail_from}
            macros = [ [self._datetime,x[0],x[1]] for x in self.macros.items() ]
            headers = [ [self._datetime,x[0],x[1]] for x in self.headers ]

            '''
            ( $1::timestamp,
              $2::text::timestamp,
              $3::text,
              $4::text::inet,
              $5::text,
              $6::int,
              $7::text,
              $8::text,
              $9::text,
              $10::text[],
              $11::text)

              cols = 'ts_now,ts_milter,qid,ip,helo,quitcode,quitshort,quitreason,quitlocation,recipients,mail_from'
            '''

            c.execute('''EXECUTE insert_stats
                (
                %(ts_now)s,
                %(ts_milter)s,
                %(qid)s,
                %(ip)s,
                %(helo)s,
                %(quitcode)s,
                %(quitshort)s,
                %(quitreason)s,
                %(quitlocation)s,
                %(recipients)s,
                %(mail_from)s
                )''', stats)

            for row in macros:
                c.execute('EXECUTE insert_macros (%s,%s,%s)', row)

            for row in headers:
                c.execute('EXECUTE insert_headers (%s,%s,%s)', row)

            self.printme('all records stored in DB', logging.DEBUG)


    def check_dns(self, hostname):
        # only allow these characters in a hostname, no shell privs for you!
        match = re.match('\[?([\d\w_.-]+)\]?', hostname)
        if match and match.group(1) == 'IPv6':
            match = re.match('\[?IPv6:([\dabcdef:]+)\]?', hostname, flags=re.I)

        try:
            answers = self.resolver.query(hostname, 'A')
            for a in sorted([str(a) for a in answers], key=socket.inet_aton):
                self.printme('  A: {}'.format(a), logging.DEBUG)
            return True
        except Exception as e:
            self.printme('failed to resolve A records: {}'.format(e), console=True)

        self.printme(ansi['byellow']+'  No A records'+ansi['none'])
        return None


    def check_dnsbl_by_ip(self, addr):
        reasons = { '127.0.0.2':'Static UBE sources, verified spam services (hosting or support) and ROKSO spammers',
                    '127.0.0.3':'Static UBE sources, verified spam services (hosting or support) and ROKSO spammers',
                    '127.0.0.4':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.5':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.6':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.7':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.8':'',
                    '127.0.0.9':'',
                    '127.0.0.10':'IP ranges which should not be delivering unauthenticated SMTP email',
                    '127.0.0.11':'IP ranges which should not be delivering unauthenticated SMTP email',
                    '127.0.1.0':'Spamhaus Domain Blocklist',
                  }

        addr = str(dns.reversename.from_address(addr)).replace('.in-addr.arpa.','')
        self.printme('query by ip for {}'.format(addr))
        response = []
        answers=[]

        for svc in ('zen.spamhaus.org','bb.barracudacentral.org'):
            q = addr + '.' + svc
            try:
                answers = self.resolver.query(q, 'A')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout): pass
            except Exception as e: self.printme('DNSBL/ip; problem resolving {}: {}'.format(q, e), console=True)

            for answer in answers:
                if answer.address in reasons:
                    if not reasons[answer.address] in response:
                        response.append(reasons[answer.address])

        if response:
            self.printme('target found in DNSBL: {}'.format(response))
            self.in_dnsbl = True
            return response

        return False


    def check_dnsbl_by_name(self, addr):
        reasons = { '127.0.0.2':'Static UBE sources, verified spam services (hosting or support) and ROKSO spammers',
                    '127.0.0.3':'Static UBE sources, verified spam services (hosting or support) and ROKSO spammers',
                    '127.0.0.4':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.5':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.6':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.7':'Illegal 3rd party exploits, including proxies, worms and trojan exploits',
                    '127.0.0.8':'',
                    '127.0.0.9':'',
                    '127.0.0.10':'IP ranges which should not be delivering unauthenticated SMTP email',
                    '127.0.0.11':'IP ranges which should not be delivering unauthenticated SMTP email',
                    '127.0.1.0':'Spamhaus Domain Blocklist',
                  }

        # see if we got an IP, [1.2.3.4] or [IPv6:xx:xx:...]
        if addr[0]=='[' and addr[1]==']':
            try:
                addr=addr[1:-1]
                if addr[:5].lower() == 'ipv6:':
                    addr = addr[:5]
                netaddr.IPAddress(addr)
                return self.check_dnsbl_by_ip(addr)
            except:
                pass

        q = addr + '.zen.spamhaus.org.'
        self.printme('query by name for {}'.format(q))
        response = []
        answers=[]

        try:
            answers = self.resolver.query(q, 'A')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout): pass
        except Exception as e: self.printme('DNSBL/host; problem resolving {}: {}'.format(q, e), console=True)

        for answer in answers:
            if answer.address in reasons:
                if not reasons[answer.address] in response:
                    response.append(reasons[answer.address])

        if response:
            self.printme('target found in DNSBL: {}'.format(response))
            self.in_dnsbl = True
            return response

        return False


    def check_mx(self, hostname):
        # sanitize, strip off trailing dot
        hostname = hostname.strip('.[]<>')

        # only allow valid hostnames (we allow "_" in the hostname even though RFC forbids it simply because
        # it has become rather common)
        m = re.match('.*?([\w\d_.-]+)$', hostname, flags=re.I)
        if m is None:
            return

        hostname = m.group(1)

        parts = hostname.split('.')
        if len(parts) == 1:
            # unfortunately there are a lot of non-RFC compliant mail servers on the internet
            # so we penalize them lightly here.
            self.mod_dfw_score(1, 'MX: invalid hostname, 1 part only')
            return

        tld = parts[-1:][0]
        if self.test_tld(tld) is False:
            self.mod_dfw_score(1, 'TLD test failed in check_mx()')
            return

        # whittle down the hostname until we have domain.com that has an MX record
        hostparts = hostname.split('.')
        while True:
            find = '.'.join(hostparts)
            self.printme('reduce and check_mx({})'.format(find))
            try:
                answers = self.resolver.query(find, 'MX')
                for a in sorted([str(a) for a in answers]):
                    self.printme('  MX: {}'.format(a), logging.DEBUG)
                return True
            except:
                pass

            hostparts = hostparts[1:]
            if not len(hostparts) > 1:
                break

        # an MX record is not strictly required for an SMTP server but we have found that an amazing
        # amount of spam can be blocked simply by the lack of the sender having an MX record
        # don't penalize too much because the assumed default MX for a host or IP, is itself
        #
        # penalty should be applied by the caller
        return None


    def test_tld(self, tld):
        if not tld: # i don't really ever expect this to be true
            self.printme('tld is empty', logging.ERROR, console=True)
            return False

        if not self.tlds:
            self.printme('tld set is empty', logging.ERROR, console=True)
            return

        tlds = self.tlds
        tld = tld.lower().strip('<> ')

        if tld in tlds:
            #self.printme('TLD(.{}) is legit'.format(tld))
            return

        return False


    def OnMacros(self, cmd, macro, data):
        #ppymilter.base._print_as_pairs(data, indention=16)
        self.quit_location = 'OnMacros'
        self.last_active = datetime.datetime.utcnow()

        d={}
        if len(data):
            d = dict(zip(data[::2], data[1::2]))
            dkeys = sorted(d)
            nmacros = 0
            for k in dkeys:
                if not k in self.macros:
                    nmacros += 1
                if k in self.macros and not self.macros[k] == d[k]:
                    nmacros += 1
                self.macros[k] = d[k]

                if k == 'i' and not self.logname:
                    _ = os.path.join('/var/spool/blam/logfiles', d[k])
                    self.printme('switching iolog stream to {}'.format(_), console=True)
                    self.logname = open(_, 'a', encoding='utf-8')
                    self.logname.write(self.iolog.getvalue())
                    self.iolog.close()
                    self.iolog = None

                if k == '{tls_version}':
                    self.starttls = True
                    # reset dfw penalty to zero, this should occur at the start of an smtp transaction
                    # so if something is still shit, we'll catch it again
                    self.mod_dfw_score(resetto=0, reason='TLS session initiating a new SMTP conversation')

            #self.printme ('M({}) {}'.format(ppymilter.base.MACRO_WHENCE[macro], d))
            self.printme('#MACROS#  [{!r}//{!r}]  {!r}'.format(cmd,macro,d), level=logging.DEBUG)

            if nmacros:
                self.print_as_pairs(self.macros, bkeys=dkeys)

        self.db.check_notified()


    def OnData(self, cmd, data):
        self.printme ('Data({})'.format(data), logging.DEBUG)
        self.quit_location = 'OnData'
        return self.Continue()


    def OnConnect(self, cmd, hostname, family, port, address):
        # this needs to be stored in a memory backed DB, not a global variable
        # this is to track IPs across sessions, that repeatedly attempt to email
        # unknown local users
        global unknown_local_attempts

        self.printme('Connect ▶ {host}, {ip}:{port}'.format(host=hostname, port=port, ip=address), console=True)

        if hostname==None and port==None and address==None:
            return

        self.quit_location = 'OnConnect'
        self.hostname = hostname

        self.client_address  = address
        self.client_port     = port

        now = time.time()

        # once DFW is rolled across the board, this is will be removed. it currently serves only to block MTAs on servers that aren't
        # enforcing DFW and for servers that have a module limit of 100 entries in xt_recent
        _ = self.dfw.forgive_when(self.client_address)
        if _:
            if self.hostname:
                h = self.hostname
                if self.hostname.strip('[]') != self.client_address:
                    h += ' (' + self.client_address + ')'
            else:
                h = self.client_address
            self.printme(ansi['bred']+'{} Firewalled'.format(h)+ansi['none']+', releasing at: {}Z'.format(_.strftime('%F %T')), console=True)
            #self.cams_notify ('{} \x1d\x02\x0307Firewalled\x0f, releasing at: {}Z'.format(h, _.strftime('%F %T')))

            # early quit
            self.early_punish = True # we're not really punishing, we're just telling our quit() routine to not act on the early quit
            return self.CustomReply(421, '4.7.1 Firewalled due to one of: a) spam, b) unauthorized activity,'
                ' c) repeat attempts with invalid DNS, d) repeat invalid SMTP. Firewall will release you at: {}Z'.format(_), '4.7.1')

        if not address in unknown_local_attempts:
            unknown_local_attempts[address] = {'ts':now, 'count':0}

        #else:
        #    # purge olders
        #    unknown_local_attempts = {k:v for v in unknown_local_attempts.items() if v['ts'] < now-60 }

        if unknown_local_attempts[address]['count'] > 3:
            self.printme('{} Emailing too many unknown users ({})'.format(self.client_address,len(unknown_local_attempts[address])), console=True)
            self.mod_dfw_score(self.dfw.grace_score +1, 'too many unknown recipients', ensure_positive_penalty=True)
            return self.CustomReply(550, '5.5.2 You have attempted to email too many unknown users', '5.5.2')

        return self.Continue()


    def _resolve_mx_host_to_ip(self, host):
        answers = []
        __mxh   = []
        try:
            # get all the MX hostnames
            __mxh = self.resolver.query(host, 'MX')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout): pass
        except Exception as e: self.printme('problem in MX resolution of {}: {}'.format(host, e), console=True)

        self.printme('MX lookup answers are: {}'.format([str(a) for a in __mxh]))

        # add all the IPs of all hostnames found for MX into the answers list
        for __rdtype in ('A', 'AAAA'):
            for __rdata in __mxh:
                try:
                    for z in self.resolver.query(__rdata.exchange.to_text(), __rdtype):
                        answers.append(z.address)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout): pass
                except Exception as e: self.printme('resolve mx; problem resolving {} on {}: {}'.format(__rdtype,__rdata.exchange.to_text(),e), console=True)

        self.printme('IPs of MX({}) are: {}'.format(host, answers))

        return answers


    def _resolve_a_host_to_ip(self, host):
        answers=[]
        for __rdtype in ('A', 'AAAA'):
            try:
                for z in self.resolver.query(host, __rdtype):
                    answers.append(z.address)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception as e:
                self.printme('problem1 in {} resolution of {}: {}'.format(__rdtype,host,e), console=True)

        self.printme('A/AAAA records found for {} are: {}'.format(host, answers))
        return answers


    def _resolve_ptr_ip_to_host(self, ip):
        __rdata=[]
        try:
            __rdata = [str(x) for x in self.resolver.query(dns.reversename.from_address(ip), 'PTR')]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass

        except Exception as e:
            self.printme('problem2 in {} resolution of {}: {}'.format('PTR',ip,e), console=True)

        self.printme('resolved {} to {}'.format(ip, __rdata))
        return __rdata


    def OnHelo(self, cmd, helo):
        #self.printme('#HELO#')
        if self.helo:
            if helo in self.helo:
                # need a way to identify starttls and not print out this message if so
                if not self.starttls:
                    self.printme('{}:{} said this HELO already: {}, STARTTLS or bot?'.format(self.client_address, self.client_port, helo), console=True)
            else:
                self.printme('{}:{} said HELO again (STARTTLS={}), but different this time: {}'.format(self.client_address, self.client_port, self.starttls, helo), console=True)
        else:
            self.printme ('HELO ▶ {}'.format(helo), console=True)

        self.quit_location = 'OnHelo'
        self.helo.append(helo)
        return self.Continue()


    def OnMailFrom(self, cmd, mail_from, esmtp_info):
        #self.try_short_circuit()
        self.quit_location = 'OnMailFrom'
        self.printme('#MAILFROM#', level=logging.DEBUG)

        # we should have stored per-message stuff in the DB, here is where we should [re]initialize
        # per-message self.* values as multiple MAIL-FROM ... END-BODY cycles can occur
        if self.quit_location == 'OnEndBody':
            self.printme('multiple message deliveries being attempted, we need to handle this!', console=True)

        # as soon as we see a MAIL FROM statement, indicate a transaction has been attempted. on RSET, we'll
        # check this as some mailers do an RSET before QUIT which used to wipe out authenticated/whitelisted
        # information. now we test for this situation and don't wipe those flags
        self.mailfrom_tried = True

        # this short circuits the rest of blam
        if '{auth_authen}' in self.macros:
            self.printme(ansi['bgreen']+'{} authenticated with {}'.format(self.macros['{auth_authen}'], self.macros['{auth_type}'])+ansi['none'], console=True)
            self.actions.append(self.AddHeader('X-Authenticated-BlueLabs','{} authenticated to send mail'.format(self.macros['{auth_authen}'])))
            self.authenticated = True

        # this should already be done by the MTA in macro {mail_addr}, no?
        mfrom = self.macros['{mail_addr}']
        if '@' in mfrom:
            mfrom = mfrom.split('@',1)

            '''
            # handle the lesser used form of 'anbceyv@fibertel.com.ar(Modelos De Contratos Listos Para Usar)'
            if '(' in mfrom:
                mfrom = re.sub('\([^)]*\)', '', mfrom).strip()

            # quoted parts should also be removed
            if '"' in mfrom:
                mfrom = re.sub('"[^"]*"', '', mfrom).strip()
            '''

        self.mail_from = mfrom
        self.printme ('Mail From ▶ {}; {}; {}'.format(mfrom,mail_from,esmtp_info), console=True)

        if isinstance(mfrom, list):
            if mfrom[1].lower() in ('itriskltd.com','itys.net'):
                self.printme(ansi['green'] + 'hard whitelisting incoming from = itys.net or itriskltd.com' + ansi['none'], console=True)
                self.whitelisted = True

            if '.' in mfrom[1]:
                inv = mfrom[1].split('.')
                inv = inv[-1:][0]

            # invalid MAIL FROM
            else:
                self.mod_dfw_score(10, 'sender domain invalid')

            # don't do SPF checks on our loved stuff
            if self.whitelisted or self.authenticated or self.client_address == '127.0.0.1':
                return self.Continue()

            if not self.client_address in ('127.0.0.1','10.255.0.2','10.255.0.3','10.255.0.4'):
                try:
                    i=self.client_address
                    if i.startswith('IPv6:'):
                        i = i[5:]
                    s='{}@{}'.format(mfrom[0],mfrom[1])
                    h=self.helo[-1]

                    res = self._spf_check(i,s,h)
                    self.printme('\033[37mSPF result for "MAIL FROM": {}\033[0m'.format(res), level=logging.DEBUG)
                    if res[0] == 'fail':
                        self.mod_dfw_score(self.dfw.grace_score +1, 'SPF designates your IP as a not-permitted source', ensure_positive_penalty=True)
                        return self.Continue()
                    elif res[0] == 'softfail':
                        # discouraged use, penalize
                        self.mod_dfw_score(5, 'SPF designates your IP as a discouraged-use source')
                    elif res[0] == 'pass':
                        if not self.spf_authorized:
                            self.mod_dfw_score(-10, 'SPF designates your IP as a permitted sender')
                        self.spf_authorized = True
                except:
                    t,v,tb = sys.exc_info()
                    self.printme('SPF MAIL FROM broke for: {} @{}: {}'.format(mfrom,esmtp_info,v), level=logging.WARNING, console=True)
                    for _ in traceback.format_stack(limit=15):
                        self.printme('{}'.format(_), console=True)

            if not self.check_mx(mfrom[1]):
                self.printme('no MX record for hostname given in env_mail_from', console=True)
                if not self.check_dns(mfrom[1]):
                    self.mod_dfw_score(10, 'No MX record for domain in env_mail_from')

        return self.Continue()


    ''' make this into a netaddr.IPSet() '''
    def is_bluelabs_ip(self, ip):
        if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if '/' in ip:
                try:
                    ip = ipaddress.ip_network(ip)
                except:
                    ip = ipaddress.ip_address(ip)
            else:
                ip = ipaddress.ip_address(ip)

        self.printme('Looking for {} in my networks'.format(ip), level=logging.DEBUG)

        bluelabs = ( ipaddress.ip_network('128.242.79.0/27'),   # david @office/datacenter
                     ipaddress.ip_network('173.12.76.128/29'),  # david @home
                     ipaddress.ip_network('107.170.82.162/32'), # sea-dragon
                     ipaddress.ip_network('97.107.142.140/32'), # mustang
                     ipaddress.ip_network('24.250.16.144/32'),     # smvfd/engine2
                     ipaddress.ip_network('10.255.0.0/22'),     # bluelabs vpn
                     ipaddress.ip_network('127.0.0.1/32'),      # localhost for a blam client
                   )

        for net in bluelabs:
            if ip in net:
                return True


    def OnRcptTo(self, cmd, rcpt_to, esmtp_info):
        ''' This recipient MUST be either a local user or a virtual user. It cannot be faked
        '''
        #self.try_short_circuit()
        self.quit_location = 'OnRcptTo'
        self.printme('#RCPTTO# {!r} {!r} {!r}'.format(cmd,rcpt_to,esmtp_info), level=logging.DEBUG)

        # short circuit spamassassin redirect
        if self.helo[-1] == 'localhost':
            if '{mail_addr}' in self.macros and self.macros['{mail_addr}'] == 'sa-milt@blue-labs.org':
                if rcpt_to == 'david+flagged-spam@blue-labs.org':
                    self.printme('default accept SA redirect to david+flagged-spam@blue-labs.org')
                    return self.Accept()

        rcpt_hostname = ''
        if '@' in rcpt_to:
            localpart,rcpt_hostname = rcpt_to.split('@')
        else:
            localpart = rcpt_to

        self.printme ('Mail @To ▶ {}@{}, {}'.format(localpart, rcpt_hostname, esmtp_info), console=True)

        if not rcpt_to in self.recipients:
            self.recipients.append(rcpt_to)
            self.stored_recipients.append(rcpt_to)

        for mjh in ('itys.net','itriskltd.com'):
            if rcpt_hostname.lower().endswith(mjh):
                self.printme('\x1b[1;37;42mhardwiring whitelist due to {} in RCPT TO: {}\x1b[0m'.format(mjh,rcpt_to), console=True)
                self.whitelisted = True
                break

        if self.whitelisted or self.authenticated:
            return self.Continue()

        if 'kalifornia.com' in rcpt_hostname.lower():
            self.mod_dfw_score(self.dfw.grace_score +1, 'use of poisoned email address', ensure_positive_penalty=True)

        # we wait until RCPT TO to do checks as this allows the incoming client to have established
        # STARTTLS and authenticate which can allow us to ignore a lot of checks. this will speed up
        # the SMTP conversation for privileged users
        #
        # ignore return values here, we need to do more checks
        _ = self._startup_checks()
        if not _ in (None,'c'):  # if not a default None or a Continue(), then return the response
            return _

        # spammer
        if localpart in self.poison:
            self.mod_dfw_score(self.dfw.grace_score +1, 'poisoned localpart', ensure_positive_penalty=True)
            return self.Continue()

        # get the first word and drop any punctuation, aka localpart+extension -> localpart
        m = re.match('([\w.]+)', localpart)
        if m:
            localpart = m.group(1).lower()

        try:
            uid = pwd.getpwnam(localpart).pw_uid
        except:
            uid = -1

        # i need a list of domains that are mine, dovecot@dovecot.org triggers this :)
        if 0 <= uid < 1000 and (not self.is_bluelabs_ip(self.client_address)) and (not localpart in ('portage','postmaster')) :
            self.mod_dfw_score(self.dfw.grace_score +1, 'email to a system account', ensure_positive_penalty=True)
            return self.Continue()

        pushoff = False
        # limited use domains
        if rcpt_hostname in ('head.org','kalifornia.com','stuph.org','boyland.org'):
            self.printme ('now looking for legit recipient: {}'.format(localpart), logging.DEBUG)
            if not localpart in ('ben','david','stephen','askanipsion','lily','postmaster','webmaster','abuse','security','clock'):
                pushoff = True

        if pushoff:
            global unknown_local_attempts
            unknown_local_attempts[self.client_address]['count'] += 1
            self.mod_dfw_score(self.dfw.grace_score +1, 'email to invalid user', ensure_positive_penalty=True)

        return self.Continue()


    def _startup_checks(self):
        _dnsbl = self.check_dnsbl_by_ip(self.client_address)
        if _dnsbl:
            response = ', '.join(_dnsbl)


            # TODO: need to handle this for bypass mode

            # early quit
            self.mod_dfw_score(self.dfw.grace_score +1, 'DNSBL: {}'.format(response), ensure_positive_penalty=True)
            return self.CustomReply(550, '5.5.2 {}'.format(response), '5.5.2')

        _dnsbl = self.check_dnsbl_by_name(self.hostname)
        if _dnsbl:
            response = ', '.join(_dnsbl)

            # early quit
            self.mod_dfw_score(self.dfw.grace_score +1, 'DNSBL: {}'.format(response), ensure_positive_penalty=True)
            return self.CustomReply(550, '5.5.2 {}'.format(response), '5.5.2')


        helo = self.helo[-1]
        # apply a 0-10 penalty for sessions. 0 for full 256bit, 10 for no encryption
        _no_enc_penalty = 10
        if '{cipher_bits}' in self.macros:
            _cb = int(self.macros.get('{cipher_bits}', '0'))/25.6
            _no_enc_penalty -= _cb
            self.mod_dfw_score(_no_enc_penalty, 'cipher bits strength penalty')

        # fuck off ylmf-pc bot
        if helo == 'ylmf-pc':
            self.mod_dfw_score(self.dfw.grace_score +1, '"ylmf-pc" spam bot', ensure_positive_penalty=True)
            return self.CustomReply(550, '5.5.2 ylmf-pc spam bot', '5.5.2')

        # broken shitty software in Brother printers
        if helo == 'BRNECD487' and self.client_address == '10.255.0.70':
            self.whitelisted = True
            return

        # short circuit approved hosts
        if helo == "localhost" or helo == "localhost.localdomain":
            if self.client_address == '127.0.0.1': # postfix insists on saying "localhost" to the
                return #                    # milter for all command line sent emails

            # this is a permanent error, their MTA is broken. them retrying is useless but we let them
            # continue so we can keep metrics on the IP and content
            self.mod_dfw_score(10, 'using "localhost" HELO; RFC5321 2.3.5')

        # should do a hostname/dns match too, some fuckers fake this
        if helo in self.pre_approved:
            self.whitelisted = True
            self.printme ('pre-approved host')
            return

        # github DNS is considerably broken. most of the outbound mail servers use hostnames that do
        # not resolve to any of the IPs the connection arrives on. unfortunately github email is
        # regarded as important and doubly unfortunate, github admins lack the understanding that proper
        # forward and reverse DNS is important
        if helo.endswith('.github.net'):
            self.printme ('pre-approved host')
            self.whitelisted = True
            return

        # RFC2821 4.1.1.1 indicates a HELLO greeting must be a FQDN or address literal
        # an address literal is an IP address (either ipv4 or ipv6) enclosed in brackets []
        if not '.' in helo and not ':' in helo:
            self.mod_dfw_score(10, 'HELO not an FQDN; RFC5321 2.3.5')

        is_ipv6  = False
        is_ip    = False
        brackets = False

        if re.match('\[(ipv6|)[\da-f:.]+\]$', helo, flags=re.I):
            brackets = True

            # IPv6
            if helo[:6].lower() == '[ipv6:':
                helo = helo[6:-1]
                if re.match('[\da-f:.]+$', helo):
                    is_ipv6 = True

            # remove brackets
            elif re.match('\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]$', helo):
                is_ip = True
                helo=helo[1:-1]

        else:
            # HELO as a raw IP, not encapsulated with brackets?
            if re.match('(?:\d{1,3}\.){3}(?:\d{1,3})$', helo):
                is_ip = True
            elif re.match('ipv6:[a-f\d:]+$', helo, flags=re.I):
                is_ipv6 = True

        if is_ip or is_ipv6:
            if not brackets:
                self.mod_dfw_score(10, 'HELO IP is not bracketed; RFC5321 2.3.5')

            try:
                inaddrarpa = dns.reversename.from_address(helo)
                ptrs = self.resolver.query(inaddrarpa, 'PTR')
                for h in ptrs:
                    self.printme('HELO: resolved: {}'.format(h.to_text()))

            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception as e:
                # this can be temporary so return 451 instead of 501
                self.mod_dfw_score(5, 'HELO greeting unresolvable: {}; RFC5321 2.3.5'.format(e))

            return

        # see if the TLD is valid
        tld = helo.split('.')[-1:][0]

        if self.test_tld(tld) is False:
            self.mod_dfw_score(5, 'HELO has unknown TLD; RFC5321 2.3.5')

        # check dnsbl for self.helo too
        _=None
        v=None
        try:
            v = netaddr.IPAddress(helo)
            if not v in rfc1918:
                _ = self.check_dnsbl_by_ip(helo)
        except:
            _ = self.check_dnsbl_by_name(helo)

        if _:
            _ = 'HELO name in DNSBL ({}): '.format(v) + ', '.join(_)
            self.mod_dfw_score(self.dfw.grace_score+1, '{}'.format(_), ensure_positive_penalty=True)

        # does it resolve? RFC requires HELO greetings MUST resolve to an A record or be an address literal
        # DNS is easy for legit operators, at bluelabs we require an A/AAAA record. the incoming connection address
        # MUST exist in the resolved A/AAAA records or we'll reject it as a forgery

        # verify it's not a CNAME
        try:
            self.resolver.query(helo, 'CNAME')
            self.mod_dfw_score(10, 'HELO is a CNAME; RFC5321 2.3.5')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout): pass
        except Exception as e: self.printme('check helo/cname; problem resolving {} on {}: {}'.format('CNAME',helo,e), console=True)

        # get initial list of IPs this helo's MX record(s) resolve to
        answers  = self._resolve_mx_host_to_ip(helo)
        answers += self._resolve_a_host_to_ip(helo)

        if not answers:
            self.mod_dfw_score(10, 'HELO; no A/AAAA records found; RFC5321 2.3.5')

        # now check that at least one of the IPs we resolved will also reverse resolve to the HELO name given to us
        # if none of the IPs match the HELO name, but the PTR resolved to HELO, it's quite likely it is forged.
        # aka, HELO ▶ abc.com, connection IP is 1.2.3.4 but abc.com only resolves to 9.9.9.9. if 4.3.2.1.in-addr.arpa.
        # resolves to abc.com, then it means the forger has complete control over the affected DNS. we should NOT trust
        # this situation.
        me = self.client_address.startswith('IPv6:') and self.client_address[5:] or self.client_address

        #if not [ x for x in answers if x == me]:
        #    self.mod_dfw_score(10, 'DNS lookup of HELO greeting ({}) is {} and'
        #        ' does not include the IP you came from: {}. See https://blue-labs.org/blocked_mail/index.html'
        #        .format(helo, answers, self.client_address))
        if me in answers:
            return

        PTR_to_hosts = []
        # get the ptr records, turn each of them into hostnames, then look up each of those hostnames for PTR records..do they match me?
        for ip in answers:
            PTR_to_hosts += self._resolve_ptr_ip_to_host(ip)

        if self.helo[-1] in PTR_to_hosts:
            return

        # ok, some sites have some really funky two-evolution chains before resolution is satisfied. whitehouse.gov comes to mind.
        answers2 = []

        # get all the hostnames of the IPs we have so far
        for host in PTR_to_hosts:
            # get all the MX hostnames for this host
            __mxh  = self._resolve_mx_host_to_ip(host)
            __mxh += self._resolve_a_host_to_ip(host)
            self.printme('MX/A/AAAA lookup answers are: {}'.format(__mxh))
            answers2 += __mxh

        #if not answers2:
        #    self.mod_dfw_score(10, 'DNS lookup of HELO greeting ({}) is {} and'
        #        ' does not include the IP you came from: {}. See https://blue-labs.org/blocked_mail/index.html'
        #        .format(helo, answers, self.client_address))

        answers = list(set(answers + answers2))
        if me in answers:
            return

        if not [x for x in answers2 if x == self.helo[-1]]:
            # once again, get all PTR records
            for __ip in answers2:
                __ptrs = self._resolve_ptr_ip_to_host(__ip)
                __rdata = [x for x in __ptrs if not x in PTR_to_hosts]
                if __rdata:
                    self.printme('resolved by 2nd evolution; additional known records: {} to {}'.format(__ip, __rdata), console=True)
                PTR_to_hosts += __rdata

            if helo in PTR_to_hosts:
                return

            # don't we need to now check all these hosts, convert them to PTRs to see if their IP matches 'me'?
            answers3 = []
            for host in PTR_to_hosts:
                answers3 += self._resolve_a_host_to_ip(host)

            answers = list(set(answers + answers3))

        if me in answers:
            return

        answers.sort()

        self.mod_dfw_score(10, 'DNS lookup of HELO greeting ({}) is {} and'
            ' does not include the IP you came from: {}. See https://blue-labs.org/blocked_mail/index.html'
            .format(helo, answers, self.client_address))

        # check dnsbl for mail-from
        # there is no From yet in startup checks
        k,h ='MAIL FROM',self.mail_from
        self.printme('{} is: {}'.format(k,h), console=True)
        if h:
            _=None
            v = h[1]
            if len(v)==2:
                v = v[1]
                try:
                    netaddr.IPAddress(v)
                    if not v in rfc1918:
                        _ = self.check_dnsbl_by_ip(v)
                except:
                    _ = self.check_dnsbl_by_name(v)

                if _:
                    _ = '{}:{} dname in DNSBL ({}): '.format(k,v) + ', '.join(_)
                    self.mod_dfw_score(self.dfw.grace_score+1, _, ensure_positive_penalty=True)


    def _spf_check(self, i, s, h):
        res = None,None,None
        if not i and s and h:
            return res

        try:
            q   = spf.query(i, s, h)
            res = q.check()
            self.printme('spf.query(i={}, s={}, h={}) = {}'.format(i, s, h, res), level=logging.DEBUG)
        except Exception as e:
            self.printme(ansi['bred']+'Failed SPF query for {}, {}, {} because: {}'.format(i, s, h, e)+ansi['none'], console=True)
            traceback.print_exc(8)

        return res


    def _run_header_tests(self):
        headers = []
        relays  = []
        fuckheads = []
        self.printme('running header tests')

        msg = self.email_msg

        # find emails relayed through known spammers
        lhs = 'Received'
        _ = msg.get_all(lhs) or []

        for i,rhs in enumerate(_):
            headers.append( (lhs.lower(),rhs) )
            self.printme ('▶{:20.20} {!r}'.format(lhs+':',rhs), logging.DEBUG)
            rhs = rhs.lower()
            rhs = re.sub('[\\r\\n\\t]', ' ', rhs)

            rehres = ('^from\s+(?P<sender_host>[\w._-]+)\s+\(([\w._-]+)\s+\[(?:IPv6:)?([a-f\d:.]+)\]\)\s+.*?by\s+(?P<receiver>[\w._-]+)',           # standard sendmail/postfix
                      '^from\s+(?P<sender_host>[\w._-]+)\s+\((?:IPv6:)?([a-f\d:.]+)\)\s+by\s+(?P<receiver>[\w._-]+)\s+\((?:IPv6:)?([a-f\d:.]+)\)',  # microsoft
                      '^from\s+(?P<sender_host>[\w._-]+)\s+\((?:IPv6:)?([a-f\d:.]+)\)\s+.*?by\s+(?P<receiver>[\w._-]+)',                            # qmail
                      '^from\s+(?P<sender_host>[\w._-]+)\s+\(helo\s+(?:IPv6:)?([\w._-]+)\)\s+\(([\w._-]+)\)\s+.*?by\s+(?P<receiver>[\w._-]+)',      # qmail
                      '^from\s+(?P<sender_host>[\w._-]+)\s+\(helo\s+([\w._-]+)\)\s+\((?:IPv6:)?\[([a-f\d.]+)\]\)\s+.*?by\s+(?P<receiver>[\w._-]+)', #
                      '^from\s+(?P<sender_host>[\w._-]+)\s+\(\[(?:IPv6:)?([a-f\d:.]+)\]\)\s+by\s+(?P<receiver>[\w._-]+)\s+\([\w._-]+\s+\[(?:IPv6:)?([a-f\d:.]+)\]\)',# amavisd-new
                      '^from\s+(?P<sender_host>[\w._-]+)\s+\(\[(?:IPv6:)?([a-f\d:.]+)\]\)\s+by\s+(?P<receiver>[\w._-]+)',                           #
                      '^from\s+\((?:IPv6:)?(?P<sender_host>[a-f\d:.]+)\)\s+by\s+(?P<receiver>[\w._-]+)',                                            #
                      '^from\s+\[(?:IPv6:)?([a-f\d:.]+)\]\s+\((?P<sender_host>[\w._-]+)\s+\[(?:IPv6:)?([a-f\d:.]+)\]\).*?by\s+(?P<receiver>[\w._-]+)', #postfix
                      '^by\s+(?P<receiver>[\w._-]+)',                                                                                               # google
                      '\(nullmailer pid \d+ invoked by uid \d+\)',
                      '\(qmail \d+ invoked from network\)',
                     )
            m=None
            for rehre in rehres:
                try:
                    m = re.match(rehre, rhs, flags=re.I|re.M|re.S)
                except Exception as e:
                    self.printme('regex error: {}'.format(e))
                    self.printme('failed re: {}'.format(rehre))
                if m:
                    break

            if not m:
                self.printme('unable to re match Received header, please check: {}'.format(rhs), level=logging.WARNING, console=True)
            if m:
                relays = set(m.groupdict().values())
                for v in relays:
                    # another tunable value
                    if not v in ['','unknown','localhost','localhost.localdomain','ranger.blue-labs.org','sea-dragon.blue-labs.org']:
                        _=None
                        try:
                            netaddr.IPAddress(v)
                            if not v in rfc1918:
                                _ = self.check_dnsbl_by_ip(v)
                        except:
                            _ = self.check_dnsbl_by_name(v)

                        if _:
                            _ = 'Relayed through known bad site ({}): '.format(v) + ', '.join(_)
                            self.mod_dfw_score(self.dfw.grace_score+1, '{}'.format(_), ensure_positive_penalty=True)

                        #relays.append(h)

                # tunable, and, we shouldn't really need this - put it into the blacklist
                fuckheads=[]
                for relay in relays:
                    for fuckhead in ['163.net','163data.com.cn','263.net','263xmail.com','bl263.com','bl868.com','bluemilenetworks.net',
                                     'adval.info','auto-quotes.eu','look-gud.eu','oszo.net','hom-solrpnel.eu',
                                    ]:
                        if relay.endswith('.'+fuckhead):
                            fuckheads.append(relay)

                if fuckheads:
                    self.mod_dfw_score(self.dfw.grace_score +1, 'Known malware/spam network: {}'.format(fuckheads), ensure_positive_penalty=True)


        # this test must happen before lowercasing RHS
        headers=[]
        for h in ('return-path','errors-to','sender','list-unsubscribe','message-id','from'):
            hlist = msg.get_all(h)
            if not hlist:
                continue
            for v in hlist:
                headers.append((h,v))

        for lhs,rhs in headers:
            # look for the domain part of a value
            m=re.search('\w+@([\w.]+)\W', rhs)
            if m:
                transitions = 0
                pstate = -1

                for c in m.group(1):
                    if not c in string.ascii_letters:
                        continue
                    if c in string.ascii_lowercase and pstate != 0:
                        transitions += 1
                        pstate = 0
                    elif c in string.ascii_uppercase and pstate != 1:
                        transitions += 1
                        pstate = 1

                if transitions >4:
                    self.mod_dfw_score(transitions, 'case transitions({}): {}: f(1)*{}={}'.format(lhs,m.group(1),transitions,transitions))

        # recode headers
        headers=[]
        for lhs,rhs in [(k,v) for k,v in msg.items() if not k.lower()=='received']:
            try:
                if isinstance(rhs, email.header.Header):
                    rhs = str(rhs)
                elif '=?' in rhs:
                    _rhs = None
                    for encoding in ('utf-8', 'cp1252', 'latin-1', 'ascii'):
                        try:
                            _rhs = ' '.join([ t.decode(e or encoding) for t,e in email.header.decode_header(rhs) ])
                            break
                        except:
                            pass
                    if not _rhs:
                        raise Exception('Could not decode header: {!r}'.format(rhs))
                    rhs = _rhs
            except Exception as e:
                self.printme('erps: {}'.format(e), console=True)
                self.printme('cannot recode: {}: {!r}'.format(lhs, rhs), console=True)
                self.printme('{}'.format( traceback.format_exc(limit=3) ), console=True)

            headers.append( (lhs.lower(),rhs.lower()) )
            self.printme ('▶{:20.20} {!r}'.format(lhs+':',rhs), logging.DEBUG)

        # get a list of recipients in To, CC; if a bunch of similar names to different domains, bounce it
        # aka: 2014-05-27 07:16:34 D 0.0  10.255.0.3:52738 ▶CC:
        '''diana.wilcox@yahoo.com,
         diana.wong@irnrealty.com,diana@4indyhomes.com,diana@92256.net,diana@allestates.com,diana@ambassadororganics.com,
         diana@bciref.com,diana@bellsouth.net,diana@bockenfeldandassociates.com,diana@c21global.com,diana@cadreaming.com,
         diana@carlilawfirm.com,diana@cbcoast.com,diana@cbpreferred.com,diana@century21goldwood.com,
         diana@chaletrealestate.com,
         diana@citygirlsresidential.com,diana@classic1realty.com,diana@classicrealtyindy.com,diana@countryair.com,
         diana@cybersol.com,diana@diana4homes.com,diana@diana7a.com,diana@dianaamos.com,diana@dianaayers.com,
         diana@dianabarker.com,diana@dianacoleman.com,diana@dianacowan.com,diana@dianadunhamsellshomes.com,
         diana@dianaeckstrom.com'''


        # now process the headers

        for lhs,rhs in headers:
            if lhs in ('to','cc'):
                # check for repeat similars
                _ = re.findall('<?([\w._+-]+)@((?:(?:[\w-]+)+\.)+(?:[\w-]+))>?', rhs)

                # count all repeats of localparts where the repeat count is > 3
                lp_rc = [(a,b) for a,b in set([(len([_lp for _lp,_dm in _ if _lp==lp]),lp) for lp,dm in _]) if a>3]

                # and likewise, repeats of domains where the repeat count is > 3
                dm_rc = [(a,b) for a,b in set([(len([_dm for _lp,_dm in _ if _dm==dm]),dm) for lp,dm in _]) if a>3]

                # find list of domains where the localpart is also a part of the domain
                lp_in_dm = [dm for lp,dm in _ if lp in dm]

                # naive search for repeated strings in all parts that aren't TLDs
                _ = re.findall('\w+', rhs)
                _ = [x for x in set([(len([c for c in _ if c==o]),o) for o in _]) if x[0]>4]
                nrs = [(c,w) for c,w in _ if not w in self.tlds]

                if lp_rc:
                    self.printme('found repeat localparts: {}'.format(lp_rc))
                if dm_rc:
                    self.printme('found repeat domains: {}'.format(dm_rc))
                if len(lp_in_dm) > 1:
                        self.printme('found repeat localparts in the domains: {}'.format(lp_in_dm))
                if nrs:
                    self.printme('found repeats of substrings: {}'.format(nrs))

                if lp_rc or dm_rc or nrs or len(lp_in_dm)>1:
                    self.mod_dfw_score(5, 'too many similar recipients found')


            if lhs == 'to':
                if '<<' in rhs or '>>' in rhs:
                    self.mod_dfw_score(5, 'malformed recipient address: {!r}'.format(rhs))

            elif lhs in ('from', 'reply-to'):
                try:
                    rhs_orig = rhs
                    rhs = getaddresses([rhs])[0][1]
                    if lhs == 'from':
                        self._from = rhs
                except:
                    self.printme('Unable to extract addresses from getaddresses([{}])[0][1]'.format(rhs_orig), console=True)
                    continue

                res = self._spf_check(self.client_address, rhs, self.helo)

                if res[0] == 'fail':
                    self.mod_dfw_score(self.dfw.grace_score +1, 'SPF designates your IP as a not-permitted source', ensure_positive_penalty=True)
                elif res[0] == 'softfail':
                    # discouraged use, penalize
                    self.mod_dfw_score(5, 'SPF designates your IP as a discouraged-use source')
                elif res[0] == 'pass':
                    if not self.spf_authorized:
                        self.mod_dfw_score(-10, 'SPF designates your IP as a permitted sender')
                    self.spf_authorized = True

                tld = rhs.split('.')[-1:][0]
                if self.test_tld(tld) is False:
                    self.mod_dfw_score(5, '{} TLD does not exist: {}'.format(lhs,tld))

                m = self.re_from.match(rhs)
                if m:
                    f = m.group(1).split('@', 1)[1].strip('>')
                    if f and len(f) > 0:
                        # check for unresolvable From address
                        try:
                            dns = self.check_dns(f)
                            if dns is None:
                                self.mod_dfw_score(5, 'unresolvable hostname in {}: {}'.format(lhs,f))
                        except Exception as e:
                            self.mod_dfw_score(1, 'exception resolving hostname in {}: {}'.format(lhs,e))

                        # check for lack of MX record for From address
                        mx  = self.check_mx(f)
                        if mx is None:
                            self.mod_dfw_score(5, 'hostname given in From has no MX: {}'.format(f))

            elif lhs == "subject":
                if re.match('fw:re:.*\s\(id:[^)]+\)$', rhs):
                    self.mod_dfw_score(self.dfw.grace_score +1, 'spam Subject', ensure_positive_penalty=True)

                if re.search(r'\b<?adv>?\b', rhs, flags=re.I):
                    self.mod_dfw_score(self.dfw.grace_score +1, 'spam Subject', ensure_positive_penalty=True)

            elif lhs == 'message-id':
                if '@mail.android.com' in rhs:
                    self.android_mail_client = True

            elif lhs in ('x-spam-flag',):
                if rhs=='yes':
                    self.mod_dfw_score(self.dfw.grace_score +1, 'upstream indicates spam detected', ensure_positive_penalty=True)

            # spam blasters
            for keyword in ('x-mnb-', 'x-emv-', 'x-ems'): # x-streamsend and x-campaign temporarily removed due to legit uses
                if re.match(keyword, lhs, flags=re.I):
                    self.mod_dfw_score(5, 'spam blaster')

            # cumulative
            if not lhs in ('dkim-signature','list-unsubscribe'):
                for keyword,score in spam_dict.items():
                    m = re.findall(r'\b'+keyword+r'\b', rhs, flags=re.I)
                    if not m:
                        m = re.findall(r'\W'+keyword+r'\W', rhs, flags=re.I)
                    if m:
                        self.mod_dfw_score(len(m)*score, 'header({}) spamword({}) f({})*{}={}'.format(lhs, keyword, score, len(m), len(m)*score))

            # xxx-xxxx random letters headers
            if re.fullmatch('\w{2,4}[_-]\w{2,6}', lhs):
                if not lhs.split('-')[0] in ('list','user','app'):
                    self.mod_dfw_score(10, 'xxx-xxxx header:{} f(10)*1=10'.format(lhs))


    def _run_white_blacklist_checks(self):
        if not self.db or not self.db.prefs:
            return

        # run the white/blacklist checks
        db = self.db

        try:
            # check blacklists/whitelists for email addresses
            envfrom = self.macros['{mail_addr}']
            rcptto  = self.recipients

            # add de-virtualized recipient
            if not self.macros['{rcpt_addr}'] in rcptto:
                rcptto.append(self.macros['{rcpt_addr}'])

            # sort and make unique
            rcpttos = set(rcptto + [ x.split('@')[0] for x in rcptto ])

            # whitelist first
            self.printme('checking whitelists')

            try:
                x = getaddresses([self._from])[0][1]
            except:
                x = None

            # allow Reply-To to be used as _From such as when a 3rd party payment processor
            # operates on behalf of a whitelisted entity
            _f = sorted(set([y for y in {envfrom, x} if y]))
            if 'Reply-To' in self.headers:
                _f += self.headers['Reply-To']

            # track this in case it's a virtual address
            try:
                localpart = localpart,domain = self.macros['{rcpt_addr}'].split('@',1)
                localuser = localpart.split('+',1)[0]
            except:
                self.printme('**************************** wtf, \033[1;31m{}\033[0m no splitty on @ or +'.format(self.macros['{rcpt_addr}']))
                localuser = localpart = self.macros['{rcpt_addr}']


            # get the local username(s) of the {rcpt_addr}
            localusers = []
            _ = get_local_username(self.macros['{rcpt_addr}'])
            if _:
                localusers += _

            self.printme ('from:       {}'.format(_f), logging.INFO)
            self.printme ('to:         {}'.format(rcpttos), logging.INFO)
            self.printme ('localpart:  {}'.format(localpart), logging.INFO)
            self.printme ('localuser:  {}'.format(localuser), logging.INFO)
            self.printme ('localusers: {}'.format(localusers), logging.INFO)

            _tocheck = [self.macros['{rcpt_addr}']]
            if localpart not in _tocheck:
                _tocheck.append(localpart)
            if localuser not in _tocheck:
                _tocheck.append(localuser)

            # check whitelists
            self.whitelisted,why = check_wblist(self.printme, db.prefs, localusers, _tocheck, 'whitelist_to')

            if not self.whitelisted:
                for tbl in ('whitelist_auth', 'whitelist_from', 'whitelist'):
                    self.whitelisted,why = check_wblist(self.printme, db.prefs, localusers, _f, tbl)
                    if self.whitelisted:
                        break

            if self.whitelisted:
                self.printme (ansi['green'] +'Email whitelisted: {username}({matchtype}) "{original_rule}"'.format(**why)+ansi['none'], console=True)
                self.actions.append(self.AddHeader('X-Blam-Whitelisted', 'TEMPORARILY whitelisted this email'))
                self.actions.append(self.AddHeader('X-Blam-why-whitelisted', str(why)))
                return

            # check blacklists
            self.blacklisted,why = check_wblist(self.printme, db.prefs, localusers, _tocheck, 'blacklist_to')

            if not self.blacklisted:
                for tbl in ('blacklist_from', 'blacklist'):
                    self.blacklisted,why = check_wblist(self.printme, db.prefs, localusers, _f, tbl)

            if self.blacklisted:
                self.mod_dfw_score(self.dfw.grace_score +1, 'blacklisted', ensure_positive_penalty=True)
                # authenticated users won't actually be blocked
                if self.authenticated:
                    self.printme('blacklisted, but overridden by authentication')
                    self.actions.append(self.AddHeader('X-Blam-Notice', "Your email would normally be rejected, here's why; blacklist rule: {}".format(why)))
                    return

        except Exception as e:
            self.printme('Exception: {}'.format(e), logging.ERROR, console=True)
            self.printme('{}'.format(traceback.format_exc(limit=5), console=True))


    def _run_body_tests(self):
        msg = self.email_msg

        for part in msg.walk():
            self.printme('checking body; {}/{}'.format(part.get_content_maintype(), part.get_content_subtype()))
            if part.get_content_maintype() == 'multipart':
                continue

            if part.get_content_maintype() == 'application':
                if part.get_content_subtype() in ('pgp-encrypted',):
                    continue

            try:
                body = part.get_payload(decode=True)
            except Exception as e:
                self.printme('Unable to decode body: {}'.format(e), console=True)
                body = part.get_payload(decode=False)

            if body is None:
                self.printme("body was None, skipping tests")
                continue

            self.printme('body size: {} bytes'.format(len(body)))

            # keyword tests if plain or html
            if part.get_content_maintype() == 'text':
                if isinstance(body, bytes):
                    try:
                        body = body.decode('utf-8')
                    except:
                        body = body.decode('latin-1')

                if part.get_content_subtype() in ('plain','html'):
                    # HTML tests
                    if part.get_content_subtype() == 'html':
                        # split css and body
                        soup = BeautifulSoup(body, 'html.parser')
                        # this is the HTML <BODY> element. we don't want to search
                        if not soup.body:
                            self.printme('text/html part has no body?\n{!r}'.format(body))
                        else:
                            #_body        = soup.body.decode()
                            try:
                                _xmldoc  = etree.HTML(body)
                            except:
                                tmp_body = body.encode('utf-8')
                                _xmldoc  = etree.HTML(tmp_body)

                            _stylesheets = [cssutils.parseString(e.text) for e in _xmldoc.getroottree().findall('//style')
                                                if 'type' in e.attrib
                                                    and e.attrib['type']=='text/css'
                                                    and e.text]
                            _texts       = set([z.replace('\n',' ')
                                                for e in _xmldoc.find('body').xpath('.//*')
                                                for z in e.itertext()
                                                    if not e.tag in ('head','style')
                                                        and z.replace('\n',' ').strip(' ')])

                            # imgs, hrefs, frame sources etc, returns a list of dictionaries
                            _extlinks    = [e.attrib for e in _xmldoc.find('body').xpath('.//*')
                                                if 'href' in e.attrib or 'src' in e.attrib ]

                            _elements    = [e for e in soup.body.findAll() if not e.name == 'style']

                            _checked = []
                            for e in _extlinks:
                                hw = 1
                                for trg in ('height','width'):
                                    if trg in e:
                                        try:
                                            _ = int(e[trg],10)
                                            hw += _
                                        except: #can't handle it right now
                                            pass

                                if 1< hw <5:
                                    self.mod_dfw_score(2, 'web bug found in {}'.format(e))

                                for attr in ('href','src'):
                                    if attr in e:
                                        break

                                m= re.match('\"?(?:(?:https?:)?(?://)|mailto:[^@]+@)?([\w._-]+)', e[attr])
                                if not m and not e[attr] == '#':
                                    self.printme("didn't match an expected hostname in an expected URI: {}".format(e), level=logging.WARNING, console=True)
                                if m:
                                    v = m.group(1)
                                    if v in _checked:
                                        continue

                                    _checked.append(v)
                                    self.printme('extracted hostname: {}'.format(v))

                                    # we should check for case transitions in the hostname

                                    # do dnsbl lookup
                                    _=None
                                    try:
                                        netaddr.IPAddress(v)
                                        if not v in rfc1918:
                                            _ = self.check_dnsbl_by_ip(v)
                                    except:
                                        _ = self.check_dnsbl_by_name(v)

                                    if _:
                                        _ = 'Relayed through known bad site ({}): '.format(v) + ', '.join(_)
                                        self.mod_dfw_score(self.dfw.grace_score+1, '{}'.format(_), ensure_positive_penalty=True)



                            self.printme('CSS style sheets found: {}'.format(len(_stylesheets)))
                            self.printme('Text segments found:    {}'.format(len(_texts)))
                            self.printme('Elements found:         {}'.format(len(_elements)))

                            # applies only to element selection
                            # dead CSS selectors
                            _cssrules     = []
                            _cssselectors = []
                            _csscomments  = []
                            for sheet in _stylesheets:
                                for rule in sheet:
                                    if rule.type == rule.COMMENT:
                                        _csscomments.append(rule)
                                    elif rule.type == rule.STYLE_RULE:
                                        # some comments are embedded in the style declaration
                                        _c = [x for x in rule._style.children() if
                                            hasattr(x, 'type')
                                            and x.type == x.COMMENT]
                                        _csscomments += _c

                                        #rule._setSelectorText(re.sub(':[\w_-]+','', rule.selectorText))
                                        if not rule.selectorText in _cssselectors:
                                          _cssrules.append(rule)
                                          _cssselectors.append(rule.selectorText)

                            self.printme('CSS Rules found:        {}'.format(len(_cssrules)))
                            self.printme('CSS Comments found:     {}'.format(len(_csscomments)))
                            for c in _csscomments:
                                if len(c.cssText) > 200:
                                    __c = len(c.cssText)
                                    self.mod_dfw_score(__c*.008, 'Long comment in CSS: f(.008)*{}={}'.format(__c,__c*.008))

                            matches = {False:0, True:0}
                            for rule in _cssrules:
                              for selector in rule.selectorList:
                                try:
                                    cssselector = CSSSelector(selector.selectorText)
                                    matches[len(cssselector.evaluate(_xmldoc))>0] += 1
                                except: # there are a few conditions such as pseudo elements, that cssutils doesn't support
                                    pass

                            if matches[True] + matches[False]:
                                fr = matches[True] and matches[True] or 1 # don't divide by zero :)
                                nfr = matches[False] / fr
                                if nfr > 5:
                                    self.mod_dfw_score(nfr, 'dead html selectors: {}'.format(matches))

                            # excessive use of html entity encoding
                            # applies to visual text
                            _pattern = '&#x[a-f\d]{4};'
                            for _t in _texts:
                                _ = re.findall(_pattern, _t, flags=re.I)
                                __ = re.sub(_pattern, lambda m: html.unescape(m.group(0)), _t, flags=re.I)

                                if len(_) > 20:
                                    self.mod_dfw_score(len(_)*.5, 'excessive html entities')
                                    self.printme('decoded excessive html entity string: {}'.format(__))

                                # find hashes
                                # applies to visual text
                                for ht in {'[\da-f]{32}',}:
                                    _ = re.findall(ht, _t)
                                    if _:
                                        self.mod_dfw_score(len(_)*.95, 'body contains hashes')

                            # particular URL patterns
                            # applies to visual text and HREF elements
                            burls={}
                            for _url in _extlinks:
                                link = ('href' in _url and 'href') or ('src' in _url and 'src') or None
                                if not link:
                                    self.printme('href/src unexpectedly not in element: {}'.format(_url), console=True)
                                    continue
                                if not '~' in _url[link]:
                                    continue
                                if not len(_url[link].split('~')) > 2:
                                    continue
                                if not _url[link] in burls:
                                    burls[_url[link]] = 0
                                burls[_url[link]] += 1

                            for _url in sorted(burls):
                                _c = len(burls[_url])
                                self.mod_dfw_score(3*_c, 'url pattern foo1~...~fooN; f({}})*{}={} occurs {} times: {}'.format(3, _c, 3*_c, _url))

                            # applies to visual text
                            for _part in _texts:
                                for keyword,score in spam_dict.items():
                                    m = re.findall(r'\b'+keyword+r'\b', _part, flags=re.I)
                                    if m:
                                        self.mod_dfw_score(len(m)*score, '{}: f({})*{}={}'.format(keyword.replace('%','%%'), score, len(m), len(m)*score))

                                # spaced out characters
                                _c = len(re.findall('\w\s{3,40}', _part))
                                if _c > 5:
                                    self.mod_dfw_score(_c, 'spaced out chars: f({})={}*{}'.format(1, _c, _c))

                    else:
                        # repeat some of the tests found in html section
                        burl_list = []
                        for url in re.findall('a href="([^"]+)"', body):
                            _l = len(url.split('~'))
                            if _l > 2:
                                burl_list.append(_l)
                        if burl_list:
                            __ = sorted(set(burl_list))
                            for _url in __:
                                _c = len([x for x in burl_list if x == _url])
                                self.mod_dfw_score(3*_c, 'url pattern foo1~...~fooN occurs {} times: {}'.format(_c, _url))

                        # applies to visual text
                        for keyword,score in spam_dict.items():
                            m = re.findall(r'\b'+keyword+r'\b', body, flags=re.I)
                            if m:
                                self.mod_dfw_score(len(m)*score, '{}: f({})*{}={}'.format(keyword.replace('%','%%'), score, len(m), len(m)*score))

                        # spaced out characters (visual text)
                        _grp = re.findall('\W\w\s{3,40}', body)
                        _c = len(_grp)
                        if _c > 5:
                            self.printme('spaced out chars result: {}'.format(_grp), console=True)
                            self.mod_dfw_score(_c, 'spaced out chars: f({})={}*{}'.format(1, _c, _c))

                        # applies to visual text
                        _ = len(re.findall('(?:\s/\w+){5,}', body))
                        if _ > 5:
                            self.mod_dfw_score(_, 'repeat (/word){5,}+ pattern')

                        # applies to visual text
                        # yes, this will partly duplicate the test in the text/html section
                        _ = len(re.findall('&#\d+;', body))
                        if _ > 10:
                            self.mod_dfw_score(_/2, '&#\\d+; matches')

                        # applies to visual text
                        wordlist  = body.split()
                        wordcount = Counter(wordlist)
                        factor    = len(body) *.005
                        for w,c in [ (w,c) for w,c in wordcount.most_common(10) if c >20 and len(w) >3]:
                            # skip really damn common shit that m$ spews in html
                            skip=False
                            for kw in ('tahoma','verdana','sans-serif','font-size','font-family','webkit','mso-','Lucida',
                                       'line-height','helvetica','arial','freesans','sans','color','collapse','cellspacing',
                                       'align=','style=','target=','border=','cellpadding=','class=','background:',
                                       'background-position:',
                                       ):
                                if kw in w.lower():
                                    skip=True
                                    break
                            if re.search('\(~\)\d+\.\d+\.\d+', w):
                                skip = True

                            if skip:
                                continue

                            if w[0] == '<' and w[-1] == '>':
                                continue

                            f = round(c/factor*len(w), 2)
                            if f < 2:
                                continue
                            label = 'word freq: {}'.format(w)
                            self.mod_dfw_score(f, '{}: f({})*{}={}'.format(label, round(f/c,3),c,f))


                        # url checks for all
                        # applies to visual text and HREF elements
                        udict = {
                                'http://[a-z0-9_\.-]+/[a-f0-9_-]+/[CV]/':5,
                                'http://[a-z0-9_\.-]+/.*/unsub.cgi':2,
                                }

                        sep=r'\b'
                        if isinstance(body, bytes):
                            sep=br'\b'
                            for k,v in udict.items():
                                if isinstance(k, str):
                                    udict[k.encode()] = v
                                    del(udict[k])

                        # applies to visual text and HREF elements
                        for keyword,score in udict.items():
                            m = re.findall(sep+keyword+sep, body, flags=re.I)
                            if m:
                                self.mod_dfw_score(len(m)*score, 'spamurl: {}, f({})*{}'.format(keyword,score,len(m)))


    def OnHeader(self, cmd, lhs, rhs):
        global recent_msgids

        #self.try_short_circuit()
        self.quit_location = 'OnHeader'

        self.printme('#HEADER# {:20.20}: {!r}'.format(lhs,rhs), level=logging.DEBUG)

        _ = '{}: {}\r\n'.format(lhs, rhs)
        self.payload += _.encode()

        if self.whitelisted or self.authenticated:
            return self.Continue()

        if '=?' in rhs:
            try:
                try:
                    rhs = ' '.join([ t.decode(e or 'utf-8') for t,e in email.header.decode_header(rhs) ])
                except:
                    rhs = ' '.join([ t.decode(e or 'latin-1') for t,e in email.header.decode_header(rhs) ])
            except:
                t,v,tb = sys.exc_info()
                self.printme('erps: {}'.format(v), console=True)
                self.printme('cannot recode: {}: {}'.format(lhs,rhs), console=True)

        self.headers.append( (lhs,rhs) )
        self.stored_headers.append( (lhs,rhs) )

        if lhs.lower() == 'message-id':
            # max of 5 recipients per msgid
            # this needs to be a tunable
            if rhs in recent_msgids:
                if len(recent_msgids[rhs]) > 5:
                    self.mod_dfw_score(len(recent_msgids[rhs]), 'duplicate msgid, count={}'.format(len(recent_msgids[rhs])), ensure_positive_penalty=True)

        return self.Continue()


    def OnEndHeaders(self, cmd):
        self.quit_location = 'OnEndHeader'
        self.printme('#ENDHEADERS#', level=logging.DEBUG)

        return self.Continue()


    def OnBody(self, cmd, body):
        """ this function repeats for each block of the body
        """

        self.quit_location = 'OnBody'
        self.printme('#BODY# segment is {}b'.format(len(body)), level=logging.DEBUG)

        #if self.whitelisted or self.authenticated:
        #    return self.Continue()

        if not self.getting_body:
            self.getting_body = True
            self.payload += b'\r\n'

        self.payload += body

        return self.Continue()


    # OnEOM?
    def OnEndBody(self, cmd):
        self.printme('#ENDBODY#', level=logging.DEBUG)
        self.quit_location = 'OnEndBody'

        # store a copy of payload in case of Aborts
        self.stored_payload = self.payload
        self.printme('payload size: {}'.format(len(self.stored_payload)))

        self.print_as_pairs(self.macros, console=True)

        fname = os.path.join(self.config['main']['spool dir'], 'interim', self.macros['{i}'])
        with open(fname, 'wb') as f:
            f.write(self.payload)

        if self.whitelisted or self.authenticated:
            return self.Continue()

        self.email_msg = email.message_from_bytes(self.payload)

        _ = self._run_header_tests()
        if _:
            self.printme('header tests return: {}'.format(_))

        _ = self._run_white_blacklist_checks()
        if _:
            self.printme('white_black_list return: {}'.format(_))

        self._run_body_tests()

        # double double triple triple check, whitelist itys.net and itriskltd.com
        # this should not be needed any more --
        if not self.whitelisted:
            for mjh in ('itys.net','itriskltd.com'):
                if self.whitelisted: continue
                for rcpt_to in self.recipients:
                    if self.whitelisted: continue
                    if rcpt_to.endswith(mjh):
                        self.printme('\x1b[1;37;42mhardwiring whitelist due to {} in RCPT TO: {}\x1b[0m'.format(mjh,rcpt_to), console=True)
                        self.whitelisted = True

        if not (self.whitelisted or self.authenticated):
            if self.dfw_penalty >= self.dfw.grace_score:
                self.was_kicked = True
                qid = '{i}' in self.macros and self.macros['{i}'] or "q<?3>"
                self.printme ('{} \x1d\x02\x0313{}\x0f \u22b3 {}; \x0313{}: scored {}\x0f'.format(qid, self._from, self.recipients, 'email too spammy', self.dfw_penalty))
                return self.CustomReply(503, '[{}] message not acceptable'.format(self._datetime), 'SPAMMY_CONTENT')

        # header insertion happens at this phase
        self.printme ('Inserting Blam headers', logging.DEBUG)
        self.actions.append(self.AddHeader('X-Blam', 'Blue-Labs Anti-Muggle filter v{}, from {}'.format(__version__, self.st[0])))
        self.actions.append(self.AddHeader('X-Blam-Report', 'dfw_penalty: {}'.format(self.dfw_penalty)))
        self.actions.append(self.AddHeader('X-Blam-Report', 'greetings: {}'.format(self.greetings)))

        self.left_early = False

        if self.whitelisted or self.authenticated:
            self.actions.append(self.Accept())

        # do any other per-message actions here, aka we should store headers/macros stuff in the DB

        return self.ReturnOnEndBodyActions(self.actions)


    def OnUnknown(self, cmd, data):
        self.quit_location = 'OnUnknown'
        # we should store this IP as a grey/bad source.  usually this is a protocol violation - aka, a bot is not paying attention to SMTP responses and
        # is slamming us with its intended spammage
        self.was_kicked = True
        self.mod_dfw_score(self.dfw.grace_score +1, 'SMTP protocol violation: {}'.format(data), ensure_positive_penalty=True)
        return self.CustomReply(421, '\033[31m☠\033[0m [{}] SMTP protocol violation'.format(self._datetime), 'PROTOCOL')


    def OnAbort(self, cmd, data):
        self.printme('#ABORT#')

        self.has_aborted = True
        if '{i}' in self.macros:
            self.last_qid = self.macros['{i}']

        tls_version = '{tls_version}' in self.macros
        # just in case it isn't a TLS session, penalize. we'll void this in OnHelo if
        # tls_version is added to our macros. also, don't penalize the Abort which happens
        # at the end of a TLS session
        if not self.pre_approved:
            if (not tls_version) and self.quit_location:
                self.mod_dfw_score(5, 'unexpected Abort', console=True)

        # postfix ALSO issues an Abort() after EOB when multiple messages are being delivered in the same session
        if self.quit_location == 'OnEndBody':
            # postfix issues two Abort() calls between EOB and QUIT in TLS sessions, ignore them
            self.printme('ignoring Postfix Abort() after EOB', level=logging.DEBUG)
            self.printme (ansi['bwhite']+'resetting variables, abort sent'+ansi['none'], level=logging.DEBUG)
            if self.do_db_store:
                self.printme('doing DB store via OnAbort 1')
                self.db_store()
            self._init_resettable(abort=True)
            return

        _console = not(self.helo[-1] == 'icinga.security-carpet.com' and self.quit_location == 'OnHelo')
        self.printme (ansi['byellow']+'Aborted'+ansi['none']+' in MTA: {}, {} was last function'.format(data, self.quit_location), console=_console)
        self.printme ('time spent: {}'.format(datetime.datetime.now() - self._datetime))
        # don't slam too hard, it could be a timeout issue rather than a bot

        # this must come before init_resettable
        if self.do_db_store:
            self.printme('doing DB store via OnAbort 2')
            self.db_store()

        # postfix sends Abort() for phase changes like STARTTLS,
        # we're supposed to drop all client information at this point and start anew.
        # problem is, we get Abort() at the end of conversations too and we don't want to lose that
        self._init_resettable(abort=True)

        #if not (self.punished or self.whitelisted):
        #    self.dfw.punish(self.st[1], self.client_address, penalty=self.dfw_penalty, reasons=['SMTP communication aborted'])
        #    self.punish = True
        #    print('punished, dfw_penalty is {}'.format(self.dfw_penalty))
        #else:
        #    print('not punished')

        return # DO NOT return anything on abort()


    def OnQuit(self, cmd, data):
        self.printme('#QUIT#')

        mta_code,mta_short,mta_reason = self.getFinis()
        self.mta_code   = mta_code
        self.mta_short  = mta_short
        self.mta_reason = mta_reason

        reasons = []

        if mta_reason:
            if not [x for x in reasons if mta_reason in x]:
                reasons.append(mta_reason.strip())

        try:
            mta_code = int(mta_code)
        except:
            mta_code = -1

        if mta_code > 499 and not self.early_punish:
            self.mod_dfw_score(self.dfw.grace_score +1, 'Aborted SMTP conversation', ensure_positive_penalty=True)

        if self.left_early or self.was_kicked or (not mta_code == 250) or self.dfw_penalty >= self.dfw.grace_score:
            if self.whitelisted or self.authenticated or self.hostname in self.pre_approved:
                self.printme('Session terminated unexpectedly early, was whitelisted/authenticated')
                if not mta_code == 250:
                    self.printme('Probably blocked by spamassassin, you probably want to fix this', logging.WARNING)
                    self.printme('  we do not punish whitelisted/authenticated/preapproved')

            else:
                self._store_reject()
                # don't bother about hanging chads
                if self.client_address and not self.early_punish:
                    self.mod_dfw_score(5, 'left early/kicked/not 250/dfw>grace')
                    self.printme('notifying DFW, score is {}'.format(self.dfw_penalty))
                    adr = self.client_address.startswith('IPv6') and self.client_address[5:] or self.client_address

                    reasons = [ x.replace('\x1b[31m☠\x1b[0m', '☠') for x in reasons if x ]
                    reasons = [ re.sub(r'☠\s\[\d{4}-\d\d-\d\d\s\d\d:\d\d:\d\d\.\d+\]\s+', '', x) for x in reasons ]
                    reasons = [ x.replace('See https://blue-labs.org/blocked_mail/index.html','') for x in reasons ]
                    reasons = [ x.strip() for x in reasons ]

                    if self.dfw_penalty:
                        reasons.append('dfw score: {}'.format(self.dfw_penalty))
                    if self.greetings:
                        reasons.append('greetings: {}'.format(self.greetings))

                    # don't waste time punching twice, early punished connections are grace+1; already firewalled
                    if not self.early_punish:
                        self.dfw.punish(self.st[1], adr, penalty=self.dfw_penalty, reasons=reasons)

        self.reasons = reasons



    def _summary_report(self):
        if not self.client_address:
            return

        # use the helo_chad since we already processed self._init_resettable() due to session end Abort()
        _console = not(self.helo_chad in ('icinga.security-carpet.com',) and self.mta_code == 250)

        self.printme('helo:   {!r} {!r}'.format(self.helo, self.helo_chad), console=_console)
        self.printme('MTA quit code:   {!r}'.format(self.mta_code), console=_console)
        self.printme('MTA quit short:  {!r}'.format(self.mta_short))
        self.printme('MTA quit reason: {!r}'.format(self.mta_reason))
        self.printme('Left early:      {!r}'.format(self.left_early))
        self.printme('Kicked by Blam:  {!r}'.format(self.was_kicked))
        self.printme('DFW penalty:     {!r}'.format(self.dfw_penalty), console=_console)
        self.printme('SPF authorized:  {!r}'.format(self.spf_authorized))
        self.printme('preapproved:     {!r}'.format(self.hostname in self.pre_approved))
        self.printme('whitelisted:     {!r}'.format(self.whitelisted))
        self.printme('blacklisted:     {!r}'.format(self.blacklisted))
        self.printme('authenticated:   {!r}'.format(self.authenticated))

        self.printme('X-Blam-Report-greetings: {}'.format(self.greetings))

        if self.mta_code == 250 and (self.hostname in self.pre_approved) or self.whitelisted or (not self.left_early):
            color = '\033[1;32m'
        else:
            color = '\033[1;31m'

        self.printme ('Finis ({} [{}:{}]) {}({!r},{})\033[0m, time spent: {}'.format(
            self.hostname, self.client_address, self.client_port,
            color, self.mta_code, self.mta_short,
            datetime.datetime.now() - self._datetime))



    def _purge_old_files(self):
        purgetime = time.time() - (86400*30)
        for f in os.scandir('/var/spool/blam/rejects'):
            if f.stat().st_ctime < purgetime:
                self.printme('purging /var/spool/blam/rejects/{}'.format(f.name))
                os.unlink(os.path.join('/var/spool/blam/rejects',f.name))
        for f in os.scandir('/var/spool/blam/logfiles'):
            if f.stat().st_ctime < purgetime:
                self.printme('purging /var/spool/blam/logfiles/{}'.format(f.name))
                os.unlink(os.path.join('/var/spool/blam/logfiles',f.name))


    def _store_reject(self):
        qid = '{i}' in self.macros and self.macros['{i}'] or self.last_qid or self._datetime.strftime('no-qid-%F %T')
        payload = self.stored_payload or b''

        if not payload:
            self.printme('no payload, not storing reject')
            return # no point in storing the blank firewalled rejects

        self.printme('storing reject at /var/spool/blam/rejects/{}'.format(qid))

        try:
            payload = payload.decode('utf-8')
        except:
            payload = payload.decode('latin-1')

        with open('/var/spool/blam/rejects/'+qid, 'w') as f:
            f.write('{}\n'.format(payload))

        with open('/var/spool/blam/rejects/'+qid+'.reasons', 'w') as f:
            f.write('\n')
            mta_code,mta_short,mta_reason = self.getFinis()
            f.write('MTA quit code:   {!r}\n'.format(mta_code))
            f.write('MTA quit short:  {!r}\n'.format(mta_short))
            f.write('MTA quit reason: {!r}\n'.format(mta_reason))
            f.write('Left early:      {!r}\n'.format(self.left_early))
            f.write('Kicked by Blam:  {!r}\n'.format(self.was_kicked))
            f.write('DFW penalty:     {!r}\n'.format(self.dfw_penalty))
            f.write('preapproved:     {!r}\n'.format(self.hostname in self.pre_approved))
            f.write('whitelisted:     {!r}\n'.format(self.whitelisted))
            f.write('blacklisted:     {!r}\n'.format(self.blacklisted))
            f.write('authenticated:   {!r}\n'.format(self.authenticated))

            f.write('X-Blam-Report-greetings: {}\n'.format(self.greetings))


    def OnEom(self):
        self.printme('#EOM#')
        return self.Continue()


    def OnClose(self, cmd, data):
        ''' cmd and data should always be nothing, just ignore them'''
        self.printme('#CLOSE#', console=True)
        if self.has_closed:
            self.printme('OnClose() called again, ignoring', console=True)

        self.has_closed=True

        global recent_msgids

        now    = self._datetime
        expire = now - datetime.timedelta(hours=2)
        dels   = []

        for k,ts in recent_msgids.items():
            for t in ts[:]:
                if t < expire:
                    ts.remove(t)
            if not ts:
                dels.append(k)

        for d in dels:
            del recent_msgids[d]


        # NOTE! this will be affected by multiple messages per session, needs to be fixed
        # we need to have a per-message post-session function
        # restore self.macros, ensure each element in self.stored_macros exists in self.macros
        for k in self.stored_macros:
            if not k in self.macros:
                self.macros[k] = self.stored_macros[k]
            elif not self.macros[k] == self.stored_macros[k]:
                self.macros[k] = self.stored_macros[k]

        # check things that need to be tracked across sessions

        # dupe msg id needs to accumulate on 250 emails otherwise we risk penalizing (legit) senders
        # that are failing for another reason

        # NOTE! this will be affected by multiple messages per session, needs to be fixed
        # we need to have a per-message post-session function
        # add our msgid
        msgid = [v for k,v in self.headers if k.lower() == 'message-id']
        if msgid:
            if not msgid[0] in recent_msgids:
                recent_msgids[msgid[0]] = []
            recent_msgids[msgid[0]].append(now)

        # NOTE! this will be affected by multiple messages per session, needs to be fixed
        # we need to have a per-message post-session function
        if self.do_db_store and self.client_address and self.client_port:
            self.db_store()

        #if not self.left_early and not (self.was_kicked or (self.hostname in self.pre_approved)):

        # don't report chaff to cams
        if (not self.mta_code == 250) and (not self.in_dnsbl):
            self.printme('MTA code: {}, MTA reason: {}'.format(self.mta_code, self.mta_reason), console=True)
            qid = '{i}' in self.stored_macros and self.stored_macros['{i}'] or "q<?4>"
            self.cams_notify('{} \x1d\x02\x0313{}\x0f \u22b3 {}; \x0313{},{},{}\x0f'.format(
                qid,
                self._from or self.hostname,
                self.recipients or (self.helo and self.helo[-1] or self.client_address),
                self.mta_code,
                self.mta_short,
                self.reasons))


        # ARF
        if (self.dfw_penalty >= self.dfw.grace_score) and not (self.whitelisted or self.hostname in self.pre_approved):
            # try and report it

            # we get the domain information from the connecting IP and hostname
            # never rely on the mail_addr macro to determine the reported domain
            # because that is easily forged

            self.print_as_pairs(self.macros, console=True)

            if not ('{mail_addr}' in self.macros and self.macros['{mail_addr}'] \
                    and '{j}' in self.macros and self.macros['{j}']
                    and self.client_port):
                self.printme('Skipping ARF, no mail_addr value in macros', console=True)
            else:
                self.printme('Starting ARF', console=True)

                '''
                enc_p=False
                for enc in ('utf-8','cp1252','latin-1','ascii'):
                    try:
                        enc_p = self.stored_payload.decode(enc)
                        break
                    except Exception as e:
                        self.printme('Failed to convert payload: {}'.format(e), console=True)
                        continue

                if enc_p is False:
                    self.printme("Unable to convert payload, can't continue with ARF", console=True)

                else:
                '''
                enc_p = self.stored_email_msg

                if self.subject_chad: # sigh, can't keep up. only do ARFs on bodied spams.
                    try:

                        arfc = 'ARF' in self.config and self.config['ARF']

                        def_reporting_domain = 'default reporting domain' in arfc \
                            and arfc['default reporting domain'] \
                            or None

                        redirect_per_domain = {}
                        for k in arfc:
                            if k.startswith('redirect.'):
                                d = k[9:]
                                redirect_per_domain[d] = [x for x in arfc[k].replace(',',' ').split(' ') if x]

                        self.printme('recipients: {}'.format(self.stored_recipients))

                        macros           = self.macros
                        mail_from        = macros['{mail_addr}']
                        rcpt_to          = self.stored_recipients or ['<undefined>']

                        if len(rcpt_to)>1:
                            # use default domain
                            reporting_domain = def_reporting_domain
                        else:
                            reporting_domain = '@' in rcpt_to[0] and rcpt_to[0].split('@')[1]

                        self.printme('reporting_domain is {}'.format(reporting_domain))

                        subject = self.subject_chad or '<message-blocked-before-body-sent>'

                        # get arf smtp server config

                        ar = arf.ARF(subject=subject, reporting_domain=reporting_domain, smtpport=587, logger=self.printme)
                        ar.characterize('Source-IP', self.client_address)
                        ar.characterize('Source-Port', self.client_port)
                        ar.characterize('Reporting-MTA', macros['{j}'])
                        ar.characterize('Original-Mail-From', mail_from)
                        ar.characterize('Original-Rcpt-To', rcpt_to)

                        # reported domain should try to use the DNS resolved address as much as possible
                        # do NOT use the mail_host as that is entirely spoofable
                        if not (self.hostname == self.client_address) and not self.hostname.startswith('['):
                            reported_domain = self.hostname
                        else:
                            reported_domain = self.client_address

                        ar.characterize('Reported-Domain', reported_domain)

                        ar.set_message(enc_p)
                        ar.add_text_notes(self.penalties)

                        ar_username = arfc.get('smtp username')
                        ar_password = arfc.get('smtp password')

                        ar.set_smtp_auth_credentials(ar_username, ar_password)

                        # this can cause long delays!
                        if ar.find_abuse_contacts():
                            ar.generate()

                            redirect=None
                            if not enc_p:
                                redirect = redirect_per_domain.get('*')
                            else:
                                # based on the reporting domain, set redirect
                                redirect = redirect_per_domain.get(reporting_domain)
                                if not redirect:
                                    redirect = redirect_per_domain.get('+')

                            self.printme('set redirectTo={}'.format(redirect))

                            if not self.unittest:
                                if redirect: # still heavily testing this so ONLY send to redirects
                                    ar.send(redirectTo=redirect)
                                self.printme('ARF report sent to {}'.format(ar.abuse_contacts), console=True)
                            else:
                                self.printme('ARF report would have been sent to: {}'.format(ar.abuse_contacts), console=True)
                                self.printme(ar)

                    except Exception as e:
                        self.printme('ARF exception, probably macros: {}'.format(e), console=True)
                        self.printme('{}'.format(traceback.format_exc(10)), console=True)

        self._summary_report()

        self._purge_old_files()

        if self.iolog:
            # in very rare situations, we have a connect and immediate close with no client info
            if self.client_address:
                # fix this to use config
                _ = os.path.join('/var/spool/blam/logfiles', 'noid-'+self.client_address+':'+str(self.client_port))
                self.printme('flushed iolog stream to {}'.format(_), console=True)
                self.logname = open(_, 'a', encoding='utf-8')
                self.logname.write(self.iolog.getvalue())
            self.iolog.close()
            self.iolog = None

        if self.logname:
            self.logname.close()
            self.logname = None

        return # pointedly don't return anything


    # todo: figure out why base.py isn't calling me. (reason: because OnAbort is defined which overrides the built in OnAbort)
    def OnResetState(self):
        self.printme('#RESET#')
        self.quit_location = 'OnReset'
        self.printme (ansi['bwhite']+'resetting variables, reset state'+ansi['none'])
        self._init_resettable()



def main(logger):
    configfile   = '/etc/Blam/Blam.conf'
    config       = configparser.ConfigParser()

    if not config.read(configfile):
        logger.warning ('Error reading required configuration file: {}'.format(configfile))

    if not 'main' in config.sections():
        config.add_section('main')
    if not 'Blam' in config.sections():
        config.add_section('Blam')
    if not 'DFW' in config.sections():
        config.add_section('DFW')
    if not 'ARF' in config.sections():
        config.add_section('ARF')

    if not 'filter name' in config['main']:
        config['main']['filter name']='mail-pit'
    if not 'resolver nameservers' in config['main']:
        config['main']['resolver nameservers']='8.8.8.8'
    if not 'resolver timeout' in config['main']:
        config['main']['resolver timeout']='3.0'
    if not 'resolver lifetime' in config['main']:
        config['main']['resolver lifetime']='8.0'
    if not 'node address' in config['main']:
        raise KeyError('No config value for "node address" in section "main"')
    if not 'node port' in config['main']:
        config['main']['node port'] = '12701'
    if not 'spool dir' in config['main']:
        config['main']['spool dir'] = '/var/spool/blam'
    if not 'tld refresh hours' in config['main']:
        config['main']['tld refresh hours'] = '12'

    sc = None
    if 'ssl crt' in config['main']:
        sc = ssl.create_default_context()
        certfile   = config['main']['ssl crt']
        keyfile    = config['main']['ssl key']
        passphrase = config['main']['ssl passphrase']
        sc.load_cert_chain(certfile=certfile, keyfile=keyfile, password=passphrase)

    _cams = len(config['CAMS'])
    if _cams:
        _d = config['CAMS']['destination'].split(':')
        destination = (_d[0],int(_d[1]))

        _cams = cams.CAMS(logger=rootlogger, sslcontext=sc, destination=destination)
        _cams.id = socket.getfqdn().split('.',1)[0] +'/blam'
        _cams.notify('startup, v%s' %(__version__))

    port = int(config['main']['node port'])

    db       = DB(config, logger)

    _dfw     = dfw.DFW(name=config['main']['filter name'],
                       node_address=config['main']['node address'],
                       dburi=config['DFW']['db uri'],
                       logger=logger)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.timeout = float(config['main']['resolver timeout'])
    resolver.lifetime = float(config['main']['resolver lifetime'])
    resolver.nameservers = [x for x in config['main']['resolver nameservers'].replace(' ',',').split(',') if x]

    spooldir = config['main']['spool dir']
    os.makedirs(os.path.join(spooldir,'rejects'), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(spooldir,'logfiles'), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(spooldir,'interim'), mode=0o700, exist_ok=True)

    ppymilter.server.AsyncPpyMilterServer(config['main']['node address'], port, BlamMilter,
        additional={'config':config,
                    'logger':logger,
                    'db':db,
                    'dfw':_dfw,
                    'cams':_cams,
                    'resolver':resolver})

    try:
        asyncore.loop(use_poll=True)
    except KeyboardInterrupt:
        print('\033[2D\033[K\033[A')
    except:
        traceback.print_exc()

    _dfw.shutdown()
    _cams.shutdown()
    sys.exit()


g_load_avg = 0

class ContextFilter(logging.Filter):
    x = None
    def __init__(self):
        self.x = super()

    def filter(self, record):
        record.sipport = ' '*17
        try:
            cf = inspect.currentframe()
            caller = inspect.getouterframes(cf)

            st = None
            for frame in caller:
                if 'self' in frame[0].f_locals and hasattr(frame[0].f_locals['self'], 'st'):
                    st = getattr(frame[0].f_locals['self'], 'st')
                    break

            if st and st[0]:
                record.sipport = '{:>11}:{:<5}'.format(st[0],st[1])

        finally:
            del(cf)
            del(caller)

        record.loadavg = os.getloadavg()[0]

        return True

# make this a static method in Blam
def update_tlds(config, logger):
    if not config:
        return

    # fetch list of TLDs from iana
    do_fetch = True
    tld_fn =  os.path.join(config['main']['spool dir'], 'tlds.txt')

    rh = int(config['main']['tld refresh hours'])

    try:
        now = datetime.datetime.now()
        ctime = datetime.datetime.fromtimestamp(os.stat(tld_fn).st_ctime)
        if ctime+datetime.timedelta(hours=rh) > now:
            do_fetch = False
    except:
        pass

    if do_fetch:
        url = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'
        try:
            f = urlopen(url, timeout=5.0)
            with open(tld_fn, 'wb') as df:
                df.write(f.read())
        except:
            logger.warn('failed to fetch TLDS')

    tlds = set()
    try:
        with open(tld_fn, 'rb') as f:
            data = f.read()
            if data:
                data = data.decode().split('\n')
                tlds = [ tld.lower() for tld in data if tld and not tld.startswith('#')]
    except:
        logger.warn('failed to read updated TLDS')

    return tlds


if __name__ == '__main__':

    # todo: move this into main and make it configurable
    rootlogger = logging.getLogger('/Blam')
    rootlogger.setLevel(logging.DEBUG)

    fh = logging.handlers.TimedRotatingFileHandler(filename='/var/log/blam', when='midnight', backupCount=14, encoding='utf-8')
    fm = logging.Formatter(fmt='%(asctime)-8s %(levelname)-.1s %(loadavg)1.1f %(sipport)s %(message)s', datefmt='%H:%M:%S')

    fh.setFormatter(fm)
    rootlogger.addHandler(fh)

    f = ContextFilter()
    rootlogger.addFilter(f)

    # remember to open new file descriptors inside the daemon context, or pass their
    # file descriptors below

    if len(sys.argv) >1 and sys.argv[1] == 'daemon':
        # these too should be in config file
        dcontext = daemon.DaemonContext(umask=0o077,
            working_directory='/var/spool/blam', pidfile=PidFile('/run/blam.pid'))

        openFiles = [sys.stdin, sys.stdout]
        for handler in rootlogger.handlers:
            if hasattr(handler, 'stream') and hasattr(handler.stream, 'fileno'):
                openFiles.append(handler.stream)

        dcontext.files_preserve = openFiles

        with dcontext:
            main(rootlogger)

    else:
        ch = logging.StreamHandler()
        ch.setFormatter(fm)
        rootlogger.addHandler(ch)

        main(rootlogger)
