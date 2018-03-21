#!/bin/env python

# Copyright (c) 2018 Richard Monk <rmonk@redhat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import json
import logging
import logging.handlers
import socket
from idstools import unified2
from idstools import maps
from idstools.packet import decode_ethernet
from idstools.scripts import u2fast, u2spewfoo
from Queue import Queue
from Queue import Empty
from threading import Thread
from multiprocessing import Process, Event, current_process
import os
import sys
import time
import os.path
from impacket.ImpactDecoder import EthDecoder
import MySQLdb
from binascii import hexlify
import datetime
import gc
import signal

# Logging configuration
class ContextFilter(logging.Filter):
    hostname = socket.gethostname()

    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True

log = logging.getLogger(__name__)
log.handlers = []
handler = logging.handlers.SysLogHandler('/dev/log')
log.addHandler(handler)
log.setLevel(logging.INFO)

# adjust idstools logging to send only to syslog
idstools_log = logging.getLogger("idstools")
idstools_log.addHandler(logging.handlers.SysLogHandler('/dev/log'))
idstools_log.setLevel(logging.ERROR)

## Signal handler, catch shutdown and close cleanly
#def signal_term_handler(signal, frame):
#    log.info("Caught signal, shutting down")
#    raise KeyboardInterrupt

#signal.signal(signal.SIGTERM, signal_term_handler)


f = ContextFilter()
log.addFilter(f)

formatter = logging.Formatter('%(asctime)s charlotte[%(process)d]: %(message)s', datefmt='%b %d %H:%M:%S')
handler.setFormatter(formatter)

log.setLevel(logging.INFO)


class CharlotteConfigError(Exception):
        def __init__(self, value):
            self.value = value
        def __str__(self):
            return self.value

class CharlotteDirectoryNotFoundError(Exception):
        def __init__(self, value):
            self.value = value
        def __str__(self):
            return self.value

class CharlotteDatabaseError(Exception):
        def __init__(self, value):
            self.value = value
        def __str__(self):
            return self.value

class CharlotteEventReaderError(Exception):
        def __init__(self, value):
            self.value = value
        def __str__(self):
            return self.value
        
# This version of the SpoolEventReader supports use of a rollover hook
class HookedSpoolEventReader(unified2.SpoolEventReader):
    def __init__(self, directory, prefix, sensor_name, follow=False, delete=False,
                             bookmark=False, rollover_hook=None):
        self.custom_hook = rollover_hook
        log.debug("custom hook registered")
        self.sensor_name = sensor_name
        super(HookedSpoolEventReader, self).__init__(directory, prefix, follow, delete, bookmark)

    def rollover_hook(self, closed, opened):
        if self.custom_hook != None:
            log.debug("Calling custom hook")
            self.custom_hook(self.sensor_name, closed, opened)
        super(HookedSpoolEventReader ,self).rollover_hook(closed, opened)

# validates and stores a config object
def Config(config_file_name):
    # pull in the config file
    try:
        with open(config_file_name, "r") as config_file:
            config = json.load(config_file)
    except Exception, e:
        raise CharlotteConfigError("Unable to read config file: %s" % e)

    # check required fields
    if 'global' in config:
        for option in ['signature_map',
            'generator_map', 'classification_map']:
            if option not in config['global']:
                raise CharlotteConfigError("Required section %s not in global config, exiting" % option)
    else:
        raise CharlotteConfigError("No global section in config")

    # make sure spools are well formed
    if 'spools' in config:
        if len(config['spools']) > 0:
            for spool_name, spool in config['spools'].iteritems():
                for option in ['directories', 'filename']:
                    if option not in spool:
                        raise CharlotteConfigError("Required section %s not in config %s" % (option, spool_name))
        else:
            raise CharlotteConfigError("No spools defined, nothing to do")
    else:
        raise CharlotteConfigError("No spool section, nothing to process")
    
    log.debug("Charlotte config imported")
    return config

class Maps(object):
    def __init__(self,config):
        self.config = config
        # pull in the classification/sig maps
        self.sigmap_timestamp = None
        self.genmap_timestamp = None
        self.classmap_timestamp = None

        self.rehash()

    # Creates new sig and class maps
    def rehash(self):
        try:
            self.sigmap = maps.SignatureMap()
            self.sigmap.load_generator_map(open(self.config['global']['generator_map']))
            self.sigmap.load_signature_map(open(self.config['global']['signature_map']))
            self.sigmap_timestamp = os.path.getmtime(self.config['global']['signature_map'])
            self.genmap_timestamp = os.path.getmtime(self.config['global']['generator_map'])
        except Exception, e:
            raise CharlotteConfigError("Error reading signature maps: %s" % e)

        try:
            self.classmap = maps.ClassificationMap()
            self.classmap.load_from_file(open(self.config['global']['classification_map']))
            self.classmap_timestamp = os.path.getmtime(self.config['global']['classification_map'])
        except Exception, e:
            raise CharlotteConfigError("Error reading classification map: %s" % e)
    # Wraps underlying map, automatically refreshes it if it changes on disk
    def get_sig(self,gen, sid):
        if os.path.getmtime(self.config['global']['signature_map']) != self.sigmap_timestamp or os.path.getmtime(self.config['global']['generator_map']) != self.genmap_timestamp:
            self.rehash()
        siginfo = self.sigmap.get(gen, sid)
        if not siginfo:
            # Uh oh, it's not in the mapping, make a fake entry
            siginfo = { 'rev' : 0, 'classid': 0, 'priority': 10, 'msg': 'Unknown Alert %s:%s' % (gen, sid)}

        if 'rev' not in siginfo:
            siginfo['rev'] = 1

        return siginfo

    # Wraps underlying map, automatically refreshes if it changes on disk
    def get_class(self,classid):
        if os.path.getmtime(self.config['global']['classification_map']) != self.classmap_timestamp:
            self.rehash()
        classinfo = self.classmap.get(classid)
        if not classinfo:
            classinfo = { 'name' : 'unknown-classification', 'classid' : classid }

        return classinfo

    # Used by tools expecting regular "get" from maps
    def get(self, *args):
        if len(args) == 2:
            return self.get_sig(args[0], args[1])
        else:
            return self.get_class(args[0])

class EventReader(object):
    def __init__(self, charlotte_config, queue, rollover_hook = None, ):
        self.queue = queue
        self.config = charlotte_config
        self.rollover_hook = rollover_hook
        self.workers = []
        self.shutdown_event = Event()
    # Reads and enqueues alerts from unified files
    def start(self):
        for spool in self.config['spools'].keys():
            try:
                log.debug("Starting worker for %s" % spool)
                worker = Process(target=self._sensor_worker, name=spool, args=(spool,self.shutdown_event, self.rollover_hook))
                worker.daemon = True
                worker.start()
                self.workers.append(worker)
            except Exception, e:
                log.error("Unable to start worker for %s: %s" % (spool, e))

    def request_close(self):
        self.shutdown_event.set()

    def wait_close(self):
        log.info("Waiting for reader workers to close")
        still_alive = True
        while still_alive:
            still_alive = False
            for worker in self.workers:
                if worker.is_alive():
                    still_alive = True
                    time.sleep(1)
                    break
        log.info("Readers closed, shutting down")
            
    # The sensor worker is a thread that reads the data from the spool dir and
    # sends the events into a Queue for processing
    # sensor_name is the name it should say these alerts come from
    # directories are the directories to work on
    # prefix is the filename prefix (snort.log)
    # queue is the output queue for sending data out
    def _sensor_worker(self, sensor_name, shutdown_event, rollover_hook = None):

        log.debug("Starting up worker for %s" % sensor_name)

        directories = self.config['spools'][sensor_name]["directories"]
        prefix = self.config['spools'][sensor_name]["filename"]

        readers = []
        try:
            for directory in directories:        
                readers.append(HookedSpoolEventReader(directory, prefix, sensor_name, follow=False, bookmark=True, rollover_hook = rollover_hook))
            
            while not shutdown_event.is_set():
                event_processed = False
                for reader in readers:
                    event = reader.next()
                
                    if event:
                        event_processed = True
                        log.debug("Received event for sensor %s" % sensor_name)
                        self.queue.put( (sensor_name, event) )

                if not event_processed:
                    time.sleep(1)
        except KeyboardInterrupt:
            pass 
        except Exception, e:
            log.error("Exception reading alert: %s" % e )
            raise CharlotteEventReaderError, e
            
        log.info("Shutting down reader")
class TextOutput(object):
    def __init__(self, charlotte_config, queue, maps, reader):
        self.config = charlotte_config
        self.queue = queue
        self.maps = maps
        self.reader = reader

    def process_alerts(self):
        shutdown = False

        log.debug("Starting up alert processor")
        self.packet_decoder = EthDecoder()
        try:
            while True:
              self._process_one_alert() 
        except KeyboardInterrupt, e:
            log.info("Shutting down readers")
            self.reader.request_close()
            log.info("Clearing queue")
            shutdown = True
            while not self.queue.empty():
                self._process_one_alert()
            log.info("Writer waiting on reader closure")
            self.reader.wait_close()
            while not self.queue.empty():
                self._process_one_alert()
            log.info("Queue clear, shutting down")

    def _process_one_alert(self):
        try:
            sensor_name, event = self.queue.get(timeout=1)
        except Empty:
            return
            
        log.debug("Received message")
        print event
        for packet in event['packets']:
            print self.packet_decoder.decode(packet['data'])
        for extradata in event['extra-data']:
            print extradata
        try:
            u2fast.print_event(event, self.maps, self.maps)
        except Exception, e:
            log.error("unable to process alert")
            print "bad alert:"
            print event

         
    def process_rollover(self, sensor_name, closed, opened):
        print "File Rollover on sensor %s" % sensor_name

    def wait_close(self):
        while not self.queue.empty():
            time.sleep(1)   
 

class DatabaseOutput(object):
    def __init__(self, charlotte_config, queue, maps):
        self.config = charlotte_config
        self.queue = queue
        self.maps = maps
        # Validate the config
        required_keys = [ 'server', 'user', 'password', 'db' ]
        for key in required_keys:
            if key not in self.config['plugin_snortdb']:
                log.error("Key %s not in DB config" % key)
                raise CharlotteConfigError("Key %s not in DB config" % key)

        # Pull variables
        dbconfig = self.config['plugin_snortdb']
        self.dbuser = dbconfig['user']
        self.dbserver = dbconfig['server']
        self.dbpassword = dbconfig['password']
        self.dbname = dbconfig['db']

        self.db = None
        self.sensor_ids = {}
        self.sig_ids = {}
        self.classification_ids = {}
        self.connect_db()

    # usually used when files reload on disk
    def clear_cache(self):
        self.sensor_ids = {}
        self.sig_ids = {}
        self.classification_ids = {}

    # Establish connection to the database
    def connect_db(self, reconnect=False):
        if self.db == None or reconnect:
            connected = False
            delay = 0
            while not connected:
                try:
                    if self.db:
                        self.db.close()
                except Exception, e:
                    log.warning("Error closing Database session: %s" % e)
                self.db = None
                    
                try:

                    if delay > 0:
                        log.warning("Waiting %s seconds before reconnecting to database" % delay)
                        time.sleep(delay)

                    self.db = MySQLdb.connect(host=self.dbserver, user=self.dbuser, passwd=self.dbpassword, db=self.dbname)
                    connected = True
                    delay = 0
                except Exception, e:
                    if delay == 0:
                        delay = 1
                    else:
                        delay = 2 * delay
        return True

    def _sql(self, statement, variables):
        success = False
        delay = 0
        while not success:
            try:
                if delay > 0:
                    log.warning("Waiting %s seconds before retrying query" % delay)
                    time.sleep(delay)

                cursor = self.db.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute(statement, variables)
                data = cursor.fetchall()
                self.db.commit()
                cursor.close()
                success = True

            except Exception, e:
                log.warning("Got DB error %s, attempting reconnect" % e)
                if delay == 0:
                    delay = 1
                else:
                    delay = 2 * delay

                if cursor:
                    try:
                        cursor.rollback()
                    except Exception, e:
                        # Oh well, can't roll back.  That's actually fine, just ignore it.
                        log.warning("Unable to roll back transaction.  Continuing")
                # attempt reconnect 
                self.connect_db(reconnect = True)
                continue

        return data

    def process_alerts(self):

        shutdown = False
        try:
            if shutdown:
                log.debug("Cleaning up alert queue")
                log.debug("%s alerts in queue" % self.queue.qsize())
            else:
                log.debug("Starting up alert processor")

            while True:
                try:
                    sensor_name, event = self.queue.get(timeout=1)
                except Empty:
                    if shutdown:
                        # we are shutting down, when the queue is empty quit
                        log.info("Writer shutting down")
                        return
                    continue

                log.debug("Received message from %s", sensor_name)
                log.debug("Alert: %s", event)
                self._push_to_db(sensor_name, event)
                #self.queue.task_done()
        except KeyboardInterrupt, e:
            log.info("Caught signal, clearing queue and shutting down")
            shutdown = True

    def _push_to_db(self, sensor_name, event):
        sensor_id = self.get_sensor_id(sensor_name)['sensor_id']
        starting_alert_id = self.get_next_alert_id(sensor_name)
        self.update_db_classification(event['classification-id'])
        signature_id = self.get_signature_id(event)
        timestamp = datetime.datetime.utcfromtimestamp(event['event-second']).strftime("%Y-%m-%d %H:%M:%S")        

        if len(event['packets']) == 0 and len(event['extra-data']) == 0: 
            # Just insert the event into the database
    	    log.warning("Possible problem, alert with no packet data" )
            self._sql("""INSERT INTO event (sid, cid, signature, timestamp) VALUES (%s, %s, %s, %s)""",
                ( sensor_id, starting_alert_id, signature_id, timestamp))
            alert_id = starting_alert_id
        else:
            alert_id = starting_alert_id
            self._sql("""INSERT INTO event (sid, cid, signature, timestamp) VALUES (%s, %s, %s, %s)""",
                ( sensor_id, starting_alert_id, signature_id, timestamp))
            for packet in event['packets']:
                log.debug("Processing packet")
                packetdata = decode_ethernet(packet['data'])
		log.debug(packetdata)
                if 'ip_version' in packetdata:
                    # IP packet, load into DB
		    log.debug("Inserting IP header")
                    self._sql("""INSERT INTO iphdr (sid, cid, ip_src, ip_dst, ip_ver, ip_hlen, ip_tos, ip_len, ip_id, ip_flags, ip_off, ip_ttl, ip_proto, ip_csum)
                           VALUES ( %s, %s, inet_aton(%s), inet_aton(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s )""", ( sensor_id,
                        alert_id, packetdata['ip_source'], packetdata['ip_destination'],
                        packetdata['ip_version'], packetdata['ip_ihl'], packetdata['ip_dscp'],
                        packetdata['ip_length'], packetdata['ip_id'], packetdata['ip_flags'],
                        packetdata['ip_offset'], packetdata['ip_ttl'], packetdata['ip_protocol'],
                        packetdata['ip_chksum'] ))
                if 'tcp_sport' in packetdata:
                    # TCP packet, load into DB
		    log.debug("Inserting TCP header")
                    self._sql("""INSERT INTO tcphdr (sid, cid, tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_off, tcp_res, tcp_flags, tcp_win, tcp_csum, tcp_urp)
                        VALUES ( %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s )""", ( sensor_id,
                        alert_id, packetdata['tcp_sport'], packetdata['tcp_dport'], packetdata['tcp_seq'],
                        packetdata['tcp_ack'], packetdata['tcp_offset'], 0, packetdata['tcp_flags'],
                        packetdata['tcp_window'], packetdata['tcp_chksum'], packetdata['tcp_urgptr']))
                    self._sql("""INSERT INTO data (sid, cid, data_payload)
                        VALUES ( %s, %s, %s )""", (sensor_id, alert_id, hexlify(packetdata['tcp_payload'])))

                elif 'udp_sport' in packetdata:
		    log.debug("Inserting UDP header")
                    self._sql("""INSERT INTO udphdr (sid, cid, udp_sport, udp_dport, udp_len, udp_csum)
                        VALUES ( %s, %s, %s, %s, %s, %s )""", ( sensor_id, alert_id,
                        packetdata['udp_sport'], packetdata['udp_dport'], packetdata['udp_length'],
                        packetdata['udp_chksum']))
                    self._sql("""INSERT INTO data (sid, cid, data_payload)
                        VALUES ( %s, %s, %s )""", (sensor_id, alert_id, hexlify(packetdata['udp_payload'])))
                elif 'icmp_type' in packetdata:
		    log.debug("Inserting ICMP header")
                    if packetdata['icmp_type'] in [ 13, 14, 17, 18 ]:
                        # timestamp, ts reply, address mask request and mask replies have the extra fields
                        icmp_extra = {}
                        (icmp_extra['icmp_id'], icmp_extra['icmp_seq']) = struct.unpack(">HH", packetdata['icmp_payload'][0:3])
                    else:
                        icmp_extra = { 'icmp_id' : None, 'icmp_seq': None }

                    self._sql("""INSERT INTO icmphdr (sid, cid, icmp_type, icmp_code, icmp_csum, icmp_id, icmp_seq)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)""", (sensor_id, alert_id, packetdata['icmp_type'],
                            packetdata['icmp_code'], packetdata['icmp_chksum'], icmp_extra['icmp_id'], icmp_extra['icmp_seq']))
                    self._sql("""INSERT INTO data (sid, cid, data_payload)
                            VALUES (%s, %s, %s)""", (sensor_id, alert_id, hexlify(packetdata['icmp_payload'])))
		else:
		    log.warning("No valid packet type identified")

                if alert_id > starting_alert_id:
                    self._sql("""INSERT INTO event (sid, cid, signature, timestamp) VALUES (%s, %s, %s, %s)""",
                        ( sensor_id, alert_id, signature_id, timestamp))
                alert_id = alert_id +1

        if alert_id > starting_alert_id:
            self.sensor_ids[sensor_name]['alert_id'] = alert_id -1
        else:
            self.sensor_ids[sensor_name]['alert_id'] = alert_id

            
    def get_sensor_id(self, sensor_name):
        if sensor_name not in self.sensor_ids:
            sid_info = self._sql("""SELECT sid FROM sensor WHERE (hostname = %s) AND (interface = 'charlotte')""", (sensor_name,))
            if len(sid_info) == 0:
                # Need to create a new sensor
                self._sql("""INSERT INTO sensor (hostname, interface, detail, encoding)
                    VALUES (%s, %s, 1, 0)""", (sensor_name, 'charlotte'))
                sid_info = self._sql("""SELECT sid FROM sensor WHERE (hostname = %s) AND (interface = 'charlotte')""", (sensor_name,))

            self.sensor_ids[sensor_name] = { 'sensor_id' : sid_info[0]['sid'] }
            log.debug("%s sensor id: %s" % (sensor_name, self.sensor_ids[sensor_name]))
        return self.sensor_ids[sensor_name]

    def get_next_alert_id(self, sensor_name):
        sensor_info = self.sensor_ids[sensor_name]
        if 'alert_id' not in sensor_info:
            # need to pull the maximum 
            last_alert_id = self._sql("""SELECT last_cid FROM sensor WHERE sid = %s""", (sensor_info['sensor_id'],))[0]['last_cid']
            for table in [ 'data', 'event', 'icmphdr', 'iphdr', 'opt', 'tcphdr', 'udphdr' ]:
                alert_id = self._sql("""SELECT MAX(cid) AS last_cid FROM %s WHERE sid = %s""" % (table, '%s'), (sensor_info['sensor_id'],))[0]['last_cid']
                last_alert_id = max( [last_alert_id, alert_id, 1])

            self._sql("""UPDATE sensor SET last_cid = %s WHERE sid = %s""", (last_alert_id, sensor_info['sensor_id']))
            log.debug("%s last alert id: %s" % (sensor_name, last_alert_id))
        else:
            last_alert_id = self.sensor_ids[sensor_name]['alert_id']

        self.sensor_ids[sensor_name]['alert_id'] = last_alert_id + 1
        self._sql("""UPDATE sensor SET last_cid = %s WHERE sid = %s""", (last_alert_id + 1, sensor_info['sensor_id']))
        return last_alert_id + 1

    def get_signature_id(self,event):
        # Is this one in the list?
        sid = event['signature-id']
        gid = event['generator-id']
        if gid not in self.sig_ids:
            self.sig_ids[gid] = {}

        if sid not in self.sig_ids[gid]:
            sig_info = self.maps.get(gid, sid)

            sid_db_info = self._sql("""SELECT sig_id FROM signature WHERE (sig_sid = %s) AND (sig_gid = %s) AND (sig_rev = %s) AND (sig_class_id = %s)
                        AND (sig_priority = %s) AND (sig_name = %s)""", ( sid, gid, sig_info['rev'], event['classification-id'], 
                        event['priority'], sig_info['msg']))
            if len(sid_db_info) == 0:
                # Oops, not in the DB, load it in
                self._sql("""INSERT INTO signature (sig_sid, sig_gid, sig_rev, sig_class_id, sig_priority, sig_name)
                        VALUES (%s, %s, %s, %s, %s, %s)""", ( sid, gid, sig_info['rev'], event['classification-id'], event['priority'], sig_info['msg']))
                sid_db_info = self._sql("""SELECT sig_id FROM signature WHERE (sig_sid = %s) AND (sig_gid = %s) AND (sig_rev = %s) AND (sig_class_id = %s)
                                AND (sig_priority = %s) AND (sig_name = %s)""", ( sid, gid, sig_info['rev'], event['classification-id'], 
                                event['priority'], sig_info['msg']))
            self.sig_ids[gid][sid] = sid_db_info[0]['sig_id']

        return self.sig_ids[gid][sid]

    # Check to see if the classification is in the DB, if not, add it and return the classification
    def update_db_classification(self,classid):
        if classid not in self.classification_ids:
            # check the DB
            class_info = self._sql("""SELECT sig_class_name FROM sig_class WHERE sig_class_id = %s""", (classid,))
            if len(class_info) == 0:
                # Not in the DB, load it in
                classinfo = self.maps.get(classid)
                self._sql("""INSERT INTO sig_class (sig_class_id, sig_class_name)
                    VALUES (%s, %s)""", (classid, classinfo['name']))
            elif class_info[0]['sig_class_name'] != self.maps.get(classid)['name']:
                # Update the DB
                self._sql("""UPDATE sig_class SET sig_class_name = %s WHERE sig_class_id = %s""", (self.maps.get(classid)['name'], classid))

            self.classification_ids[classid] = class_info
        return True
