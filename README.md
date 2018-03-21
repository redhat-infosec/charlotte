# charlotte
A Snort unified file to database processor, similar to barnyard but with better handling of large Snort deployments

## Introduction
[Snort](https://snort.org/) is a well established Intrusion Detection and Intrusion Prevention service used by many IDS systems.  It generates [unifed2](https://www.snort.org/faq/readme-unified2) file format files that contain alert information.  Some systems consume this data natively, but others, like [Snorby](https://github.com/Snorby/snorby) require the data into a database first.

Typically, this is accomplished with the [barnyard2](https://github.com/firnsy/barnyard2) tool, which picks up unified files and sends them to a database.  However, barnyard2 has some drawbacks that Charlotte seeks to improve upon:
### Originally forked from the snort database code, so written in C which is harder to understand and improve
C is an excellent language, it's fast and well understood.  However, other languages have come along that are far easier to write simple, maintainable code in.  Additionally, since barnyard2 is forked off the database code, it continues to have some cruft in it that can make it hard to understand.

### Does not handle multiple snort instances per "sensor"
In a deployment for a high bandwidth link, often you will need multiple snort instances running per link, using something like [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/) for distributing the packets.  When you do this, it's ideal for all the individual snort instances to show up as a single "sensor" in the database for ease of handling in Snorby or other service.  Charlotte combines an arbitrary number of snort output directories into a single "sensor" in the database.

### Has problems with error handling database/connectivity issues
We had issues with high-latency or low-bandwidth connections causing the database connection to fail.  Charlotte has a retry mechanism to continue to attempt to connect and send alerts.

### Takes up a large amount of RAM per instance
To get around handling long-distance database connections, as well as keep a master copy of all alerts on the central sensornet node, we started using inotify and rsync to copy over the unified files and run barnyard from a master node.  This resulted in a large speed increase as rsync is orders of magnitude faster than database queries, but barnyard can take up quite a bit of RAM to start (see problem above with fork of snort DB code) and running 50+ copies of barnyard was prohibitive.  Charlotte tries to be as low-resource as possible while still get the job done.

### Handle map changes gracefully
In order to update the signature lists, barnyard has to be restarted.  Charlotte monitors the file and dynamically clears its cache and reloads the file if it changes on-disk, making snort updates trivial

## How does it work?
Charlotte's config file will specify one or more sensor "spools" which correspond to snort output directories.  Each spool is given its own process to monitor that directory for new unified files and alerts added.  These are processed by the excellent [py-idstools](https://github.com/jasonish/py-idstools) library into python objects.  These objects are then send via a Queue to the sender which opens and maintains a database connection, sending alerts into a snorby-compatible database schema.  Charlotte keeps track of the last alert and file processed and will start from where it left off when restarted.

Charlotte can be used on each sensor in a barnyard-like fashion, or used centrally with rsynced/network mapped unified file directories.  


## Example config file
```json
{
    "spools": {
        "example1": {
            "directories": [  "/unified/example1" ],
            "filename": "snort.log"
        },
        "example2": {
            "directories": [  "/unified/example2/1", "/unified/example2/2" ],
            "filename": "snort.log"
        }
    },
    "global": {
        "signature_map": "/etc/snort/sid-msg.map/sid-msg.map",
        "generator_map": "/etc/snort/gen-msg.map/gen-msg.map",
        "classification_map": "/etc/snort/classification.config/classification.config"
    },
    "plugin_snortdb": {
        "server": "localhost",
        "user": "charlotte",
        "password": "secretpass",
        "db": "charlotte"
    }
}
```

In this example, there are two snort sensors **example1** and **example2**.  Example1 has only a single snort instance running, so it has one directory specified.  Note that even a single directory should specified as a list.  Example2 has two snort instances, so each base directory is specified.

The *filename* specifies the base name of each unified file.  snort.log is the default for snort, with filenames like snort.log.<timestamp>

*signature_map*, *generator_map*, and *classification_map* are all direct from your snort ruleset, and will be dynamically reloaded if they change.  It's recommended to use the same files as snort is using, to be sure they match.

The snortdb plugin provides an output to MySQL-based databases. the server/user/password/db are all from your snorby/etc setup to be able to add alerts to the database.

## Setup
The init script provided expects a RHEL/CentOS style setup, with an /etc/sysconfig/charlotte file.  In this file should be a CONFIG= line with the path to the charlotte.conf


