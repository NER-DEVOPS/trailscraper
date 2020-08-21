"""Command Line Interface for Trailscraper"""
import json
import logging
import os
import time
import pprint
import click

import trailscraper
from trailscraper import time_utils, policy_generator
from trailscraper.cloudtrail import load_from_dir, load_from_api, last_event_timestamp_in_dir, filter_records, \
    parse_records, _valid_log_files
from trailscraper.guess import guess_statements
from trailscraper.iam import parse_policy_document
from trailscraper.s3_download import download_cloudtrail_logs

logger = logging.getLogger()
logger.setLevel(logging.INFO)
#logging.getLogger('botocore').setLevel(logging.INFO)
#logging.getLogger('s3transfer').setLevel(logging.INFO)

@click.group()
@click.version_option(version=trailscraper.__version__)
@click.option('--verbose', default=False, is_flag=True)
def root_group(verbose):
    """A command-line tool to get valuable information out of AWS CloudTrail."""


@click.command()
@click.option('--bucket', required=True,
              help='The S3 bucket that contains cloud-trail logs')
@click.option('--prefix', default="",
              help='Prefix in the S3 bucket (including trailing slash)')
@click.option('--account-id', multiple=True, required=True,
              help='ID of the account we want to look at')
@click.option('--region', multiple=True, required=True,
              help='Regions we want to look at')
@click.option('--log-dir', default="~/.trailscraper/logs", type=click.Path(),
              help='Where to put logfiles')
@click.option('--from', 'from_s', default="one day ago", type=click.STRING,
              help='Start date, e.g. "2017-01-01" or "-1days". Defaults to "one day ago".')
@click.option('--to', 'to_s', default="now", type=click.STRING,
              help='End date, e.g. "2017-01-01" or "now". Defaults to "now".')
@click.option('--wait', default=False, is_flag=True,
              help='Wait until events after the specified timeframe are found.')
@click.option('--profile', default="default", help='Profile name')
# pylint: disable=too-many-arguments
def download(bucket, prefix, account_id, region, log_dir, from_s, to_s, wait, profile):
    """Downloads CloudTrail Logs from S3."""
    log_dir = os.path.expanduser(log_dir)

    from_date = time_utils.parse_human_readable_time(from_s)
    to_date = time_utils.parse_human_readable_time(to_s)

    download_cloudtrail_logs(log_dir, bucket, prefix, account_id, region, from_date, to_date, profile)

    if wait:
        last_timestamp = last_event_timestamp_in_dir(log_dir)
        while last_timestamp <= to_date:
            click.echo("CloudTrail logs haven't caught up to "+str(to_date)+" yet. "+
                       "Most recent timestamp: "+str(last_timestamp.astimezone(to_date.tzinfo))+". "+
                       "Trying again in 60sec.")

            time.sleep(60*1)

            download_cloudtrail_logs(log_dir, bucket, prefix, account_id, region, from_date, to_date)
            last_timestamp = last_event_timestamp_in_dir(log_dir)


@click.command("select")
@click.option('--log-dir', default="~/.trailscraper/logs", type=click.Path(),
              help='Where to put logfiles')
@click.option('--filter-assumed-role-arn', multiple=True,
              help='only consider events from this role (can be used multiple times)')
@click.option('--use-cloudtrail-api', is_flag=True, default=False,
              help='Pull Events from CloudtrailAPI instead of log-dir')
@click.option('--from', 'from_s', default="1970-01-01", type=click.STRING,
              help='Start date, e.g. "2017-01-01" or "-1days"')
@click.option('--to', 'to_s', default="now", type=click.STRING,
              help='End date, e.g. "2017-01-01" or "now"')
@click.option('--profile', default="default", help='Profile name')
def select(log_dir, filter_assumed_role_arn, use_cloudtrail_api, from_s, to_s, profile):
    """Finds all CloudTrail records matching the given filters and prints them."""
    log_dir = os.path.expanduser(log_dir)
    from_date = time_utils.parse_human_readable_time(from_s)
    to_date = time_utils.parse_human_readable_time(to_s)

    if use_cloudtrail_api:
        records = load_from_api(from_date, to_date, profile)
    else:
        records = load_from_dir(log_dir, from_date, to_date)

    filtered_records = filter_records(records, filter_assumed_role_arn, from_date, to_date)

    filtered_records_as_json = [record.raw_source for record in filtered_records]

    click.echo(json.dumps({"Records": filtered_records_as_json}))


@click.command("generate")
def generate():
    print ("generate")
    """Generates a policy that allows the events passed in through STDIN"""
    input_file = click.get_text_stream('stdin')
    records = set()
    for line in input_file:
        d = []
        try :
            d.append( json.loads(line))
        except Exception as e:
            print(e)
            print(line)
        records = records.union(parse_records(d))
    policy = policy_generator.generate_policy(records)
    click.echo(policy.to_json())

@click.command("generate2")
@click.argument('input-file', type=click.File('r'))
def generate2(input_file):
#def generate():
    print ("generate")
    """Generates a policy that allows the events passed in through STDIN"""
    #input_file = click.get_text_stream('stdin')
    records = set()
    #import pdb
    #pdb.set_trace()
    for line in input_file:
        d = []
        try :
            d.append( json.loads(line))
        except Exception as e:
            print(e)
            print(line)
        records = records.union(parse_records(d))
    policy = policy_generator.generate_policy(records)
    click.echo(policy.to_json())


@click.command("guess")
@click.option("--only", multiple=True,
              help='Only guess actions with the given prefix, e.g. Describe (can be passed multiple times)')
def guess(only):
    """Extend a policy passed in through STDIN by guessing related actions"""
    stdin = click.get_text_stream('stdin')
    policy = parse_policy_document(stdin)

    allowed_prefixes = [s.title() for s in only]

    policy = guess_statements(policy, allowed_prefixes)
    click.echo(policy.to_json())

@click.command("merge")
@click.option('--log-dir', default="~/.trailscraper/logs", type=click.Path())
def merge(log_dir):
    log_dir = os.path.expanduser(log_dir)
    print (log_dir)
    statements = []
    for logfile in _valid_log_files(log_dir):
        fn = logfile.filename()
        if fn.endswith('policy'):
            print(logfile._path)
            
            with open(logfile._path) as fi:
                try :
                    policy = parse_policy_document(fi)
                except Exception as e:
                    print(e)
                    #pprint.pprint(policy)
                for x in policy.Statement:
                    statements.append(x)
    # apply large merge

    click.echo(policy_generator.merge_policies(statements).to_json())

        #process_events_in_dir(log_dir,)
#    click.echo(last_event_timestamp_in_dir())

#    stdin = click.get_text_stream('stdin')
    
#    
#    allowed_prefixes = [s.title() for s in only]

#    policy = guess_statements(policy, allowed_prefixes)
#    click.echo(policy.to_json())
    

@click.command("last-event-timestamp")
@click.option('--log-dir', default="~/.trailscraper/logs", type=click.Path(),
              help='Where to put logfiles')
def last_event_timestamp(log_dir):
    """Print the most recent cloudtrail event timestamp"""
    log_dir = os.path.expanduser(log_dir)
    click.echo(last_event_timestamp_in_dir(log_dir))


root_group.add_command(download)
root_group.add_command(select)
root_group.add_command(generate)
root_group.add_command(generate2)
root_group.add_command(guess)
root_group.add_command(merge)
root_group.add_command(last_event_timestamp)

#print("hello")
