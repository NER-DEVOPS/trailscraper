"""Functions to get CloudTrail records from disk"""
import datetime
import re
import gzip
import json
import logging
import os
import re
import pprint

import boto3
import pytz
from toolz import pipe
from toolz.curried import filter as filterz

from toolz.curried import last as lastz
from toolz.curried import map as mapz
from toolz.curried import mapcat as mapcatz
from toolz.curried import sorted as sortedz

from trailscraper.boto_service_definitions import operation_definition
from trailscraper.iam import Statement, Action

ALL_RECORDS_FILTERED = "No records matching your criteria found! Did you use the right filters? " \
                       "Did you download the right logfiles? "\
                       "It might take about 15 minutes for events to turn up in CloudTrail logs."


class Record:
    """Represents a CloudTrail record"""

    # pylint: disable=too-many-arguments
    def __init__(self, event_source, event_name,
                 resource_arns=None, assumed_role_arn=None, event_time=None, raw_source=None):
        self.event_source = event_source
        self.event_name = event_name
        self.raw_source = raw_source
        self.event_time = event_time
        self.resource_arns = resource_arns or ["*"]
        self.assumed_role_arn = assumed_role_arn

    def __repr__(self):
        return "Record(event_source={} event_name={} event_time={} resource_arns={})" \
            .format(self.event_source, self.event_name, self.event_time, self.resource_arns)

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.event_source == other.event_source and \
                   self.event_name == other.event_name and \
                   self.event_time == other.event_time and \
                   self.resource_arns == other.resource_arns and \
                   self.assumed_role_arn == other.assumed_role_arn

        return False

    def __hash__(self):
        return hash((self.event_source,
                     self.event_name,
                     self.event_time,
                     tuple(self.resource_arns),
                     self.assumed_role_arn))

    def __ne__(self, other):
        return not self.__eq__(other)

    def _source_to_iam_prefix(self):
        special_cases = {
            'monitoring.amazonaws.com': 'cloudwatch',
            'appstream2.amazonaws.com': 'appstream',
            'models.lex.amazonaws.com': 'lex',
            'runtime.lex.amazonaws.com': 'lex',
            'mturk-requester.amazonaws.com': 'mechanicalturk',
            'streams.dynamodb.amazonaws.com': 'dynamodb',
            'tagging.amazonaws.com': 'tag',
        }

        default_case = self.event_source.split('.')[0]

        return special_cases.get(self.event_source, default_case)

    def _event_name_to_iam_action(self):
        special_cases = {
            's3.amazonaws.com': {
                'CompleteMultipartUpload': 'PutObject',
                'CopyObject': 'PutObject',
                'CreateMultipartUpload': 'PutObject',
                'DeleteBucketAnalyticsConfiguration': 'PutAnalyticsConfiguration',
                'DeleteBucketEncryption': 'PutEncryptionConfiguration',
                'DeleteBucketInventoryConfiguration': 'PutInventoryConfiguration',
                'DeleteBucketLifecycle': 'PutLifecycleConfiguration',
                'DeleteBucketMetricsConfiguration': 'PutMetricsConfiguration',
                'DeleteBucketReplication': 'DeleteReplicationConfiguration',
                'DeleteBucketTagging': 'PutBucketTagging',
                'DeleteObjects': 'DeleteObject',
                'GetBucketAccelerateConfiguration': 'GetAccelerateConfiguration',
                'GetBucketAnalyticsConfiguration': 'GetAnalyticsConfiguration',
                'GetBucketEncryption': 'GetEncryptionConfiguration',
                'GetBucketInventoryConfiguration': 'GetInventoryConfiguration',
                'GetBucketLifecycle': 'GetLifecycleConfiguration',
                'GetBucketLifecycleConfiguration': 'GetLifecycleConfiguration',
                'GetBucketMetricsConfiguration': 'GetMetricsConfiguration',
                'GetBucketNotificationConfiguration': 'GetBucketNotification',
                'GetBucketReplication': 'GetReplicationConfiguration',
                'HeadBucket': 'ListBucket',
                'HeadObject': 'GetObject',
                'ListBucketAnalyticsConfigurations': 'GetAnalyticsConfiguration',
                'ListBucketInventoryConfigurations': 'GetInventoryConfiguration',
                'ListBucketMetricsConfigurations': 'GetMetricsConfiguration',
                'ListBuckets': 'ListAllMyBuckets',
                'ListMultipartUploads': 'ListBucketMultipartUploads',
                'ListObjectVersions': 'ListBucketVersions',
                'ListObjects': 'ListBucket',
                'ListObjectsV2': 'ListBucket',
                'ListParts': 'ListMultipartUploadParts',
                'PutBucketAccelerateConfiguration': 'PutAccelerateConfiguration',
                'PutBucketAnalyticsConfiguration': 'PutAnalyticsConfiguration',
                'PutBucketEncryption': 'PutEncryptionConfiguration',
                'PutBucketInventoryConfiguration': 'PutInventoryConfiguration',
                'PutBucketLifecycle': 'PutLifecycleConfiguration',
                'PutBucketLifecycleConfiguration': 'PutLifecycleConfiguration',
                'PutBucketMetricsConfiguration': 'PutMetricsConfiguration',
                'PutBucketNotificationConfiguration': 'PutBucketNotification',
                'PutBucketReplication': 'DeleteReplicationConfiguration',
                'UploadPart': 'PutObject',
                'UploadPartCopy': 'PutObject',
            },
            'kms.amazonaws.com': {
                'ReEncrypt': 'ReEncrypt*'  # not precise. See #27 for more details.
            }
        }

        def _regex_sub(expr, subs):
            regex = re.compile(expr)
            return lambda s: regex.sub(subs, s)

        def _special_case_mappings(event_name):
            return special_cases \
                .get(self.event_source, {}) \
                .get(event_name, event_name)

        return pipe(self.event_name,
                    _special_case_mappings,
                    _regex_sub(r"DeleteBucketCors", "PutBucketCORS"),
                    _regex_sub(r"([a-zA-Z]+)[0-9v_]+$", r"\1", ),
                    _regex_sub(r"Cors$", "CORS"))

    def _to_api_gateway_statement(self):
        op_def = operation_definition("apigateway", self.event_name)

        http_method = op_def['http']['method']
        request_uri = op_def['http']['requestUri']

        resource_path = re.compile(r"{[a-zA-Z_]+}").sub("*", request_uri)

        region = "*"  # use proper region from requestParameters

        return Statement(
            Effect="Allow",
            Action=[Action("apigateway", http_method)],
            Resource=["arn:aws:apigateway:{}::{}".format(region, resource_path)]
        )

    def to_statement(self):
        """Converts record into a matching IAM Policy Statement"""
        if self.event_source == "sts.amazonaws.com" and self.event_name == "GetCallerIdentity":
            return None
        if self.event_name == "ConsoleLogin":
            return None
        
        if self.event_source == "apigateway.amazonaws.com":
            return self._to_api_gateway_statement()
        ip = self.raw_source['sourceIPAddress']
        agent = self.raw_source['userAgent']
        
        return Statement(
            Effect="Allow",
            Action=[Action(self._source_to_iam_prefix(), self._event_name_to_iam_action())],
            Resource=sorted(list(set(self.resource_arns))),
            #Condition=[ "user" + _user_arns(self.raw_source) ]
            Condition=[ ]
            #'IpAddress' : {
            #        'aws:SourceIp' : [ { 'agent':  agent, 'ip': ip } ]
            #    }
            #}
            
        )

def debug(name, value):
    pass

class LogFile:
    """Represents a single CloudTrail Log File"""

    def __init__(self, path):
        self._path = path

    def timestamp(self):
        """Returns the timestamp the log file was delivered"""

        timestamp_part = self.filename().split('_')[3]
        return datetime.datetime.strptime(timestamp_part, "%Y%m%dT%H%MZ").replace(tzinfo=pytz.utc)

    def filename(self):
        """Name of the logfile (without path)"""
        return os.path.split(self._path)[-1]

    def has_valid_filename(self):
        """Returns if the log file represented has a valid filename"""
        pattern = re.compile(r"[0-9]+_CloudTrail_[a-z0-9-]+_[0-9TZ]+_[a-zA-Z0-9]+\.json\.gz")
        return pattern.match(self.filename())

    def records(self):
        """Returns CloudTrail Records in this log file"""
        logging.debug("Loading %s", self._path)

        try:
            with gzip.open(self._path, 'rt') as unzipped:
                json_data = json.load(unzipped)
                records = json_data
                return parse_records(records)
        except (IOError, OSError) as error:
            logging.warning("Could not load %s: %s", self._path, error)
            return []

    def contains_events_for_timeframe(self, from_date, to_date):
        """Returns true if this logfile likely contains events in the relevant timeframe"""
        return from_date <= self.timestamp() <= to_date + datetime.timedelta(hours=1)


def _resource_arns(json_record):
    error = json_record.get('errorMessage')
    if error :
        if 'does not exist on EventBus default.' in error:
            return []
        
        if 'The role with name' in error:
            return []
        if 'Function not found' in error:
            return []
        if 'Stack for' in error:            
            return []
        if  "have an EventInvokeConfig" in error:
            return []
        if error in ('An unknown error occurred',
                     'The resource you requested does not exist.',
                     'The specified bucket does not have a website configuration',
                     'The replication configuration was not found',
                     'MultiFactorAuthentication failed with invalid MFA one time pass code. ',
                     'The bucket policy does not exist',
                     'The server side encryption configuration was not found',
                     'The specified log group does not exist.'):
            return []

        if error == 'Access Denied':
            
            if 'requestParameters' in json_record:
                if 'bucketName' in json_record['requestParameters']:
                    return [ 'arn:s3:' + json_record['requestParameters']['bucketName'] ]
            return []
        
        g = re.match(r'User: arn:aws:sts::(?P<account>\w+):assumed-role/(?P<role_name>[\w\-]+)/(?P<session_name>[\-\w\.]+) is not authorized to perform: (?P<eventSource>[\w\-]+):(?P<eventName>\w+) on resource: (?P<resource>.+)', error)
        #             'User: arn:aws:sts::106715121600:assumed-role/secureauth-saml/jdupont is not authorized to perform: health:DescribeEventAggregates on resource: *'
        if g :
            return [g.groupdict()['resource']]
        else:
            g = re.match(r'User: arn:aws:sts::(?P<account>\w+):assumed-role/(?P<role_name>[\w\-]+)/(?P<session_name>\w+) is not authorized to perform: (?P<eventSource>\w+):(?P<eventName>\w+)', error)
            if g :
                return []
            else:

                g = re.match(r'User: arn:aws:iam::(?P<account>\w+):user/(?P<user_name>[\w\.\-]+) is not authorized to perform: (?P<eventSource>\w+):(?P<eventName>\w+) on resource: (?P<resource>.+)', error)
                if g :
                    return [g.groupdict()['resource']]
                else:        
                    g = re.match(r'User: arn:aws:iam::(?P<account>\w+):user/(?P<user_name>[\w\.\-]+) is not authorized to perform: (?P<eventSource>\w+):(?P<eventName>\w+)', error)
                    if g :
                        return []
                    else:        
                        print(error)
                        #raise Exception(error)
        
    resources = json_record.get('resources', [])
    arns = [resource['ARN'] for resource in resources if 'ARN' in resource]

    if 'requestParameters' in json_record:
        params = json_record['requestParameters']
        if params :            
            if 'arn' in params:
                arns.append(params['arn'])
            elif 'roleName' in params:
                account_id = json_record["userIdentity"]["accountId"]
                arns.append("arn:aws:iam::{}:role/{}".format(account_id,params['roleName']))
            elif 'rule' in params:
                account_id = json_record["userIdentity"]["accountId"]
                region = json_record["awsRegion"]
                arns = ["arn:aws:events:{}:{}:rule/{}".format(region, account_id, params['rule'])] # overwrite list
            else:
                if isinstance(params,dict):
                    for key in params:
                        v = params[key]
                        if isinstance(v,dict):
                            if 'arn' in v:                        
                                arns.append(v['arn'])
                            elif 'aws:lambda:FunctionArn' in v:
                                arns.append(v['aws:lambda:FunctionArn'])
                            else:
                                debug("sub1",v)
                                
                        elif isinstance(v,str):
                            if 'arn' in v:
                                arns.append(v)
                            else:
                                debug("main",  v)
                        elif isinstance(v,list):
                            for v2 in v :
                                if 'arn' in v2:
                                    if isinstance(v2,str):
                                        arns.append(v2)
                                    else:
                                        arns.append(v2['arn'])
                                else:
                                    debug("somelist",v2)
                else:
                    debug("other", params)

    response_elements = json_record.get('responseElements', [])
    if response_elements:
        if 'arn' in response_elements:
            arns.append(response_elements['arn'])
        elif 'ruleArn' in response_elements:
            arns.append(response_elements['ruleArn'])
        else:
            if isinstance(response_elements,dict):
                for key in response_elements:
                    v = response_elements[key]
                    if isinstance(v,dict):
                        if 'arn' in v:                        
                            arns.append(v['arn'])
                        elif 'aws:lambda:FunctionArn' in v:
                            arns.append(v['aws:lambda:FunctionArn'])
                        else:
                            debug("sub2",v)
                    else:
                        if isinstance(v,str):
                            if 'arn' in v:
                                arns.append(v)
                            else:
                                debug("main", v)
                        else:
                            debug("v", v)
            else:
                debug("other", response_elements)
    return arns

def _user_arns(json_record):
    error = json_record.get('errorMessage')
    if error :
        g = re.match(r'User: (?P<user_arn>arn:[:/\w\-.]+) is not authorized to perform:(.*)', error)
        if g :
            return g.groupdict()['user_arn']
        if error == 'An unknown error occurred' :
            return json_record['userIdentity']['arn']
        if error == 'Access Denied':
            if 'arn' in json_record['userIdentity']:
                return json_record['userIdentity']['arn']

    if 'userIdentity' in json_record:
        if 'accountId' in json_record['userIdentity']:
            return json_record['userIdentity']['accountId']


    resources = json_record.get('resources', [])
    arns = [resource['ARN'] for resource in resources if 'ARN' in resource]
    return arns


def _assumed_role_arn(json_record):
    user_identity = json_record['userIdentity']
    if 'type' in user_identity \
            and user_identity['type'] == 'AssumedRole' \
            and 'sessionContext' in user_identity:
        return user_identity['sessionContext']['sessionIssuer']['arn']
    return None


def _parse_record(json_record):
    if '@message' in json_record:
        json_record = json.loads(json_record['@message'])
        
    try:
        return Record(json_record['eventSource'],
                      json_record['eventName'],
                      event_time=datetime.datetime.strptime(json_record['eventTime'],
                                                            "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.utc),
                      resource_arns=_resource_arns(json_record),
                      assumed_role_arn=_assumed_role_arn(json_record),
                      raw_source=json_record)
    except KeyError as error:
        logging.warning("Could not parse %s: %s", json_record, error)
        return None


def parse_records(json_records):
    """Convert JSON Records into Record objects"""
    parsed_records = [_parse_record(record) for record in json_records]
    return [r for r in parsed_records if r is not None]


def _valid_log_files(log_dir):
    def _valid_or_warn(log_file):
        if log_file.has_valid_filename():
            return True

        logging.warning("Invalid filename: %s", log_file.filename())
        return False

    def _to_paths(triple):
        root, _, files_in_dir = triple
        return [os.path.join(root, file_in_dir) for file_in_dir in files_in_dir]

    return pipe(os.walk(log_dir),
                mapcatz(_to_paths),
                mapz(LogFile),
                filterz(_valid_or_warn))


def load_from_dir(log_dir, from_date, to_date):
    """Loads all CloudTrail Records in a file"""
    records = []
    for logfile in _valid_log_files(log_dir):
        if logfile.contains_events_for_timeframe(from_date, to_date):
            records.extend(logfile.records())

    return records


def last_event_timestamp_in_dir(log_dir):
    """Return the timestamp of the most recent event in the given directory"""
    most_recent_file = pipe(_valid_log_files(log_dir),
                            sortedz(key=LogFile.timestamp),
                            lastz,
                            LogFile.records,
                            sortedz(key=lambda record: record.event_time),
                            lastz)

    return most_recent_file.event_time


def process_events_in_dir(log_dir, func):
    """Process events"""
    
    for logfile in _valid_log_files(log_dir):
        print(logfile)



def load_from_api(from_date, to_date,profile):
    """Loads the last 10 hours of cloudtrail events from the API"""
    session  = boto3.session.Session(profile_name=profile)
    client = session.client('cloudtrail')
    paginator = client.get_paginator('lookup_events')
    response_iterator = paginator.paginate(
        StartTime=from_date,
        EndTime=to_date,
    )
    records = []
    for response in response_iterator:
        for event in response['Events']:
            records.append(_parse_record(json.loads(event['CloudTrailEvent'])))

    return records


def _by_timeframe(from_date, to_date):
    return lambda record: record.event_time is None or \
                          (from_date <= record.event_time <= to_date)


def _by_role_arns(arns_to_filter_for):
    if arns_to_filter_for is None:
        arns_to_filter_for = []

    return lambda record: (record.assumed_role_arn in arns_to_filter_for) or (len(arns_to_filter_for) == 0)


def filter_records(records,
                   arns_to_filter_for=None,
                   from_date=datetime.datetime(1970, 1, 1, tzinfo=pytz.utc),
                   to_date=datetime.datetime.now(tz=pytz.utc)):
    """Filter records so they match the given condition"""
    result = list(pipe(records, filterz(_by_timeframe(from_date, to_date)), filterz(_by_role_arns(arns_to_filter_for))))
    if not result and records:
        logging.warning(ALL_RECORDS_FILTERED)

    return result
