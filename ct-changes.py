import boto3
import re

regions = ['us-east-2','us-east-1','us-west-1','us-west-2','ap-southeast-2','eu-central-1']
for region in regions:

    print(f'RUNNING FOR REGION: {region}')

    # cloudTrail client
    cloud_trial_client = boto3.client('cloudtrail', region_name=region)
    # cloud watch log client
    cloud_watch_logs_client = boto3.client('logs', region_name=region)
    # cloud watch client
    cloud_watch_client = boto3.client('cloudwatch', region_name=region)
    # SNS Client
    sns_client = boto3.client('sns', region_name=region)

    '''
        active multi-region CloudTrail
    '''

    # Trails List
    trails_list = cloud_trial_client.list_trails()
    trails = trails_list['Trails']

    trails_name_list = [trail["Name"] for trail in trails]
    print(" \n trails_name_list", trails_name_list)

    # trails description
    trail_desc = cloud_trial_client.describe_trails(
        trailNameList=[]
    )
    print(" \n trail_desc", trail_desc)

    # Multi_region Cloudtrails list
    multi_region_cloudtrails = [
        trail for trail in trail_desc["trailList"] if trail["IsMultiRegionTrail"] is True]

    print(" \n multi_region_cloudtrails", multi_region_cloudtrails)
    
    qualified_multi_region_cts = []
    # Checking for active multi region cloudtrials
    for trail in multi_region_cloudtrails:
        trail_status = cloud_trial_client.get_trail_status(
            Name=trail['TrailARN']
        )
        # Ensuring Identified Multi region CloudTrail is active aws cloudtrail
        if trail_status['IsLogging']:
            print(' \n Multi region CloudTrail is active ', True)
            event_selectors = cloud_trial_client.get_event_selectors(
                TrailName=trail['TrailARN']
            )
            print('Event Selectors: ', event_selectors)
            # Ensuring identified Multi-region Cloudtrail captures all Management Events
            for event_selector in event_selectors['EventSelectors']:
                if event_selector["ReadWriteType"] == "All" and event_selector["IncludeManagementEvents"] is True:
                    qualified_multi_region_cts.append(trail)

    print(' \n Multi_Region_Cloudtrails_List:', qualified_multi_region_cts)

    


    '''
            Metric Filter
    '''

    for multi_region_ct in qualified_multi_region_cts:
        # Getting <cloud_trail_log_group_arn> value from the clouldtrail
        CloudWatchLogsLogGroupArn = multi_region_ct.get("CloudWatchLogsLogGroupArn")
        if CloudWatchLogsLogGroupArn:
            cloud_trail_log_group_arn = CloudWatchLogsLogGroupArn.split(":")[-2]
            print(" \n cloud_trail_log_group_arn", cloud_trail_log_group_arn)            
            try:
                # Getting metric filters
                metric_filters = cloud_watch_logs_client.describe_metric_filters(
                    logGroupName=cloud_trail_log_group_arn
                )
                qualified_filter_pattern = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
                print(" \n metric_filters", metric_filters)
                for metric_filter in metric_filters['metricFilters']:
                    # Checking for valid metric filters
                    if metric_filter["filterPattern"] != qualified_filter_pattern:
                        print(' \n filterPattern not matched...')                    
                    if metric_filter["filterPattern"] == qualified_filter_pattern:

                        print('filterPattern matched ...', metric_filter["filterPattern"])
                        # getting <cloudtrail_cfg_changes_metric>  value
                        for metricName in metric_filter['metricTransformations']:
                            cloudtrail_cfg_changes_metric = metricName['metricName']
                            metricNamespace = metricName['metricNamespace']
                            print(' \n cloudtrail_cfg_changes_metric Name:', cloudtrail_cfg_changes_metric)
                            print(' \n metric Namespace', metricNamespace)

                            '''
                                Alarms
                            '''
                            # Getting list of CloudWatch alarms on the <cloudtrail_cfg_changes_metric>
                            cloud_watch_alarms = cloud_watch_client.describe_alarms_for_metric(
                                MetricName=cloudtrail_cfg_changes_metric,
                                Namespace=metricNamespace
                            )

                            print(' \n cloud_watch_alarms ', cloud_watch_alarms)

                            # SNS Topic Arn
                            sns_topic_arn = ''
                            for metric_alarm in cloud_watch_alarms["MetricAlarms"]:
                                actions = metric_alarm['AlarmActions']
                                # getting sns topic arn from AlarmActions 
                                for alarm_action in actions:
                                    sns_topic_arn = alarm_action
                                    print(' \n sns_topic_arn:  ', sns_topic_arn)
                                    
                            # Remediation part start
                            print(' \n  -----   REMEDIATION PART  -------')

                            # Creating metric filter
                            new_metric_filter = cloud_watch_logs_client.put_metric_filter(
                                logGroupName=cloud_trail_log_group_arn,
                                filterName=cloudtrail_cfg_changes_metric,
                                filterPattern=qualified_filter_pattern,
                                metricTransformations=[
                                    {
                                        'metricName': cloudtrail_cfg_changes_metric,
                                        'metricNamespace': 'CISBenchmark',
                                        'metricValue': '1',
                                        'defaultValue': 123.0,

                                    },
                                ]
                            )

                            print(' \n new_metric_filter: ', new_metric_filter)
                            # Creating a SNS Topic
                            sns_topic = sns_client.create_topic(
                                Name='CT_SNS_TOPIC'
                            )

                            print(' \n SNS TOPIC :', sns_topic)

                            
                            # Creating SNS Subsription
                            sns_subscription = sns_client.subscribe(
                                TopicArn=sns_topic['TopicArn'],
                                Protocol='email',
                                Endpoint='user@email.com'

                            )

                            print(' \n sns_subscription: ', sns_subscription)
                            # Creating an Alarm
                            new_alarm = cloud_watch_client.put_metric_alarm(
                                AlarmName='ct_alarm',
                                AlarmActions=[
                                    sns_topic['TopicArn'],
                                ],
                                MetricName=cloudtrail_cfg_changes_metric,
                                Namespace='CISBenchmark',
                                Statistic='Sum',
                                Period=300,
                                EvaluationPeriods=1,
                                Threshold=1,
                                ComparisonOperator='GreaterThanOrEqualToThreshold'

                            )
                            print(' \n New Alarm:', new_alarm)


            except Exception as e:
                print("failed with error : " + str(e))
                # print(' \n No metric Filter Exist for this Log group', cloud_trail_log_group_arn)
        else:
            print(" \n cloudtrail without log group", multi_region_ct)







