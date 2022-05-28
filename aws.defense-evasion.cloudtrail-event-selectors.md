#### Description

This attack simulates an attacker disrupting CloudTrail Logging by creating an event selector on the Trail, excluding out all management events.

#### Run the test

```
└─$ ./stratus detonate aws.defense-evasion.cloudtrail-delete
2022/05/27 21:34:12 Checking your authentication against AWS
2022/05/27 21:34:13 Not warming up - aws.defense-evasion.cloudtrail-delete is already warm. Use --force to force
2022/05/27 21:34:13 Deleting CloudTrail trail my-cloudtrail-trail-2
```

#### Detection 

When it comes to detection, we will track the usage of a particular API call **PutEventSelectors** which is used when we apply event selectors to enable/disable logging of particular events on a existing Cloud Trail.

Inorder to check whether management event logging is being disabled we can use an additional filter on the PutEventSelector log which checks if *includeManagementEvents* entry is false.

```
_sourceCategory=aws/cloudtrail
| json field=_raw "sourceIPAddress" as srcIP nodrop
| json field=_raw "eventName" as eventName nodrop 
| json field=_raw "userIdentity.principalId" as principalid nodrop
| where !(principalid matches "*sumologic*")
| where eventName = "PutEventSelectors"
| json field=_raw "requestParameters.eventSelectors[0].includeManagementEvents" as includemanagementevents nodrop
| where includemanagementevents= "false"
```

![](./Screenshots/11.png)

