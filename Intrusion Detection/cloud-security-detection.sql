_sourceCategory = *AWS* 
| json auto 
| where eventname = "CreatePolicyVersion" 
| where requestParameters.policyArn is not null 
| where requestParameters.setAsDefault = "true" 
| count by userIdentity.userName, eventname, requestParameters.policyArn
