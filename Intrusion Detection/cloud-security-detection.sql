/* The cloud security detection is being used to detect anomalous activity on the log source we used on the 
previous lab assignment. My query is focused on privilege escalation in the cloud, and the query below 
monitors any changes in Identity and Access Management, policies, or procedures which can be shown as 
an attempt to escalate privileges. */

_sourceCategory = *AWS* 
| json auto 
| where eventname = "CreatePolicyVersion" 
| where requestParameters.policyArn is not null 
| where requestParameters.setAsDefault = "true" 
| count by userIdentity.userName, eventname, requestParameters.policyArn


/* We have used the *AWS* category to select all possible AWS sources and then the json auto command 
allows us to parse the logs in JSON format, which we can then analyze and extract as needed.  
We are looking for events where a new policy version has been created which usually denotes when a new 
version for IAM policies is created, and so the next line logs for events where eventname is 
“CreatePolicyVersion”. The arn is a unique identified when we talk about IAM policies, and the next line looks 
for all fields where that is not null, since we are detecting IAM changes. Additionally, we also wanted to 
check if this IAM policy has been set to default to check if there is any actual privilege escalation taking place, 
as attackers would generally make IAM changes and then make them the defaults to use in all cases, which 
gives them a backdoor like access.  
Finally, we have counted the filters and placed them in the count by as the useridentity – as name; 
eventname, to show us the event we are looking for, and then the request parameters to show the unique 
IAM identification. */
