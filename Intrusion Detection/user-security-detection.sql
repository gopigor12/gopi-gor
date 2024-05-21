/* Successful Logins from Unusual Location 
 
This discussion covers a new query that has been created to detect successful logins from unusual locations 
and then when this query is run, it will give results about all those users and devices that have been accessed 
from outside the country. This means there could be employees outside the country who work, but their IP 
addresses would not be considered malicious once the configuration is set to trust them. Even for testing 
purposes, if they are found to be outside, their IP address can always be verified. */

_sourceCategory=Labs/Okta 
| parse "\"ipAddress\":\"*.*.*.*\",\"geographicalContext\":{\"country\":\"*\"}" as source_ip, 
country 
| where _time >= now() - 1h    
| where country != "United States"    

/*In the above query, we have used the Okta log source which we used in the user security monitoring lab. 
Now we are looking for IP addresses and the country from which the IP address has been logging in. For this, 
we parse the IP address and country from which the requests have come in. The parse command allows us 
to parse the 2 fields from the raw log source. The next line of the query, the time window, in this case has 
been set to the past hour, and thus where clause looks for all requests made within the past hour and parses 
the IP and countries. The last line of the query is more like a filter where it looks for the country which does 
not match United states. This would show suspicious logins outside the United States and the IP address 
would be visible as well. This is a very simple query to quickly detect outside IP addresses in the organization 
if their operations run only in a specific country. */
