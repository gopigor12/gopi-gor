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
