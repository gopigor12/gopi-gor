_sourceCategory=Labs/Okta 
| parse "\"ipAddress\":\"*.*.*.*\",\"geographicalContext\":{\"country\":\"*\"}" as source_ip, 
country 
| where _time >= now() - 1h    
| where country != "United States"    
