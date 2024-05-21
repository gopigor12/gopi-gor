/* The attack which occurs with the ID – CVE-2023-46589 on Apache Tomcat is due to an improper input 
validation. The HTTP trailer headers were not parsed properly. This results in the treating of a single request 
as multiple requests when sent from behind a reverse proxy.  This occurrence would be due to a trailer 
header exceeding the header size limit. An improper header size limit leads to an incomplete POST request 
which then returns status code between 400 – 500. The incomplete POST requests trigger an error response 
which can have information from the previous request. The detection query for this has been shown and 
explained */

_sourceCategory=Labs/Apache/* 
| parse regex field=_raw "(?<raw_log>.*)" 
| parse regex field=raw_log "(?i)content-length:\s*(?<header_size>\d+)" 
| where method == "POST" AND (header_size > 500 OR status_code == "413")
