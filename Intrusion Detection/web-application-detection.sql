/* The attack which occurs with the ID – CVE-2023-46589 on Apache Tomcat is due to an improper input 
validation. The HTTP trailer headers were not parsed properly. This results in the treating of a single request 
as multiple requests when sent from behind a reverse proxy.  This occurrence would be due to a trailer 
header exceeding the header size limit. An improper header size limit leads to an incomplete POST request 
which then returns status code between 400 – 500. The incomplete POST requests trigger an error response 
which can have information from the previous request. The detection query for this has been shown and 
explained */

_sourceCategory=Labs/Apache/"*"
| parse regex field=_raw "(?<raw_log>.*)" 
| parse regex field=raw_log "(?i)content-length:\s*(?<header_size>\d+)" 
| where method == "POST" AND (header_size > 500 OR status_code == "413")

/*First, we select the source category as the log source we want to use in this query. Now, to get all the HTTP 
header details, we need to look at the raw log source. In the second line, a new field called raw_log is created, 
and the complete raw log message is extracted. The next line looks for the case-insensitive part in content 
length with (?i) and gathers the numeric value into a new field called header_size. Finally, as per the 
vulnerability, the attack occurs on POST requests, so we use the where clause to look for POST requests in 
the “method” field and filter on the basis of header size > 500 or status_code = 413. We want to make sure 
that we get all POST requests that may have an unexpectedly big header size or a status code of 413 to 
denote a large payload.*/
