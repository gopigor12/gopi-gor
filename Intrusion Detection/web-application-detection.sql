
_sourceCategory=Labs/Apache/* 
| parse regex field=_raw "(?<raw_log>.*)" 
| parse regex field=raw_log "(?i)content-length:\s*(?<header_size>\d+)" 
| where method == "POST" AND (header_size > 500 OR status_code == "413")
