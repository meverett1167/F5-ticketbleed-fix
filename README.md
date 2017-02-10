# F5-ticketbleed-fix
Python script for connecting to F5 appliances and mitigating ticketbleed vulnerability

<h4>Requirements:</h4>
F5 Python SDK (https://github.com/F5Networks/f5-common-python)

<h4>usage:</h4>
python F5-ticketbleed-fix.py <options><br> 
  <b>Options:</b><br> 
* -c --bigip_creds</t>  --> bigip_creds file, json file.  Optional, if not listed will look for bigip_creds.json in project base directory
* -m --mititgate    --> optional flag, if set, will modify all vulnerable Client SSL Profiles by disabling SessionTicket setting
    
