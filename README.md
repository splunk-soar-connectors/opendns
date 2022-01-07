[comment]: # "Auto-generated SOAR connector documentation"
# OpenDNS Investigate

Publisher: Splunk  
Connector Version: 2\.0\.3  
Product Vendor: OpenDNS  
Product Name: OpenDNS Investigate  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.6\.19142  

This app implements investigative actions by querying the OpenDNS Investigate cloud service

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a OpenDNS Investigate asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**apikey** |  required  | password | OpenDNS API key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity  
[domain reputation](#action-domain-reputation) - Query OpenDNS for domain info  
[ip reputation](#action-ip-reputation) - Query OpenDNS for IP info  
[whois domain](#action-whois-domain) - Run a whois query on OpenDNS for the given domain  

## action: 'test connectivity'
Validate the asset configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'domain reputation'
Query OpenDNS for domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.category\_info\.content\_categories | string | 
action\_result\.data\.\*\.category\_info\.security\_categories | string | 
action\_result\.data\.\*\.category\_info\.status | numeric | 
action\_result\.data\.\*\.features\.\*\.feature | string | 
action\_result\.data\.\*\.features\.\*\.normalizedScore | numeric | 
action\_result\.data\.\*\.features\.\*\.score | numeric | 
action\_result\.data\.\*\.relative\_links\.\* | numeric | 
action\_result\.data\.\*\.riskScore | numeric | 
action\_result\.data\.\*\.security\_info\.asn\_score | numeric | 
action\_result\.data\.\*\.security\_info\.attack | string | 
action\_result\.data\.\*\.security\_info\.dga\_score | numeric | 
action\_result\.data\.\*\.security\_info\.entropy | numeric | 
action\_result\.data\.\*\.security\_info\.fastflux | boolean | 
action\_result\.data\.\*\.security\_info\.found | boolean | 
action\_result\.data\.\*\.security\_info\.geodiversity | string | 
action\_result\.data\.\*\.security\_info\.geodiversity\.\* | numeric | 
action\_result\.data\.\*\.security\_info\.geodiversity\_normalized | string | 
action\_result\.data\.\*\.security\_info\.geodiversity\_normalized\.\* | numeric | 
action\_result\.data\.\*\.security\_info\.geoscore | numeric | 
action\_result\.data\.\*\.security\_info\.handlings\.normal | numeric | 
action\_result\.data\.\*\.security\_info\.ks\_test | numeric | 
action\_result\.data\.\*\.security\_info\.pagerank | numeric | 
action\_result\.data\.\*\.security\_info\.perplexity | numeric | 
action\_result\.data\.\*\.security\_info\.popularity | numeric | 
action\_result\.data\.\*\.security\_info\.prefix\_score | numeric | 
action\_result\.data\.\*\.security\_info\.rip\_score | numeric | 
action\_result\.data\.\*\.security\_info\.securerank2 | numeric | 
action\_result\.data\.\*\.security\_info\.threat\_type | string | 
action\_result\.data\.\*\.security\_info\.tld\_geodiversity | string | 
action\_result\.data\.\*\.security\_info\.tld\_geodiversity\.\* | numeric | 
action\_result\.data\.\*\.status\_desc | string | 
action\_result\.data\.\*\.tag\_info\.\*\.attacks | string | 
action\_result\.data\.\*\.tag\_info\.\*\.categories | string | 
action\_result\.data\.\*\.tag\_info\.\*\.category | string | 
action\_result\.data\.\*\.tag\_info\.\*\.period\.begin | string | 
action\_result\.data\.\*\.tag\_info\.\*\.period\.end | string | 
action\_result\.data\.\*\.tag\_info\.\*\.threatTypes | string | 
action\_result\.data\.\*\.tag\_info\.\*\.timestamp | numeric | 
action\_result\.summary\.domain\_status | string |  `domain` 
action\_result\.summary\.riskScore | numeric | 
action\_result\.summary\.total\_co\_occurances | numeric | 
action\_result\.summary\.total\_relative\_links | numeric | 
action\_result\.summary\.total\_tag\_info | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Query OpenDNS for IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string |  `domain` 
action\_result\.summary\.ip\_status | string | 
action\_result\.summary\.total\_blocked\_domains | numeric |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois domain'
Run a whois query on OpenDNS for the given domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.addresses | string | 
action\_result\.data\.\*\.administrativeContactCity | string | 
action\_result\.data\.\*\.administrativeContactCountry | string | 
action\_result\.data\.\*\.administrativeContactEmail | string |  `email` 
action\_result\.data\.\*\.administrativeContactFax | string | 
action\_result\.data\.\*\.administrativeContactFaxExt | string | 
action\_result\.data\.\*\.administrativeContactName | string | 
action\_result\.data\.\*\.administrativeContactOrganization | string | 
action\_result\.data\.\*\.administrativeContactPostalCode | string | 
action\_result\.data\.\*\.administrativeContactState | string | 
action\_result\.data\.\*\.administrativeContactStreet | string | 
action\_result\.data\.\*\.administrativeContactTelephone | string | 
action\_result\.data\.\*\.administrativeContactTelephoneExt | string | 
action\_result\.data\.\*\.auditUpdatedDate | string | 
action\_result\.data\.\*\.billingContactCity | string | 
action\_result\.data\.\*\.billingContactCountry | string | 
action\_result\.data\.\*\.billingContactEmail | string | 
action\_result\.data\.\*\.billingContactFax | string | 
action\_result\.data\.\*\.billingContactFaxExt | string | 
action\_result\.data\.\*\.billingContactName | string | 
action\_result\.data\.\*\.billingContactOrganization | string | 
action\_result\.data\.\*\.billingContactPostalCode | string | 
action\_result\.data\.\*\.billingContactState | string | 
action\_result\.data\.\*\.billingContactStreet | string | 
action\_result\.data\.\*\.billingContactTelephone | string | 
action\_result\.data\.\*\.billingContactTelephoneExt | string | 
action\_result\.data\.\*\.created | string | 
action\_result\.data\.\*\.domainName | string |  `domain` 
action\_result\.data\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.expires | string | 
action\_result\.data\.\*\.hasRawText | boolean | 
action\_result\.data\.\*\.nameServers | string | 
action\_result\.data\.\*\.recordExpired | boolean | 
action\_result\.data\.\*\.registrantCity | string | 
action\_result\.data\.\*\.registrantCountry | string | 
action\_result\.data\.\*\.registrantEmail | string |  `email` 
action\_result\.data\.\*\.registrantFax | string | 
action\_result\.data\.\*\.registrantFaxExt | string | 
action\_result\.data\.\*\.registrantName | string | 
action\_result\.data\.\*\.registrantOrganization | string | 
action\_result\.data\.\*\.registrantPostalCode | string | 
action\_result\.data\.\*\.registrantState | string | 
action\_result\.data\.\*\.registrantStreet | string | 
action\_result\.data\.\*\.registrantTelephone | string | 
action\_result\.data\.\*\.registrantTelephoneExt | string | 
action\_result\.data\.\*\.registrarIANAID | string | 
action\_result\.data\.\*\.registrarName | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.technicalContactCity | string | 
action\_result\.data\.\*\.technicalContactCountry | string | 
action\_result\.data\.\*\.technicalContactEmail | string |  `email` 
action\_result\.data\.\*\.technicalContactFax | string | 
action\_result\.data\.\*\.technicalContactFaxExt | string | 
action\_result\.data\.\*\.technicalContactName | string | 
action\_result\.data\.\*\.technicalContactOrganization | string | 
action\_result\.data\.\*\.technicalContactPostalCode | string | 
action\_result\.data\.\*\.technicalContactState | string | 
action\_result\.data\.\*\.technicalContactStreet | string | 
action\_result\.data\.\*\.technicalContactTelephone | string | 
action\_result\.data\.\*\.technicalContactTelephoneExt | string | 
action\_result\.data\.\*\.timeOfLatestRealtimeCheck | numeric | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.data\.\*\.updated | string | 
action\_result\.data\.\*\.whoisServers | string | 
action\_result\.data\.\*\.zoneContactCity | string | 
action\_result\.data\.\*\.zoneContactCountry | string | 
action\_result\.data\.\*\.zoneContactEmail | string | 
action\_result\.data\.\*\.zoneContactFax | string | 
action\_result\.data\.\*\.zoneContactFaxExt | string | 
action\_result\.data\.\*\.zoneContactName | string | 
action\_result\.data\.\*\.zoneContactOrganization | string | 
action\_result\.data\.\*\.zoneContactPostalCode | string | 
action\_result\.data\.\*\.zoneContactState | string | 
action\_result\.data\.\*\.zoneContactStreet | string | 
action\_result\.data\.\*\.zoneContactTelephone | string | 
action\_result\.data\.\*\.zoneContactTelephoneExt | string | 
action\_result\.summary\.city | string | 
action\_result\.summary\.country | string | 
action\_result\.summary\.organization | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 