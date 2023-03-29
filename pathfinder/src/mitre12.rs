

use std::collections::HashMap;

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
         let mut map = ::std::collections::HashMap::new();
         $( map.insert($key, $val); )*
         map
    }}
}

#[derive(Debug)]
pub struct Hnode<'a> {
    d : &'a str ,
    t : &'a str ,
    o : Vec< &'a str>, 
    s : Option< HashMap<&'a str, Hnode<'a> >>
}


impl<'a> Hnode<'a> {
    pub fn get_listing( &self ) -> &Vec<&'a str> {
        & self.o
    }
    pub fn get_sub(&self) -> Option< Vec< &'a str>> {
        match &self.s {
            Some( v ) => Some( v.keys().cloned().collect()),
            None => None
        }
    }
    pub fn get_des(&self, cat: &'a str) -> String{
        match &self.s {
            Some( v ) => match &v.get( cat ) {
                Some( x ) => { String::from( x.d ) },
                None => String::from(" -- not found  -- ")
            },
            None => String::from("- NA -")
        }
    }
    pub fn get_child(&self, cat : &'a str )-> Option<&Hnode<'a>> {
        match &self.s {
            Some( v ) => match &v.get( cat ) {
                Some( x ) =>  Some( x ),
                None => None
            },
            None => None
        }
        
    }
}


pub fn mitre12() -> Hnode<'static> {

// processing MITRE12org.pkl
 Hnode{
	d:"_",
	t:"None",
	o:vec!["Reconnaissance","ResourceDevelopment","InitialAccess","Execution","Persistence","PrivilegeEscalation","DefenseEvasion","CredentialAccess","Discovery","LateralMovement","Collection","CommandandControl","Exfiltration","Impact"],
	s:Some(hashmap!( 
	"Reconnaissance" => 	Hnode{ 
		d:"safe_str(The adversary is trying to gather information they can use to plan future operations.Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.)",
		t:"None",
		o:vec!["Active Scanning","Gather Victim Host Information","Gather Victim Identity Information","Gather Victim Network Information","Gather Victim Org Information","Phishing for Information","Search Closed Sources","Search Open Technical Databases","Search Open Websites/Domains","Search Victim-Owned Websites"],
		s: Some(
			hashmap!(
				"Active Scanning" => 		 Hnode{ 
			d:"Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.",
			t:"T1595",
			o:vec!["Scanning IP Blocks","Vulnerability Scanning","Wordlist Scanning"],
			s: Some(
				hashmap!(
					"Scanning IP Blocks" => Hnode{ d:"Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses.", t:".001", o:vec![], s: None }  ,
					"Vulnerability Scanning" => Hnode{ d:"Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific exploit the adversary may seek to use.", t:".002", o:vec![], s: None }  ,
					"Wordlist Scanning" => Hnode{ d:"Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to Brute Force, its goal is the identification of content and infrastructure rather than the discovery of valid credentials. Wordlists used in these scans may contain generic, commonly used names and file extensions or terms specific to a particular software. Adversaries may also create custom, target-specific wordlists using data gathered from other Reconnaissance techniques (ex: Gather Victim Org Information, or Search Victim-Owned Websites).", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Gather Victim Host Information" => 		 Hnode{ 
			d:"Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).",
			t:"T1592",
			o:vec!["Hardware","Software","Firmware","Client Configurations"],
			s: Some(
				hashmap!(
					"Hardware" => Hnode{ d:"Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.).", t:".001", o:vec![], s: None }  ,
					"Software" => Hnode{ d:"Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: antivirus, SIEMs, etc.).", t:".002", o:vec![], s: None }  ,
					"Firmware" => Hnode{ d:"Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment (ex: configuration, purpose, age/patch level, etc.).", t:".003", o:vec![], s: None }  ,
					"Client Configurations" => Hnode{ d:"Adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system/version, virtualization, architecture (ex: 32 or 64 bit), language, and/or time zone.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Gather Victim Identity Information" => 		 Hnode{ 
			d:"Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, etc.) as well as sensitive details such as credentials.",
			t:"T1589",
			o:vec!["Credentials","Email Addresses","Employee Names"],
			s: Some(
				hashmap!(
					"Credentials" => Hnode{ d:"Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts.", t:".001", o:vec![], s: None }  ,
					"Email Addresses" => Hnode{ d:"Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees.", t:".002", o:vec![], s: None }  ,
					"Employee Names" => Hnode{ d:"Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Gather Victim Network Information" => 		 Hnode{ 
			d:"Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.",
			t:"T1590",
			o:vec!["Domain Properties","DNS","Network Trust Dependencies","Network Topology","IP Addresses","Network Security Appliances"],
			s: Some(
				hashmap!(
					"Domain Properties" => Hnode{ d:"Adversaries may gather information about the victim's network domain(s) that can be used during targeting. Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers.", t:".001", o:vec![], s: None }  ,
					"DNS" => Hnode{ d:"Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. DNS, MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk.", t:".002", o:vec![], s: None }  ,
					"Network Trust Dependencies" => Hnode{ d:"Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access.", t:".003", o:vec![], s: None }  ,
					"Network Topology" => Hnode{ d:"Adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments. This information may also include specifics regarding network devices (gateways, routers, etc.) and other infrastructure.", t:".004", o:vec![], s: None }  ,
					"IP Addresses" => Hnode{ d:"Adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety of details, such as which IP addresses are in use. IP addresses may also enable an adversary to derive other details about a victim, such as organizational size, physical location(s), Internet service provider, and or where/how their publicly-facing infrastructure is hosted.", t:".005", o:vec![], s: None }  ,
					"Network Security Appliances" => Hnode{ d:"Adversaries may gather information about the victim's network security appliances that can be used during targeting. Information about network security appliances may include a variety of details, such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts. Adversaries may also target information about victim network-based intrusion detection systems (NIDS) or other appliances related to defensive cybersecurity operations.", t:".006", o:vec![], s: None }  
				)
			)} ,
				"Gather Victim Org Information" => 		 Hnode{ 
			d:"Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.",
			t:"T1591",
			o:vec!["Determine Physical Locations","Business Relationships","Identify Business Tempo","Identify Roles"],
			s: Some(
				hashmap!(
					"Determine Physical Locations" => Hnode{ d:"Adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within.", t:".001", o:vec![], s: None }  ,
					"Business Relationships" => Hnode{ d:"Adversaries may gather information about the victim's business relationships that can be used during targeting. Information about an organization’s business relationships may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. This information may also reveal supply chains and shipment paths for the victim’s hardware and software resources.", t:".002", o:vec![], s: None }  ,
					"Identify Business Tempo" => Hnode{ d:"Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim’s hardware and software resources.", t:".003", o:vec![], s: None }  ,
					"Identify Roles" => Hnode{ d:"Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data/resources they have access to.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Phishing for Information" => 		 Hnode{ 
			d:"Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from Phishing in that the objective is gathering data from the victim rather than executing malicious code.",
			t:"T1598",
			o:vec!["Spearphishing Service","Spearphishing Attachment","Spearphishing Link"],
			s: Some(
				hashmap!(
					"Spearphishing Service" => Hnode{ d:"Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: Establish Accounts or Compromise Accounts) and/or sending multiple, seemingly urgent messages.", t:".001", o:vec![], s: None }  ,
					"Spearphishing Attachment" => Hnode{ d:"Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: Establish Accounts or Compromise Accounts) and/or sending multiple, seemingly urgent messages.", t:".002", o:vec![], s: None }  ,
					"Spearphishing Link" => Hnode{ d:"Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: Establish Accounts or Compromise Accounts) and/or sending multiple, seemingly urgent messages.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Search Closed Sources" => 		 Hnode{ 
			d:"Adversaries may search and gather information about victims from closed sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical/threat intelligence data. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.",
			t:"T1597",
			o:vec!["Threat Intel Vendors","Purchase Technical Data"],
			s: Some(
				hashmap!(
					"Threat Intel Vendors" => Hnode{ d:"Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures.", t:".001", o:vec![], s: None }  ,
					"Purchase Technical Data" => Hnode{ d:"Adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan databases or other data aggregation services. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Search Open Technical Databases" => 		 Hnode{ 
			d:"Adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans.",
			t:"T1596",
			o:vec!["DNS/Passive DNS","WHOIS","Digital Certificates","CDNs","Scan Databases"],
			s: Some(
				hashmap!(
					"DNS/Passive DNS" => Hnode{ d:"Adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts.", t:".001", o:vec![], s: None }  ,
					"WHOIS" => Hnode{ d:"Adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names. Anyone can query WHOIS servers for information about a registered domain, such as assigned IP blocks, contact information, and DNS nameservers.", t:".002", o:vec![], s: None }  ,
					"Digital Certificates" => Hnode{ d:"Adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content. These certificates, such as those used for encrypted web traffic (HTTPS SSL/TLS communications), contain information about the registered organization such as name and location.", t:".003", o:vec![], s: None }  ,
					"CDNs" => Hnode{ d:"Adversaries may search content delivery network (CDN) data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region.", t:".004", o:vec![], s: None }  ,
					"Scan Databases" => Hnode{ d:"Adversaries may search within public scan databases for information about victims that can be used during targeting. Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Search Open Websites/Domains" => 		 Hnode{ 
			d:"Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts.",
			t:"T1593",
			o:vec!["Social Media","Search Engines","Code Repositories"],
			s: Some(
				hashmap!(
					"Social Media" => Hnode{ d:"Adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff.", t:".001", o:vec![], s: None }  ,
					"Search Engines" => Hnode{ d:"Adversaries may use search engines to collect information about victims that can be used during targeting. Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content (i.e. filetypes).", t:".002", o:vec![], s: None }  ,
					"Code Repositories" => Hnode{ d:"Adversaries may search public code repositories for information about victims that can be used during targeting. Victims may store code in repositories on various third-party websites such as GitHub, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Search Victim-Owned Websites" => 		 Hnode{ 
			d:"Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: Email Addresses). These sites may also have details highlighting business operations and relationships.",
			t:"T1594",
			o:vec![],
			s: None } 
			)
		)} ,
	"ResourceDevelopment" => 	Hnode{ 
		d:"safe_str(The adversary is trying to establish resources they can use to support operations.Resource Development consists of techniques that involve adversaries creating, purchasing, or compromising/stealing resources that can be used to support targeting. Such resources include infrastructure, accounts, or capabilities. These resources can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using purchased domains to support Command and Control, email accounts for phishing as a part of Initial Access, or stealing code signing certificates to help with Defense Evasion.)",
		t:"None",
		o:vec!["Acquire Infrastructure","Compromise Accounts","Compromise Infrastructure","Develop Capabilities","Establish Accounts","Obtain Capabilities","Stage Capabilities"],
		s: Some(
			hashmap!(
				"Acquire Infrastructure" => 		 Hnode{ 
			d:"Adversaries may buy, lease, or rent infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services. Additionally, botnets are available for rent or purchase.",
			t:"T1583",
			o:vec!["Domains","DNS Server","Virtual Private Server","Server","Botnet","Web Services","Serverless"],
			s: Some(
				hashmap!(
					"Domains" => Hnode{ d:"Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free.", t:".001", o:vec![], s: None }  ,
					"DNS Server" => Hnode{ d:"Adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: Application Layer Protocol). Instead of hijacking existing DNS servers, adversaries may opt to configure and run their own DNS servers in support of operations.", t:".002", o:vec![], s: None }  ,
					"Virtual Private Server" => Hnode{ d:"Adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them. The use of cloud infrastructure can also make it easier for adversaries to rapidly provision, modify, and shut down their infrastructure.", t:".003", o:vec![], s: None }  ,
					"Server" => Hnode{ d:"Adversaries may buy, lease, or rent physical servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control. Instead of compromising a third-party Server or renting a Virtual Private Server, adversaries may opt to configure and run their own servers in support of operations.", t:".004", o:vec![], s: None }  ,
					"Botnet" => Hnode{ d:"Adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale Phishing or Distributed Denial of Service (DDoS).", t:".005", o:vec![], s: None }  ,
					"Web Services" => Hnode{ d:"Adversaries may register for web services that can be used during targeting. A variety of popular websites exist for adversaries to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control (Web Service) or Exfiltration Over Web Service. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, adversaries can make it difficult to physically tie back operations to them.", t:".006", o:vec![], s: None }  ,
					"Serverless" => Hnode{ d:"Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers or AWS Lambda functions, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Compromise Accounts" => 		 Hnode{ 
			d:"Adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. Establish Accounts), adversaries may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona.",
			t:"T1586",
			o:vec!["Social Media Accounts","Email Accounts","Cloud Accounts"],
			s: Some(
				hashmap!(
					"Social Media Accounts" => Hnode{ d:"Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. Social Media Accounts), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona.", t:".001", o:vec![], s: None }  ,
					"Email Accounts" => Hnode{ d:"Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct Phishing for Information or Phishing. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (ex: Domains).", t:".002", o:vec![], s: None }  ,
					"Cloud Accounts" => Hnode{ d:"Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools. Cloud accounts can also be used in the acquisition of infrastructure, such as Virtual Private Servers or Serverless infrastructure. Compromising cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Compromise Infrastructure" => 		 Hnode{ 
			d:"Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, and third-party web and DNS services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle. Additionally, adversaries may compromise numerous machines to form a botnet they can leverage.",
			t:"T1584",
			o:vec!["Domains","DNS Server","Virtual Private Server","Server","Botnet","Web Services","Serverless"],
			s: Some(
				hashmap!(
					"Domains" => Hnode{ d:"Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant. Adversaries may gain access to an email account for the person listed as the owner of the domain. The adversary can then claim that they forgot their password in order to make changes to the domain registration. Other possibilities include social engineering a domain registration help desk to gain access to an account or taking advantage of renewal process gaps.", t:".001", o:vec![], s: None }  ,
					"DNS Server" => Hnode{ d:"Adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: Application Layer Protocol). Instead of setting up their own DNS servers, adversaries may compromise third-party DNS servers in support of operations.", t:".002", o:vec![], s: None }  ,
					"Virtual Private Server" => Hnode{ d:"Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities. By compromising a VPS to use as infrastructure, adversaries can make it difficult to physically tie back operations to themselves.", t:".003", o:vec![], s: None }  ,
					"Server" => Hnode{ d:"Adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control. Instead of purchasing a Server or Virtual Private Server, adversaries may compromise third-party servers in support of operations.", t:".004", o:vec![], s: None }  ,
					"Botnet" => Hnode{ d:"Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Instead of purchasing/renting a botnet from a booter/stresser service, adversaries may build their own botnet by compromising numerous third-party systems. Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale Phishing or Distributed Denial of Service (DDoS).", t:".005", o:vec![], s: None }  ,
					"Web Services" => Hnode{ d:"Adversaries may compromise access to third-party web services that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, etc. Adversaries may try to take ownership of a legitimate user's access to a web service and use that web service as infrastructure in support of cyber operations. Such web services can be abused during later stages of the adversary lifecycle, such as during Command and Control (Web Service) or Exfiltration Over Web Service. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, particularly when access is stolen from legitimate users, adversaries can make it difficult to physically tie back operations to them.", t:".006", o:vec![], s: None }  ,
					"Serverless" => Hnode{ d:"Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers or AWS Lambda functions, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Develop Capabilities" => 		 Hnode{ 
			d:"Adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Adversaries may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.",
			t:"T1587",
			o:vec!["Malware","Code Signing Certificates","Digital Certificates","Exploits"],
			s: Some(
				hashmap!(
					"Malware" => Hnode{ d:"Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Adversaries may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.", t:".001", o:vec![], s: None }  ,
					"Code Signing Certificates" => Hnode{ d:"Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.", t:".002", o:vec![], s: None }  ,
					"Digital Certificates" => Hnode{ d:"Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. In the case of self-signing, digital certificates will lack the element of trust associated with the signature of a third-party certificate authority (CA).", t:".003", o:vec![], s: None }  ,
					"Exploits" => Hnode{ d:"Adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than finding/modifying exploits from online or purchasing them from exploit vendors, an adversary may develop their own exploits. Adversaries may use information acquired via Vulnerabilities to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Establish Accounts" => 		 Hnode{ 
			d:"Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.",
			t:"T1585",
			o:vec!["Social Media Accounts","Email Accounts","Cloud Accounts"],
			s: Some(
				hashmap!(
					"Social Media Accounts" => Hnode{ d:"Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations.", t:".001", o:vec![], s: None }  ,
					"Email Accounts" => Hnode{ d:"Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct Phishing for Information or Phishing. Adversaries may also take steps to cultivate a persona around the email account, such as through use of Social Media Accounts, to increase the chance of success of follow-on behaviors. Created email accounts can also be used in the acquisition of infrastructure (ex: Domains).", t:".002", o:vec![], s: None }  ,
					"Cloud Accounts" => Hnode{ d:"Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools. Cloud accounts can also be used in the acquisition of infrastructure, such as Virtual Private Servers or Serverless infrastructure. Establishing cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Obtain Capabilities" => 		 Hnode{ 
			d:"Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.",
			t:"T1588",
			o:vec!["Malware","Tool","Code Signing Certificates","Digital Certificates","Exploits","Vulnerabilities"],
			s: Some(
				hashmap!(
					"Malware" => Hnode{ d:"Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their operations, obtaining a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.", t:".001", o:vec![], s: None }  ,
					"Tool" => Hnode{ d:"Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: PsExec). Tool acquisition can involve the procurement of commercial software licenses, including for red teaming tools such as Cobalt Strike. Commercial software may be obtained through purchase, stealing licenses (or licensed copies of the software), or cracking trial versions.", t:".002", o:vec![], s: None }  ,
					"Code Signing Certificates" => Hnode{ d:"Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.", t:".003", o:vec![], s: None }  ,
					"Digital Certificates" => Hnode{ d:"Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner.", t:".004", o:vec![], s: None }  ,
					"Exploits" => Hnode{ d:"Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors.", t:".005", o:vec![], s: None }  ,
					"Vulnerabilities" => Hnode{ d:"Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur. Adversaries may find vulnerability information by searching open databases or gaining access to closed vulnerability databases.", t:".006", o:vec![], s: None }  
				)
			)} ,
				"Stage Capabilities" => 		 Hnode{ 
			d:"Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed (Develop Capabilities) or obtained (Obtain Capabilities) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary (Acquire Infrastructure) or was otherwise compromised by them (Compromise Infrastructure). Capabilities may also be staged on web services, such as GitHub or Pastebin, or on Platform-as-a-Service (PaaS) offerings that enable users to easily provision applications.",
			t:"T1608",
			o:vec!["Upload Malware","Upload Tool","Install Digital Certificate","Drive-by Target","Link Target","SEO Poisoning"],
			s: Some(
				hashmap!(
					"Upload Malware" => Hnode{ d:"Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious content. Adversaries may upload malware to support their operations, such as making a payload available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server.", t:".001", o:vec![], s: None }  ,
					"Upload Tool" => Hnode{ d:"Adversaries may upload tools to third-party or adversary controlled infrastructure to make it accessible during targeting. Tools can be open or closed source, free or commercial. Tools can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: PsExec). Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable Ingress Tool Transfer by placing it on an Internet accessible web server.", t:".002", o:vec![], s: None }  ,
					"Install Digital Certificate" => Hnode{ d:"Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems. Digital certificates include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate securely with its owner. Certificates can be uploaded to a server, then the server can be configured to use the certificate to enable encrypted communication with it.", t:".003", o:vec![], s: None }  ,
					"Drive-by Target" => Hnode{ d:"Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in Drive-by Compromise. In such cases, the user's web browser is typically targeted for exploitation (often not requiring any extra user interaction once landing on the site), but adversaries may also set up websites for non-exploitation behavior such as Application Access Token. Prior to Drive-by Compromise, adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired (Acquire Infrastructure) or previously compromised (Compromise Infrastructure).", t:".004", o:vec![], s: None }  ,
					"Link Target" => Hnode{ d:"Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in Malicious Link. Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. Prior to a phish for information (as in Spearphishing Link) or a phish to gain initial access to a system (as in Spearphishing Link), an adversary must set up the resources for a link target for the spearphishing link.", t:".005", o:vec![], s: None }  ,
					"SEO Poisoning" => Hnode{ d:"Adversaries may poison mechanisms that influence search engine optimization (SEO) to further lure staged capabilities towards potential victims. Search engines typically display results to users based on purchased ads as well as the site’s ranking/score/reputation calculated by their web crawlers and algorithms.", t:".006", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"InitialAccess" => 	Hnode{ 
		d:"safe_str(The adversary is trying to get into your network.Initial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.)",
		t:"None",
		o:vec!["Drive-by Compromise","Exploit Public-Facing Application","External Remote Services","Hardware Additions","Phishing","Replication Through Removable Media","Supply Chain Compromise","Trusted Relationship","Valid Accounts"],
		s: Some(
			hashmap!(
				"Drive-by Compromise" => 		 Hnode{ 
			d:"Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring Application Access Token.",
			t:"T1189",
			o:vec![],
			s: None } ,
				"Exploit Public-Facing Application" => 		 Hnode{ 
			d:"Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. These applications are often websites, but can include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other applications with Internet accessible open sockets, such as web servers and related services. Depending on the flaw being exploited this may include Exploitation for Defense Evasion.",
			t:"T1190",
			o:vec![],
			s: None } ,
				"External Remote Services" => 		 Hnode{ 
			d:"Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.",
			t:"T1133",
			o:vec![],
			s: None } ,
				"Hardware Additions" => 		 Hnode{ 
			d:"Adversaries may introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable storage (i.e. Replication Through Removable Media), more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused.",
			t:"T1200",
			o:vec![],
			s: None } ,
				"Phishing" => 		 Hnode{ 
			d:"Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.",
			t:"T1566",
			o:vec!["Spearphishing Attachment","Spearphishing Link","Spearphishing via Service"],
			s: Some(
				hashmap!(
					"Spearphishing Attachment" => Hnode{ d:"Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.", t:".001", o:vec![], s: None }  ,
					"Spearphishing Link" => Hnode{ d:"Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.", t:".002", o:vec![], s: None }  ,
					"Spearphishing via Service" => Hnode{ d:"Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Replication Through Removable Media" => 		 Hnode{ 
			d:"Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.",
			t:"T1091",
			o:vec![],
			s: None } ,
				"Supply Chain Compromise" => 		 Hnode{ 
			d:"Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.",
			t:"T1195",
			o:vec!["Compromise Software Dependencies and Development Tools","Compromise Software Supply Chain","Compromise Hardware Supply Chain"],
			s: Some(
				hashmap!(
					"Compromise Software Dependencies and Development Tools" => Hnode{ d:"Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency.", t:".001", o:vec![], s: None }  ,
					"Compromise Software Supply Chain" => Hnode{ d:"Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.", t:".002", o:vec![], s: None }  ,
					"Compromise Hardware Supply Chain" => Hnode{ d:"Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Trusted Relationship" => 		 Hnode{ 
			d:"Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.",
			t:"T1199",
			o:vec![],
			s: None } ,
				"Valid Accounts" => 		 Hnode{ 
			d:"Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
			t:"T1078",
			o:vec!["Default Accounts","Domain Accounts","Local Accounts","Cloud Accounts"],
			s: Some(
				hashmap!(
					"Default Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes.", t:".001", o:vec![], s: None }  ,
					"Domain Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.", t:".002", o:vec![], s: None }  ,
					"Local Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.", t:".003", o:vec![], s: None }  ,
					"Cloud Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. In some cases, cloud accounts may be federated with traditional identity management system, such as Window Active Directory.", t:".004", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"Execution" => 	Hnode{ 
		d:"safe_str(The adversary is trying to run malicious code.Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery.)",
		t:"None",
		o:vec!["Command and Scripting Interpreter","Container Administration Command","Deploy Container","Exploitation for Client Execution","Inter-Process Communication","Native API","Scheduled Task/Job","Serverless Execution","Shared Modules","Software Deployment Tools","System Services","User Execution","Windows Management Instrumentation"],
		s: Some(
			hashmap!(
				"Command and Scripting Interpreter" => 		 Hnode{ 
			d:"Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.",
			t:"T1059",
			o:vec!["PowerShell","AppleScript","Windows Command Shell","Unix Shell","Visual Basic","Python","JavaScript","Network Device CLI"],
			s: Some(
				hashmap!(
					"PowerShell" => Hnode{ d:"Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).", t:".001", o:vec![], s: None }  ,
					"AppleScript" => Hnode{ d:"Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control applications and parts of the OS via inter-application messages called AppleEvents. These AppleEvent messages can be sent independently or easily scripted with AppleScript. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely.", t:".002", o:vec![], s: None }  ,
					"Windows Command Shell" => Hnode{ d:"Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. The command prompt can be invoked remotely via Remote Services such as SSH.", t:".003", o:vec![], s: None }  ,
					"Unix Shell" => Hnode{ d:"Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist (e.g. sh, bash, zsh, etc.) depending on the specific OS or distribution. Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.", t:".004", o:vec![], s: None }  ,
					"Visual Basic" => Hnode{ d:"Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as Component Object Model and the Native API through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core.", t:".005", o:vec![], s: None }  ,
					"Python" => Hnode{ d:"Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line (via the python.exe interpreter) or via scripts (.py) that can be written and distributed to different systems. Python code can also be compiled into binary executables.", t:".006", o:vec![], s: None }  ,
					"JavaScript" => Hnode{ d:"Adversaries may abuse various implementations of JavaScript for execution. JavaScript (JS) is a platform-independent scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser.", t:".007", o:vec![], s: None }  ,
					"Network Device CLI" => Hnode{ d:"Adversaries may abuse scripting or built-in command line interpreters (CLI) on network devices to execute malicious command and payloads. The CLI is the primary means through which users and administrators interact with the device in order to view system information, modify device operations, or perform diagnostic and administrative functions. CLIs typically contain various permission levels required for different commands.", t:".008", o:vec![], s: None }  
				)
			)} ,
				"Container Administration Command" => 		 Hnode{ 
			d:"Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.",
			t:"T1609",
			o:vec![],
			s: None } ,
				"Deploy Container" => 		 Hnode{ 
			d:"Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.",
			t:"T1610",
			o:vec![],
			s: None } ,
				"Exploitation for Client Execution" => 		 Hnode{ 
			d:"Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.",
			t:"T1203",
			o:vec![],
			s: None } ,
				"Inter-Process Communication" => 		 Hnode{ 
			d:"Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern.",
			t:"T1559",
			o:vec!["Component Object Model","Dynamic Data Exchange","XPC Services"],
			s: Some(
				hashmap!(
					"Component Object Model" => Hnode{ d:"Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE). Remote COM execution is facilitated by Remote Services such as Distributed Component Object Model (DCOM).", t:".001", o:vec![], s: None }  ,
					"Dynamic Data Exchange" => Hnode{ d:"Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.", t:".002", o:vec![], s: None }  ,
					"XPC Services" => Hnode{ d:"Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools. Applications can send messages to the XPC Service daemon, which runs as root, using the low-level XPC Service C API or the high level NSXPCConnection API in order to handle tasks that require elevated privileges (such as network connections). Applications are responsible for providing the protocol definition which serves as a blueprint of the XPC services. Developers typically use XPC Services to provide applications stability and privilege separation between the application client and the daemon.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Native API" => 		 Hnode{ 
			d:"Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes. These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.",
			t:"T1106",
			o:vec![],
			s: None } ,
				"Scheduled Task/Job" => 		 Hnode{ 
			d:"Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.",
			t:"T1053",
			o:vec!["At","Cron","Scheduled Task","Systemd Timers","Container Orchestration Job"],
			s: Some(
				hashmap!(
					"At" => Hnode{ d:"Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group.", t:".002", o:vec![], s: None }  ,
					"Cron" => Hnode{ d:"Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code. The cron utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron entries to be run and the specified times for execution. Any crontab files are stored in operating system-specific file paths.", t:".003", o:vec![], s: None }  ,
					"Scheduled Task" => Hnode{ d:"Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.", t:".005", o:vec![], s: None }  ,
					"Systemd Timers" => Hnode{ d:"Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH.", t:".006", o:vec![], s: None }  ,
					"Container Orchestration Job" => Hnode{ d:"Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Serverless Execution" => 		 Hnode{ 
			d:"Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers.",
			t:"T1648",
			o:vec![],
			s: None } ,
				"Shared Modules" => 		 Hnode{ 
			d:"Adversaries may execute malicious payloads via loading shared modules. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, LoadLibrary, etc. of the Win32 API.",
			t:"T1129",
			o:vec![],
			s: None } ,
				"Software Deployment Tools" => 		 Hnode{ 
			d:"Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, HBSS, Altiris, etc.).",
			t:"T1072",
			o:vec![],
			s: None } ,
				"System Services" => 		 Hnode{ 
			d:"Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely. Many services are set to run at boot, which can aid in achieving persistence (Create or Modify System Process), but adversaries can also abuse services for one-time or temporary execution.",
			t:"T1569",
			o:vec!["Launchctl","Service Execution"],
			s: Some(
				hashmap!(
					"Launchctl" => Hnode{ d:"Adversaries may abuse launchctl to execute commands or programs. Launchctl interfaces with launchd, the service management framework for macOS. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input.", t:".001", o:vec![], s: None }  ,
					"Service Execution" => Hnode{ d:"Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (services.exe) is an interface to manage and manipulate services. The service control manager is accessible to users via GUI components as well as system utilities such as sc.exe and Net.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"User Execution" => 		 Hnode{ 
			d:"An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of Phishing.",
			t:"T1204",
			o:vec!["Malicious Link","Malicious File","Malicious Image"],
			s: Some(
				hashmap!(
					"Malicious Link" => Hnode{ d:"An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Link. Clicking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via Exploitation for Client Execution. Links may also lead users to download files that require execution via Malicious File.", t:".001", o:vec![], s: None }  ,
					"Malicious File" => Hnode{ d:"An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Attachment. Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl.", t:".002", o:vec![], s: None }  ,
					"Malicious Image" => Hnode{ d:"Adversaries may rely on a user running a malicious image to facilitate execution. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be backdoored. Backdoored images may be uploaded to a public repository via Upload Malware, and users may then download and deploy an instance or container from the image without realizing the image is malicious, thus bypassing techniques that specifically achieve Initial Access. This can lead to the execution of malicious code, such as code that executes cryptocurrency mining, in the instance or container.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Windows Management Instrumentation" => 		 Hnode{ 
			d:"Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is an administration feature that provides a uniform environment to access Windows system components. The WMI service enables both local and remote access, though the latter is facilitated by Remote Services such as Distributed Component Object Model (DCOM) and Windows Remote Management (WinRM). Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates over port 5985 when using HTTP and 5986 for HTTPS.",
			t:"T1047",
			o:vec![],
			s: None } 
			)
		)} ,
	"Persistence" => 	Hnode{ 
		d:"safe_str(The adversary is trying to maintain their foothold.Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.)",
		t:"None",
		o:vec!["Account Manipulation","BITS Jobs","Boot or Logon Autostart Execution","Boot or Logon Initialization Scripts","Browser Extensions","Compromise Client Software Binary","Create Account","Create or Modify System Process","Event Triggered Execution","External Remote Services","Hijack Execution Flow","Implant Internal Image","Modify Authentication Process","Office Application Startup","Pre-OS Boot","Scheduled Task/Job","Server Software Component","Traffic Signaling","Valid Accounts"],
		s: Some(
			hashmap!(
				"Account Manipulation" => 		 Hnode{ 
			d:"Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.",
			t:"T1098",
			o:vec!["Additional Cloud Credentials","Additional Email Delegate Permissions","Additional Cloud Roles","SSH Authorized Keys","Device Registration"],
			s: Some(
				hashmap!(
					"Additional Cloud Credentials" => Hnode{ d:"Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.", t:".001", o:vec![], s: None }  ,
					"Additional Email Delegate Permissions" => Hnode{ d:"Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account.", t:".002", o:vec![], s: None }  ,
					"Additional Cloud Roles" => Hnode{ d:"An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments. With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins).", t:".003", o:vec![], s: None }  ,
					"SSH Authorized Keys" => Hnode{ d:"Adversaries may modify the SSH authorized_keys file to maintain persistence on a victim host. Linux distributions and macOS commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The authorized_keys file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under &lt;user-home&gt;/.ssh/authorized_keys. Users may edit the system’s SSH config file to modify the directives PubkeyAuthentication and RSAAuthentication to the value QUOTEyesQUOTE to ensure public key and RSA authentication are enabled. The SSH config file is usually located under /etc/ssh/sshd_config.", t:".004", o:vec![], s: None }  ,
					"Device Registration" => Hnode{ d:"Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"BITS Jobs" => 		 Hnode{ 
			d:"Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.",
			t:"T1197",
			o:vec![],
			s: None } ,
				"Boot or Logon Autostart Execution" => 		 Hnode{ 
			d:"Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.",
			t:"T1547",
			o:vec!["Registry Run Keys / Startup Folder","Authentication Package","Time Providers","Winlogon Helper DLL","Security Support Provider","Kernel Modules and Extensions","Re-opened Applications","LSASS Driver","Shortcut Modification","Port Monitors","Print Processors","XDG Autostart Entries","Active Setup","Login Items"],
			s: Some(
				hashmap!(
					"Registry Run Keys / Startup Folder" => Hnode{ d:"Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the QUOTErun keysQUOTE in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.", t:".001", o:vec![], s: None }  ,
					"Authentication Package" => Hnode{ d:"Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.", t:".002", o:vec![], s: None }  ,
					"Time Providers" => Hnode{ d:"Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.", t:".003", o:vec![], s: None }  ,
					"Winlogon Helper DLL" => Hnode{ d:"Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM/Software[/Wow6432Node/]/Microsoft/Windows NT/CurrentVersion/Winlogon/ and HKCU/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ are used to manage additional helper programs and functionalities that support Winlogon.", t:".004", o:vec![], s: None }  ,
					"Security Support Provider" => Hnode{ d:"Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.", t:".005", o:vec![], s: None }  ,
					"Kernel Modules and Extensions" => Hnode{ d:"Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system. ", t:".006", o:vec![], s: None }  ,
					"Re-opened Applications" => Hnode{ d:"Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to QUOTEReopen windows when logging back inQUOTE. When selected, all applications currently open are added to a property list file named com.apple.loginwindow.[UUID].plist within the ~/Library/Preferences/ByHost directory. Applications listed in this file are automatically reopened upon the user’s next logon.", t:".007", o:vec![], s: None }  ,
					"LSASS Driver" => Hnode{ d:"Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process.", t:".008", o:vec![], s: None }  ,
					"Shortcut Modification" => Hnode{ d:"Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.", t:".009", o:vec![], s: None }  ,
					"Port Monitors" => Hnode{ d:"Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:/Windows/System32 and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to HKLM/SYSTEM/CurrentControlSet/Control/Print/Monitors.", t:".010", o:vec![], s: None }  ,
					"Print Processors" => Hnode{ d:"Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, spoolsv.exe, during boot.", t:".012", o:vec![], s: None }  ,
					"XDG Autostart Entries" => Hnode{ d:"Adversaries may modify XDG autostart entries to execute programs or commands during system boot. Linux desktop environments that are XDG compliant implement functionality for XDG autostart entries. These entries will allow an application to automatically start during the startup of a desktop environment after user logon. By default, XDG autostart entries are stored within the /etc/xdg/autostart or ~/.config/autostart directories and have a .desktop file extension.", t:".013", o:vec![], s: None }  ,
					"Active Setup" => Hnode{ d:"Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level.", t:".014", o:vec![], s: None }  ,
					"Login Items" => Hnode{ d:"Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in. Login items can be added via a shared file list or Service Management Framework. Shared file list login items can be set using scripting languages such as AppleScript, whereas the Service Management Framework uses the API call SMLoginItemSetEnabled.", t:".015", o:vec![], s: None }  
				)
			)} ,
				"Boot or Logon Initialization Scripts" => 		 Hnode{ 
			d:"Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.",
			t:"T1037",
			o:vec!["Logon Script (Windows)","Login Hook","Network Logon Script","RC Scripts","Startup Items"],
			s: Some(
				hashmap!(
					"Logon Script (Windows)" => Hnode{ d:"Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path to a script to the HKCU/Environment/UserInitMprLogonScript Registry key.", t:".001", o:vec![], s: None }  ,
					"Login Hook" => Hnode{ d:"Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the /Library/Preferences/com.apple.loginwindow.plist file and can be modified using the defaults command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks.", t:".002", o:vec![], s: None }  ,
					"Network Logon Script" => Hnode{ d:"Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems.", t:".003", o:vec![], s: None }  ,
					"RC Scripts" => Hnode{ d:"Adversaries may establish persistence by modifying RC scripts which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.", t:".004", o:vec![], s: None }  ,
					"Startup Items" => Hnode{ d:"Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Browser Extensions" => 		 Hnode{ 
			d:"Adversaries may abuse Internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access.",
			t:"T1176",
			o:vec![],
			s: None } ,
				"Compromise Client Software Binary" => 		 Hnode{ 
			d:"Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.",
			t:"T1554",
			o:vec![],
			s: None } ,
				"Create Account" => 		 Hnode{ 
			d:"Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.",
			t:"T1136",
			o:vec!["Local Account","Domain Account","Cloud Account"],
			s: Some(
				hashmap!(
					"Local Account" => Hnode{ d:"Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service. With a sufficient level of access, the net user /add command can be used to create a local account. On macOS systems the dscl -create command can be used to create a local account.", t:".001", o:vec![], s: None }  ,
					"Domain Account" => Hnode{ d:"Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the net user /add /domain command can be used to create a domain account.", t:".002", o:vec![], s: None }  ,
					"Cloud Account" => Hnode{ d:"Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Create or Modify System Process" => 		 Hnode{ 
			d:"Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.",
			t:"T1543",
			o:vec!["Launch Agent","Systemd Service","Windows Service","Launch Daemon"],
			s: Some(
				hashmap!(
					"Launch Agent" => Hnode{ d:"Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in /System/Library/LaunchAgents, /Library/LaunchAgents, and ~/Library/LaunchAgents. Property list files use the Label, ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks.", t:".001", o:vec![], s: None }  ,
					"Systemd Service" => Hnode{ d:"Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. The systemd service manager is commonly used for managing background daemon processes (also known as services) and other system resources. Systemd is the default initialization (init) system on many Linux distributions starting with Debian 8, Ubuntu 15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems including SysVinit and Upstart while remaining backwards compatible with the aforementioned init systems.", t:".002", o:vec![], s: None }  ,
					"Windows Service" => Hnode{ d:"Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.", t:".003", o:vec![], s: None }  ,
					"Launch Daemon" => Hnode{ d:"Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in /System/Library/LaunchDaemons/ and /Library/LaunchDaemons/. Required Launch Daemons parameters include a Label to identify the task, Program to provide a path to the executable, and RunAtLoad to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Event Triggered Execution" => 		 Hnode{ 
			d:"Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.",
			t:"T1546",
			o:vec!["Change Default File Association","Screensaver","Windows Management Instrumentation Event Subscription","Unix Shell Configuration Modification","Trap","LC_LOAD_DYLIB Addition","Netsh Helper DLL","Accessibility Features","AppCert DLLs","AppInit DLLs","Application Shimming","Image File Execution Options Injection","PowerShell Profile","Emond","Component Object Model Hijacking","Installer Packages"],
			s: Some(
				hashmap!(
					"Change Default File Association" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.", t:".001", o:vec![], s: None }  ,
					"Screensaver" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension. The Windows screensaver application scrnsave.scr is located in C:/Windows/System32/, and C:/Windows/sysWOW64/ on 64-bit Windows systems, along with screensavers included with base Windows installations.", t:".002", o:vec![], s: None }  ,
					"Windows Management Instrumentation Event Subscription" => Hnode{ d:"Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime.", t:".003", o:vec![], s: None }  ,
					"Unix Shell Configuration Modification" => Hnode{ d:"Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User Unix Shells execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (/etc) and the user’s home directory (~/) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately.", t:".004", o:vec![], s: None }  ,
					"Trap" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d.", t:".005", o:vec![], s: None }  ,
					"LC_LOAD_DYLIB Addition" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies. There are tools available to perform these changes.", t:".006", o:vec![], s: None }  ,
					"Netsh Helper DLL" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM/SOFTWARE/Microsoft/Netsh.", t:".007", o:vec![], s: None }  ,
					"Accessibility Features" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.", t:".008", o:vec![], s: None }  ,
					"AppCert DLLs" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under HKEY_LOCAL_MACHINE/System/CurrentControlSet/Control/Session Manager/ are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec.", t:".009", o:vec![], s: None }  ,
					"AppInit DLLs" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys HKEY_LOCAL_MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Windows or HKEY_LOCAL_MACHINE/Software/Wow6432Node/Microsoft/Windows NT/CurrentVersion/Windows are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library.", t:".010", o:vec![], s: None }  ,
					"Application Shimming" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10.", t:".011", o:vec![], s: None }  ,
					"Image File Execution Options Injection" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., C:/dbg/ntsd.exe -g notepad.exe).", t:".012", o:vec![], s: None }  ,
					"PowerShell Profile" => Hnode{ d:"Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments.", t:".013", o:vec![], s: None }  ,
					"Emond" => Hnode{ d:"Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a Launch Daemon that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at /sbin/emond will load any rules from the /etc/emond.d/rules/ directory and take action once an explicitly defined event takes place.", t:".014", o:vec![], s: None }  ,
					"Component Object Model Hijacking" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry.", t:".015", o:vec![], s: None }  ,
					"Installer Packages" => Hnode{ d:"Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation.", t:".016", o:vec![], s: None }  
				)
			)} ,
				"External Remote Services" => 		 Hnode{ 
			d:"Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.",
			t:"T1133",
			o:vec![],
			s: None } ,
				"Hijack Execution Flow" => 		 Hnode{ 
			d:"Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.",
			t:"T1574",
			o:vec!["DLL Search Order Hijacking","DLL Side-Loading","Dylib Hijacking","Executable Installer File Permissions Weakness","Dynamic Linker Hijacking","Path Interception by PATH Environment Variable","Path Interception by Search Order Hijacking","Path Interception by Unquoted Path","Services File Permissions Weakness","Services Registry Permissions Weakness","COR_PROFILER","KernelCallbackTable"],
			s: Some(
				hashmap!(
					"DLL Search Order Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.", t:".001", o:vec![], s: None }  ,
					"DLL Side-Loading" => Hnode{ d:"Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to DLL Search Order Hijacking, side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).", t:".002", o:vec![], s: None }  ,
					"Dylib Hijacking" => Hnode{ d:"Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with @rpath, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable. Additionally, if weak linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added.", t:".004", o:vec![], s: None }  ,
					"Executable Installer File Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.", t:".005", o:vec![], s: None }  ,
					"Dynamic Linker Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library.", t:".006", o:vec![], s: None }  ,
					"Path Interception by PATH Environment Variable" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. Adversaries may place a program in an earlier entry in the list of directories stored in the PATH environment variable, which Windows will then execute when it searches sequentially through that PATH listing in search of the binary that was called from a script or the command line.", t:".007", o:vec![], s: None }  ,
					"Path Interception by Search Order Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.", t:".008", o:vec![], s: None }  ,
					"Path Interception by Unquoted Path" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.", t:".009", o:vec![], s: None }  ,
					"Services File Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.", t:".010", o:vec![], s: None }  ,
					"Services Registry Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under HKLM/SYSTEM/CurrentControlSet/Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through access control lists and user permissions.", t:".011", o:vec![], s: None }  ,
					"COR_PROFILER" => Hnode{ d:"Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.", t:".012", o:vec![], s: None }  ,
					"KernelCallbackTable" => Hnode{ d:"Adversaries may abuse the KernelCallbackTable of a process to hijack its execution flow in order to run their own payloads. The KernelCallbackTable can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once user32.dll is loaded.", t:".013", o:vec![], s: None }  
				)
			)} ,
				"Implant Internal Image" => 		 Hnode{ 
			d:"Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike Upload Malware, this technique focuses on adversaries implanting an image in a registry within a victim’s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.",
			t:"T1525",
			o:vec![],
			s: None } ,
				"Modify Authentication Process" => 		 Hnode{ 
			d:"Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts.",
			t:"T1556",
			o:vec!["Domain Controller Authentication","Password Filter DLL","Pluggable Authentication Modules","Network Device Authentication","Reversible Encryption","Multi-Factor Authentication","Hybrid Identity"],
			s: Some(
				hashmap!(
					"Domain Controller Authentication" => Hnode{ d:"Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts.", t:".001", o:vec![], s: None }  ,
					"Password Filter DLL" => Hnode{ d:"Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.", t:".002", o:vec![], s: None }  ,
					"Pluggable Authentication Modules" => Hnode{ d:"Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow.", t:".003", o:vec![], s: None }  ,
					"Network Device Authentication" => Hnode{ d:"Adversaries may use Patch System Image to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.", t:".004", o:vec![], s: None }  ,
					"Reversible Encryption" => Hnode{ d:"An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it.", t:".005", o:vec![], s: None }  ,
					"Multi-Factor Authentication" => Hnode{ d:"Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.", t:".006", o:vec![], s: None }  ,
					"Hybrid Identity" => Hnode{ d:"Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Office Application Startup" => 		 Hnode{ 
			d:"Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.",
			t:"T1137",
			o:vec!["Office Template Macros","Office Test","Outlook Forms","Outlook Home Page","Outlook Rules","Add-ins"],
			s: Some(
				hashmap!(
					"Office Template Macros" => Hnode{ d:"Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts.", t:".001", o:vec![], s: None }  ,
					"Office Test" => Hnode{ d:"Adversaries may abuse the Microsoft Office QUOTEOffice TestQUOTE Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started. This Registry key is thought to be used by Microsoft to load DLLs for testing and debugging purposes while developing Office applications. This Registry key is not created by default during an Office installation.", t:".002", o:vec![], s: None }  ,
					"Outlook Forms" => Hnode{ d:"Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form.", t:".003", o:vec![], s: None }  ,
					"Outlook Home Page" => Hnode{ d:"Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened. A malicious HTML page can be crafted that will execute code when loaded by Outlook Home Page.", t:".004", o:vec![], s: None }  ,
					"Outlook Rules" => Hnode{ d:"Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user.", t:".005", o:vec![], s: None }  ,
					"Add-ins" => Hnode{ d:"Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs. There are different types of add-ins that can be used by the various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-ins, and Outlook add-ins.", t:".006", o:vec![], s: None }  
				)
			)} ,
				"Pre-OS Boot" => 		 Hnode{ 
			d:"Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.",
			t:"T1542",
			o:vec!["System Firmware","Component Firmware","Bootkit","ROMMONkit","TFTP Boot"],
			s: Some(
				hashmap!(
					"System Firmware" => Hnode{ d:"Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.", t:".001", o:vec![], s: None }  ,
					"Component Firmware" => Hnode{ d:"Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to System Firmware but conducted upon other system components/devices that may not have the same capability or level of integrity checking.", t:".002", o:vec![], s: None }  ,
					"Bootkit" => Hnode{ d:"Adversaries may use bootkits to persist on systems. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly.", t:".003", o:vec![], s: None }  ,
					"ROMMONkit" => Hnode{ d:"Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect.", t:".004", o:vec![], s: None }  ,
					"TFTP Boot" => Hnode{ d:"Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Scheduled Task/Job" => 		 Hnode{ 
			d:"Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.",
			t:"T1053",
			o:vec!["At","Cron","Scheduled Task","Systemd Timers","Container Orchestration Job"],
			s: Some(
				hashmap!(
					"At" => Hnode{ d:"Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group.", t:".002", o:vec![], s: None }  ,
					"Cron" => Hnode{ d:"Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code. The cron utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron entries to be run and the specified times for execution. Any crontab files are stored in operating system-specific file paths.", t:".003", o:vec![], s: None }  ,
					"Scheduled Task" => Hnode{ d:"Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.", t:".005", o:vec![], s: None }  ,
					"Systemd Timers" => Hnode{ d:"Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH.", t:".006", o:vec![], s: None }  ,
					"Container Orchestration Job" => Hnode{ d:"Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Server Software Component" => 		 Hnode{ 
			d:"Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.",
			t:"T1505",
			o:vec!["SQL Stored Procedures","Transport Agent","Web Shell","IIS Components","Terminal Services DLL"],
			s: Some(
				hashmap!(
					"SQL Stored Procedures" => Hnode{ d:"Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted).", t:".001", o:vec![], s: None }  ,
					"Transport Agent" => Hnode{ d:"Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails. Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks.", t:".002", o:vec![], s: None }  ,
					"Web Shell" => Hnode{ d:"Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server.", t:".003", o:vec![], s: None }  ,
					"IIS Components" => Hnode{ d:"Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests. Extensions and filters are deployed as DLL files that export three functions: Get{Extension/Filter}Version, Http{Extension/Filter}Proc, and (optionally) Terminate{Extension/Filter}. IIS modules may also be installed to extend IIS web servers.", t:".004", o:vec![], s: None }  ,
					"Terminal Services DLL" => Hnode{ d:"Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Traffic Signaling" => 		 Hnode{ 
			d:"Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.",
			t:"T1205",
			o:vec!["Port Knocking","Socket Filters"],
			s: Some(
				hashmap!(
					"Port Knocking" => Hnode{ d:"Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.", t:".001", o:vec![], s: None }  ,
					"Socket Filters" => Hnode{ d:"Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the libpcap library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Valid Accounts" => 		 Hnode{ 
			d:"Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
			t:"T1078",
			o:vec!["Default Accounts","Domain Accounts","Local Accounts","Cloud Accounts"],
			s: Some(
				hashmap!(
					"Default Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes.", t:".001", o:vec![], s: None }  ,
					"Domain Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.", t:".002", o:vec![], s: None }  ,
					"Local Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.", t:".003", o:vec![], s: None }  ,
					"Cloud Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. In some cases, cloud accounts may be federated with traditional identity management system, such as Window Active Directory.", t:".004", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"PrivilegeEscalation" => 	Hnode{ 
		d:"safe_str(The adversary is trying to gain higher-level permissions.Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include: <ul><li>SYSTEM/root level</li><li>local administrator</li><li>user account with admin-like access </li><li>user accounts with access to specific system or perform specific function</li></ul>These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.)",
		t:"None",
		o:vec!["Abuse Elevation Control Mechanism","Access Token Manipulation","Boot or Logon Autostart Execution","Boot or Logon Initialization Scripts","Create or Modify System Process","Domain Policy Modification","Escape to Host","Event Triggered Execution","Exploitation for Privilege Escalation","Hijack Execution Flow","Process Injection","Scheduled Task/Job","Valid Accounts"],
		s: Some(
			hashmap!(
				"Abuse Elevation Control Mechanism" => 		 Hnode{ 
			d:"Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.",
			t:"T1548",
			o:vec!["Setuid and Setgid","Bypass User Account Control","Sudo and Sudo Caching","Elevated Execution with Prompt"],
			s: Some(
				hashmap!(
					"Setuid and Setgid" => Hnode{ d:"An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges.", t:".001", o:vec![], s: None }  ,
					"Bypass User Account Control" => Hnode{ d:"Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.", t:".002", o:vec![], s: None }  ,
					"Sudo and Sudo Caching" => Hnode{ d:"Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges.", t:".003", o:vec![], s: None }  ,
					"Elevated Execution with Prompt" => Hnode{ d:"Adversaries may leverage the AuthorizationExecuteWithPrivileges API to escalate privileges by prompting the user for credentials. The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Access Token Manipulation" => 		 Hnode{ 
			d:"Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.",
			t:"T1134",
			o:vec!["Token Impersonation/Theft","Create Process with Token","Make and Impersonate Token","Parent PID Spoofing","SID-History Injection"],
			s: Some(
				hashmap!(
					"Token Impersonation/Theft" => Hnode{ d:"Adversaries may duplicate then impersonate another user's token to escalate privileges and bypass access controls. An adversary can create a new access token that duplicates an existing token using DuplicateToken(Ex). The token can then be used with ImpersonateLoggedOnUser to allow the calling thread to impersonate a logged on user's security context, or with SetThreadToken to assign the impersonated token to a thread.", t:".001", o:vec![], s: None }  ,
					"Create Process with Token" => Hnode{ d:"Adversaries may create a new process with a different token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as CreateProcessWithTokenW and runas.", t:".002", o:vec![], s: None }  ,
					"Make and Impersonate Token" => Hnode{ d:"Adversaries may make and impersonate tokens to escalate privileges and bypass access controls. If an adversary has a username and password but the user is not logged onto the system, the adversary can then create a logon session for the user using the LogonUser function. The function will return a copy of the new session's access token and the adversary can use SetThreadToken to assign the token to a thread.", t:".003", o:vec![], s: None }  ,
					"Parent PID Spoofing" => Hnode{ d:"Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the CreateProcess API call, which supports a parameter that defines the PPID to use. This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via svchost.exe or consent.exe) rather than the current user context.", t:".004", o:vec![], s: None }  ,
					"SID-History Injection" => Hnode{ d:"Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. An account can hold additional SIDs in the SID-History Active Directory attribute , allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Boot or Logon Autostart Execution" => 		 Hnode{ 
			d:"Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.",
			t:"T1547",
			o:vec!["Registry Run Keys / Startup Folder","Authentication Package","Time Providers","Winlogon Helper DLL","Security Support Provider","Kernel Modules and Extensions","Re-opened Applications","LSASS Driver","Shortcut Modification","Port Monitors","Print Processors","XDG Autostart Entries","Active Setup","Login Items"],
			s: Some(
				hashmap!(
					"Registry Run Keys / Startup Folder" => Hnode{ d:"Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the QUOTErun keysQUOTE in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.", t:".001", o:vec![], s: None }  ,
					"Authentication Package" => Hnode{ d:"Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.", t:".002", o:vec![], s: None }  ,
					"Time Providers" => Hnode{ d:"Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.", t:".003", o:vec![], s: None }  ,
					"Winlogon Helper DLL" => Hnode{ d:"Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM/Software[/Wow6432Node/]/Microsoft/Windows NT/CurrentVersion/Winlogon/ and HKCU/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ are used to manage additional helper programs and functionalities that support Winlogon.", t:".004", o:vec![], s: None }  ,
					"Security Support Provider" => Hnode{ d:"Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.", t:".005", o:vec![], s: None }  ,
					"Kernel Modules and Extensions" => Hnode{ d:"Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system. ", t:".006", o:vec![], s: None }  ,
					"Re-opened Applications" => Hnode{ d:"Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to QUOTEReopen windows when logging back inQUOTE. When selected, all applications currently open are added to a property list file named com.apple.loginwindow.[UUID].plist within the ~/Library/Preferences/ByHost directory. Applications listed in this file are automatically reopened upon the user’s next logon.", t:".007", o:vec![], s: None }  ,
					"LSASS Driver" => Hnode{ d:"Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process.", t:".008", o:vec![], s: None }  ,
					"Shortcut Modification" => Hnode{ d:"Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.", t:".009", o:vec![], s: None }  ,
					"Port Monitors" => Hnode{ d:"Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the AddMonitor API call to set a DLL to be loaded at startup. This DLL can be located in C:/Windows/System32 and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to HKLM/SYSTEM/CurrentControlSet/Control/Print/Monitors.", t:".010", o:vec![], s: None }  ,
					"Print Processors" => Hnode{ d:"Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, spoolsv.exe, during boot.", t:".012", o:vec![], s: None }  ,
					"XDG Autostart Entries" => Hnode{ d:"Adversaries may modify XDG autostart entries to execute programs or commands during system boot. Linux desktop environments that are XDG compliant implement functionality for XDG autostart entries. These entries will allow an application to automatically start during the startup of a desktop environment after user logon. By default, XDG autostart entries are stored within the /etc/xdg/autostart or ~/.config/autostart directories and have a .desktop file extension.", t:".013", o:vec![], s: None }  ,
					"Active Setup" => Hnode{ d:"Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer. These programs will be executed under the context of the user and will have the account's associated permissions level.", t:".014", o:vec![], s: None }  ,
					"Login Items" => Hnode{ d:"Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in. Login items can be added via a shared file list or Service Management Framework. Shared file list login items can be set using scripting languages such as AppleScript, whereas the Service Management Framework uses the API call SMLoginItemSetEnabled.", t:".015", o:vec![], s: None }  
				)
			)} ,
				"Boot or Logon Initialization Scripts" => 		 Hnode{ 
			d:"Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence. Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.",
			t:"T1037",
			o:vec!["Logon Script (Windows)","Login Hook","Network Logon Script","RC Scripts","Startup Items"],
			s: Some(
				hashmap!(
					"Logon Script (Windows)" => Hnode{ d:"Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system. This is done via adding a path to a script to the HKCU/Environment/UserInitMprLogonScript Registry key.", t:".001", o:vec![], s: None }  ,
					"Login Hook" => Hnode{ d:"Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the /Library/Preferences/com.apple.loginwindow.plist file and can be modified using the defaults command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks.", t:".002", o:vec![], s: None }  ,
					"Network Logon Script" => Hnode{ d:"Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects. These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems.", t:".003", o:vec![], s: None }  ,
					"RC Scripts" => Hnode{ d:"Adversaries may establish persistence by modifying RC scripts which are executed during a Unix-like system’s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.", t:".004", o:vec![], s: None }  ,
					"Startup Items" => Hnode{ d:"Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Create or Modify System Process" => 		 Hnode{ 
			d:"Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.",
			t:"T1543",
			o:vec!["Launch Agent","Systemd Service","Windows Service","Launch Daemon"],
			s: Some(
				hashmap!(
					"Launch Agent" => Hnode{ d:"Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in /System/Library/LaunchAgents, /Library/LaunchAgents, and ~/Library/LaunchAgents. Property list files use the Label, ProgramArguments , and RunAtLoad keys to identify the Launch Agent's name, executable location, and execution time. Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks.", t:".001", o:vec![], s: None }  ,
					"Systemd Service" => Hnode{ d:"Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. The systemd service manager is commonly used for managing background daemon processes (also known as services) and other system resources. Systemd is the default initialization (init) system on many Linux distributions starting with Debian 8, Ubuntu 15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems including SysVinit and Upstart while remaining backwards compatible with the aforementioned init systems.", t:".002", o:vec![], s: None }  ,
					"Windows Service" => Hnode{ d:"Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.", t:".003", o:vec![], s: None }  ,
					"Launch Daemon" => Hnode{ d:"Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in /System/Library/LaunchDaemons/ and /Library/LaunchDaemons/. Required Launch Daemons parameters include a Label to identify the task, Program to provide a path to the executable, and RunAtLoad to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Domain Policy Modification" => 		 Hnode{ 
			d:"Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.",
			t:"T1484",
			o:vec!["Group Policy Modification","Domain Trust Modification"],
			s: Some(
				hashmap!(
					"Group Policy Modification" => Hnode{ d:"Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predicable network path /&lt;DOMAIN&gt;/SYSVOL/&lt;DOMAIN&gt;/Policies/.", t:".001", o:vec![], s: None }  ,
					"Domain Trust Modification" => Hnode{ d:"Adversaries may add new domain trusts or modify the properties of existing domain trusts to evade defenses and/or elevate privileges. Domain trust details, such as whether or not a domain is federated, allow authentication and authorization properties to apply between domains for the purpose of accessing shared resources. These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Escape to Host" => 		 Hnode{ 
			d:"Adversaries may break out of a container to gain access to the underlying host. This can allow an adversary access to other containerized resources from the host level or to the host itself. In principle, containerized resources should provide a clear separation of application functionality and be isolated from the host environment.",
			t:"T1611",
			o:vec![],
			s: None } ,
				"Event Triggered Execution" => 		 Hnode{ 
			d:"Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.",
			t:"T1546",
			o:vec!["Change Default File Association","Screensaver","Windows Management Instrumentation Event Subscription","Unix Shell Configuration Modification","Trap","LC_LOAD_DYLIB Addition","Netsh Helper DLL","Accessibility Features","AppCert DLLs","AppInit DLLs","Application Shimming","Image File Execution Options Injection","PowerShell Profile","Emond","Component Object Model Hijacking","Installer Packages"],
			s: Some(
				hashmap!(
					"Change Default File Association" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.", t:".001", o:vec![], s: None }  ,
					"Screensaver" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension. The Windows screensaver application scrnsave.scr is located in C:/Windows/System32/, and C:/Windows/sysWOW64/ on 64-bit Windows systems, along with screensavers included with base Windows installations.", t:".002", o:vec![], s: None }  ,
					"Windows Management Instrumentation Event Subscription" => Hnode{ d:"Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime.", t:".003", o:vec![], s: None }  ,
					"Unix Shell Configuration Modification" => Hnode{ d:"Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User Unix Shells execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (/etc) and the user’s home directory (~/) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately.", t:".004", o:vec![], s: None }  ,
					"Trap" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d.", t:".005", o:vec![], s: None }  ,
					"LC_LOAD_DYLIB Addition" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies. There are tools available to perform these changes.", t:".006", o:vec![], s: None }  ,
					"Netsh Helper DLL" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM/SOFTWARE/Microsoft/Netsh.", t:".007", o:vec![], s: None }  ,
					"Accessibility Features" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.", t:".008", o:vec![], s: None }  ,
					"AppCert DLLs" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under HKEY_LOCAL_MACHINE/System/CurrentControlSet/Control/Session Manager/ are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec.", t:".009", o:vec![], s: None }  ,
					"AppInit DLLs" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys HKEY_LOCAL_MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Windows or HKEY_LOCAL_MACHINE/Software/Wow6432Node/Microsoft/Windows NT/CurrentVersion/Windows are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library.", t:".010", o:vec![], s: None }  ,
					"Application Shimming" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10.", t:".011", o:vec![], s: None }  ,
					"Image File Execution Options Injection" => Hnode{ d:"Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., C:/dbg/ntsd.exe -g notepad.exe).", t:".012", o:vec![], s: None }  ,
					"PowerShell Profile" => Hnode{ d:"Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments.", t:".013", o:vec![], s: None }  ,
					"Emond" => Hnode{ d:"Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a Launch Daemon that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at /sbin/emond will load any rules from the /etc/emond.d/rules/ directory and take action once an explicitly defined event takes place.", t:".014", o:vec![], s: None }  ,
					"Component Object Model Hijacking" => Hnode{ d:"Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry.", t:".015", o:vec![], s: None }  ,
					"Installer Packages" => Hnode{ d:"Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation.", t:".016", o:vec![], s: None }  
				)
			)} ,
				"Exploitation for Privilege Escalation" => 		 Hnode{ 
			d:"Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.",
			t:"T1068",
			o:vec![],
			s: None } ,
				"Hijack Execution Flow" => 		 Hnode{ 
			d:"Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.",
			t:"T1574",
			o:vec!["DLL Search Order Hijacking","DLL Side-Loading","Dylib Hijacking","Executable Installer File Permissions Weakness","Dynamic Linker Hijacking","Path Interception by PATH Environment Variable","Path Interception by Search Order Hijacking","Path Interception by Unquoted Path","Services File Permissions Weakness","Services Registry Permissions Weakness","COR_PROFILER","KernelCallbackTable"],
			s: Some(
				hashmap!(
					"DLL Search Order Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.", t:".001", o:vec![], s: None }  ,
					"DLL Side-Loading" => Hnode{ d:"Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to DLL Search Order Hijacking, side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).", t:".002", o:vec![], s: None }  ,
					"Dylib Hijacking" => Hnode{ d:"Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with @rpath, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable. Additionally, if weak linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added.", t:".004", o:vec![], s: None }  ,
					"Executable Installer File Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.", t:".005", o:vec![], s: None }  ,
					"Dynamic Linker Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library.", t:".006", o:vec![], s: None }  ,
					"Path Interception by PATH Environment Variable" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. Adversaries may place a program in an earlier entry in the list of directories stored in the PATH environment variable, which Windows will then execute when it searches sequentially through that PATH listing in search of the binary that was called from a script or the command line.", t:".007", o:vec![], s: None }  ,
					"Path Interception by Search Order Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.", t:".008", o:vec![], s: None }  ,
					"Path Interception by Unquoted Path" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.", t:".009", o:vec![], s: None }  ,
					"Services File Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.", t:".010", o:vec![], s: None }  ,
					"Services Registry Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under HKLM/SYSTEM/CurrentControlSet/Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through access control lists and user permissions.", t:".011", o:vec![], s: None }  ,
					"COR_PROFILER" => Hnode{ d:"Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.", t:".012", o:vec![], s: None }  ,
					"KernelCallbackTable" => Hnode{ d:"Adversaries may abuse the KernelCallbackTable of a process to hijack its execution flow in order to run their own payloads. The KernelCallbackTable can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once user32.dll is loaded.", t:".013", o:vec![], s: None }  
				)
			)} ,
				"Process Injection" => 		 Hnode{ 
			d:"Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.",
			t:"T1055",
			o:vec!["Dynamic-link Library Injection","Portable Executable Injection","Thread Execution Hijacking","Asynchronous Procedure Call","Thread Local Storage","Ptrace System Calls","Proc Memory","Extra Window Memory Injection","Process Hollowing","Process Doppelgänging","VDSO Hijacking","ListPlanting"],
			s: Some(
				hashmap!(
					"Dynamic-link Library Injection" => Hnode{ d:"Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.", t:".001", o:vec![], s: None }  ,
					"Portable Executable Injection" => Hnode{ d:"Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process.", t:".002", o:vec![], s: None }  ,
					"Thread Execution Hijacking" => Hnode{ d:"Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process.", t:".003", o:vec![], s: None }  ,
					"Asynchronous Procedure Call" => Hnode{ d:"Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process.", t:".004", o:vec![], s: None }  ,
					"Thread Local Storage" => Hnode{ d:"Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process.", t:".005", o:vec![], s: None }  ,
					"Ptrace System Calls" => Hnode{ d:"Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.", t:".008", o:vec![], s: None }  ,
					"Proc Memory" => Hnode{ d:"Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process.", t:".009", o:vec![], s: None }  ,
					"Extra Window Memory Injection" => Hnode{ d:"Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process.", t:".011", o:vec![], s: None }  ,
					"Process Hollowing" => Hnode{ d:"Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.", t:".012", o:vec![], s: None }  ,
					"Process Doppelgänging" => Hnode{ d:"Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a separate live process.", t:".013", o:vec![], s: None }  ,
					"VDSO Hijacking" => Hnode{ d:"Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process.", t:".014", o:vec![], s: None }  ,
					"ListPlanting" => Hnode{ d:"Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of a separate live process. Code executed via ListPlanting may also evade detection from security products since the execution is masked under a legitimate process.", t:".015", o:vec![], s: None }  
				)
			)} ,
				"Scheduled Task/Job" => 		 Hnode{ 
			d:"Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically may require being a member of an admin or otherwise privileged group on the remote system.",
			t:"T1053",
			o:vec!["At","Cron","Scheduled Task","Systemd Timers","Container Orchestration Job"],
			s: Some(
				hashmap!(
					"At" => Hnode{ d:"Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of Scheduled Task's schtasks in Windows environments, using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group.", t:".002", o:vec![], s: None }  ,
					"Cron" => Hnode{ d:"Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code. The cron utility is a time-based job scheduler for Unix-like operating systems. The crontab file contains the schedule of cron entries to be run and the specified times for execution. Any crontab files are stored in operating system-specific file paths.", t:".003", o:vec![], s: None }  ,
					"Scheduled Task" => Hnode{ d:"Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The schtasks utility can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.", t:".005", o:vec![], s: None }  ,
					"Systemd Timers" => Hnode{ d:"Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension .timer that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to Cron in Linux environments. Systemd timers may be activated remotely via the systemctl command line utility, which operates over SSH.", t:".006", o:vec![], s: None }  ,
					"Container Orchestration Job" => Hnode{ d:"Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Valid Accounts" => 		 Hnode{ 
			d:"Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
			t:"T1078",
			o:vec!["Default Accounts","Domain Accounts","Local Accounts","Cloud Accounts"],
			s: Some(
				hashmap!(
					"Default Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes.", t:".001", o:vec![], s: None }  ,
					"Domain Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.", t:".002", o:vec![], s: None }  ,
					"Local Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.", t:".003", o:vec![], s: None }  ,
					"Cloud Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. In some cases, cloud accounts may be federated with traditional identity management system, such as Window Active Directory.", t:".004", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"DefenseEvasion" => 	Hnode{ 
		d:"safe_str(The adversary is trying to avoid being detected.Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics’ techniques are cross-listed here when those techniques include the added benefit of subverting defenses.)",
		t:"None",
		o:vec!["Abuse Elevation Control Mechanism","Access Token Manipulation","BITS Jobs","Build Image on Host","Debugger Evasion","Deobfuscate/Decode Files or Information","Deploy Container","Direct Volume Access","Domain Policy Modification","Execution Guardrails","Exploitation for Defense Evasion","File and Directory Permissions Modification","Hide Artifacts","Hijack Execution Flow","Impair Defenses","Indicator Removal","Indirect Command Execution","Masquerading","Modify Authentication Process","Modify Cloud Compute Infrastructure","Modify Registry","Modify System Image","Network Boundary Bridging","Obfuscated Files or Information","Plist File Modification","Pre-OS Boot","Process Injection","Reflective Code Loading","Rogue Domain Controller","Rootkit","Subvert Trust Controls","System Binary Proxy Execution","System Script Proxy Execution","Template Injection","Traffic Signaling","Trusted Developer Utilities Proxy Execution","Unused/Unsupported Cloud Regions","Use Alternate Authentication Material","Valid Accounts","Virtualization/Sandbox Evasion","Weaken Encryption","XSL Script Processing"],
		s: Some(
			hashmap!(
				"Abuse Elevation Control Mechanism" => 		 Hnode{ 
			d:"Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.",
			t:"T1548",
			o:vec!["Setuid and Setgid","Bypass User Account Control","Sudo and Sudo Caching","Elevated Execution with Prompt"],
			s: Some(
				hashmap!(
					"Setuid and Setgid" => Hnode{ d:"An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges.", t:".001", o:vec![], s: None }  ,
					"Bypass User Account Control" => Hnode{ d:"Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.", t:".002", o:vec![], s: None }  ,
					"Sudo and Sudo Caching" => Hnode{ d:"Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges.", t:".003", o:vec![], s: None }  ,
					"Elevated Execution with Prompt" => Hnode{ d:"Adversaries may leverage the AuthorizationExecuteWithPrivileges API to escalate privileges by prompting the user for credentials. The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Access Token Manipulation" => 		 Hnode{ 
			d:"Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.",
			t:"T1134",
			o:vec!["Token Impersonation/Theft","Create Process with Token","Make and Impersonate Token","Parent PID Spoofing","SID-History Injection"],
			s: Some(
				hashmap!(
					"Token Impersonation/Theft" => Hnode{ d:"Adversaries may duplicate then impersonate another user's token to escalate privileges and bypass access controls. An adversary can create a new access token that duplicates an existing token using DuplicateToken(Ex). The token can then be used with ImpersonateLoggedOnUser to allow the calling thread to impersonate a logged on user's security context, or with SetThreadToken to assign the impersonated token to a thread.", t:".001", o:vec![], s: None }  ,
					"Create Process with Token" => Hnode{ d:"Adversaries may create a new process with a different token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as CreateProcessWithTokenW and runas.", t:".002", o:vec![], s: None }  ,
					"Make and Impersonate Token" => Hnode{ d:"Adversaries may make and impersonate tokens to escalate privileges and bypass access controls. If an adversary has a username and password but the user is not logged onto the system, the adversary can then create a logon session for the user using the LogonUser function. The function will return a copy of the new session's access token and the adversary can use SetThreadToken to assign the token to a thread.", t:".003", o:vec![], s: None }  ,
					"Parent PID Spoofing" => Hnode{ d:"Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the CreateProcess API call, which supports a parameter that defines the PPID to use. This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via svchost.exe or consent.exe) rather than the current user context.", t:".004", o:vec![], s: None }  ,
					"SID-History Injection" => Hnode{ d:"Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. An account can hold additional SIDs in the SID-History Active Directory attribute , allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).", t:".005", o:vec![], s: None }  
				)
			)} ,
				"BITS Jobs" => 		 Hnode{ 
			d:"Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.",
			t:"T1197",
			o:vec![],
			s: None } ,
				"Build Image on Host" => 		 Hnode{ 
			d:"Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.",
			t:"T1612",
			o:vec![],
			s: None } ,
				"Debugger Evasion" => 		 Hnode{ 
			d:"Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.",
			t:"T1622",
			o:vec![],
			s: None } ,
				"Deobfuscate/Decode Files or Information" => 		 Hnode{ 
			d:"Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.",
			t:"T1140",
			o:vec![],
			s: None } ,
				"Deploy Container" => 		 Hnode{ 
			d:"Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment.",
			t:"T1610",
			o:vec![],
			s: None } ,
				"Direct Volume Access" => 		 Hnode{ 
			d:"Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access controls as well as file system monitoring tools.",
			t:"T1006",
			o:vec![],
			s: None } ,
				"Domain Policy Modification" => 		 Hnode{ 
			d:"Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges in domain environments. Domains provide a centralized means of managing how computer resources (ex: computers, user accounts) can act, and interact with each other, on a network. The policy of the domain also includes configuration settings that may apply between domains in a multi-domain/forest environment. Modifications to domain settings may include altering domain Group Policy Objects (GPOs) or changing trust settings for domains, including federation trusts.",
			t:"T1484",
			o:vec!["Group Policy Modification","Domain Trust Modification"],
			s: Some(
				hashmap!(
					"Group Policy Modification" => Hnode{ d:"Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predicable network path /&lt;DOMAIN&gt;/SYSVOL/&lt;DOMAIN&gt;/Policies/.", t:".001", o:vec![], s: None }  ,
					"Domain Trust Modification" => Hnode{ d:"Adversaries may add new domain trusts or modify the properties of existing domain trusts to evade defenses and/or elevate privileges. Domain trust details, such as whether or not a domain is federated, allow authentication and authorization properties to apply between domains for the purpose of accessing shared resources. These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Execution Guardrails" => 		 Hnode{ 
			d:"Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign. Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.",
			t:"T1480",
			o:vec!["Environmental Keying"],
			s: Some(
				hashmap!(
					"Environmental Keying" => Hnode{ d:"Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment. Environmental keying uses cryptography to constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target. Environmental keying is an implementation of Execution Guardrails that utilizes cryptographic techniques for deriving encryption/decryption keys from specific types of values in a given computing environment.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"Exploitation for Defense Evasion" => 		 Hnode{ 
			d:"Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Vulnerabilities may exist in defensive security software that can be used to disable or circumvent them.",
			t:"T1211",
			o:vec![],
			s: None } ,
				"File and Directory Permissions Modification" => 		 Hnode{ 
			d:"Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).",
			t:"T1222",
			o:vec!["Windows File and Directory Permissions Modification","Linux and Mac File and Directory Permissions Modification"],
			s: Some(
				hashmap!(
					"Windows File and Directory Permissions Modification" => Hnode{ d:"Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).", t:".001", o:vec![], s: None }  ,
					"Linux and Mac File and Directory Permissions Modification" => Hnode{ d:"Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Hide Artifacts" => 		 Hnode{ 
			d:"Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.",
			t:"T1564",
			o:vec!["Hidden Files and Directories","Hidden Users","Hidden Window","NTFS File Attributes","Hidden File System","Run Virtual Instance","VBA Stomping","Email Hiding Rules","Resource Forking","Process Argument Spoofing"],
			s: Some(
				hashmap!(
					"Hidden Files and Directories" => Hnode{ d:"Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS).", t:".001", o:vec![], s: None }  ,
					"Hidden Users" => Hnode{ d:"Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other management accounts from other users.", t:".002", o:vec![], s: None }  ,
					"Hidden Window" => Hnode{ d:"Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks.", t:".003", o:vec![], s: None }  ,
					"NTFS File Attributes" => Hnode{ d:"Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. Within MFT entries are file attributes, such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files).", t:".004", o:vec![], s: None }  ,
					"Hidden File System" => Hnode{ d:"Adversaries may use a hidden file system to conceal malicious activity from users and security tools. File systems provide a structure to store and access data from physical storage. Typically, a user engages with a file system through applications that allow them to access files and directories, which are an abstraction from their physical location (ex: disk sector). Standard file systems include FAT, NTFS, ext4, and APFS. File systems can also contain other structures, such as the Volume Boot Record (VBR) and Master File Table (MFT) in NTFS.", t:".005", o:vec![], s: None }  ,
					"Run Virtual Instance" => Hnode{ d:"Adversaries may carry out malicious operations using a virtual instance to avoid detection. A wide variety of virtualization technologies exist that allow for the emulation of a computer or computing environment. By running malicious code inside of a virtual instance, adversaries can hide artifacts associated with their behavior from security tools that are unable to monitor activity inside the virtual instance. Additionally, depending on the virtual networking implementation (ex: bridged adapter), network traffic generated by the virtual instance can be difficult to trace back to the compromised host as the IP address and hostname might not match known values.", t:".006", o:vec![], s: None }  ,
					"VBA Stomping" => Hnode{ d:"Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data.", t:".007", o:vec![], s: None }  ,
					"Email Hiding Rules" => Hnode{ d:"Adversaries may use email rules to hide inbound emails in a compromised user's mailbox. Many email clients allow users to create inbox rules for various email functions, including moving emails to other folders, marking emails as read, or deleting emails. Rules may be created or modified within email clients or through external features such as the New-InboxRule or Set-InboxRule PowerShell cmdlets on Windows systems.", t:".008", o:vec![], s: None }  ,
					"Resource Forking" => Hnode{ d:"Adversaries may abuse resource forks to hide malicious code or executables to evade detection and bypass security applications. A resource fork provides applications a structured way to store resources such as thumbnail images, menu definitions, icons, dialog boxes, and code. Usage of a resource fork is identifiable when displaying a file’s extended attributes, using ls -l@ or xattr -l commands. Resource forks have been deprecated and replaced with the application bundle structure. Non-localized resources are placed at the top level directory of an application bundle, while localized resources are placed in the /Resources folder.", t:".009", o:vec![], s: None }  ,
					"Process Argument Spoofing" => Hnode{ d:"Adversaries may attempt to hide process command-line arguments by overwriting process memory. Process command-line arguments are stored in the process environment block (PEB), a data structure used by Windows to store various information about/used by a process. The PEB includes the process command-line arguments that are referenced when executing the process. When a process is created, defensive tools/sensors that monitor process creations may retrieve the process arguments from the PEB.", t:".010", o:vec![], s: None }  
				)
			)} ,
				"Hijack Execution Flow" => 		 Hnode{ 
			d:"Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.",
			t:"T1574",
			o:vec!["DLL Search Order Hijacking","DLL Side-Loading","Dylib Hijacking","Executable Installer File Permissions Weakness","Dynamic Linker Hijacking","Path Interception by PATH Environment Variable","Path Interception by Search Order Hijacking","Path Interception by Unquoted Path","Services File Permissions Weakness","Services Registry Permissions Weakness","COR_PROFILER","KernelCallbackTable"],
			s: Some(
				hashmap!(
					"DLL Search Order Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.", t:".001", o:vec![], s: None }  ,
					"DLL Side-Loading" => Hnode{ d:"Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to DLL Search Order Hijacking, side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).", t:".002", o:vec![], s: None }  ,
					"Dylib Hijacking" => Hnode{ d:"Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with @rpath, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable. Additionally, if weak linking is used, such as the LC_LOAD_WEAK_DYLIB function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added.", t:".004", o:vec![], s: None }  ,
					"Executable Installer File Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.", t:".005", o:vec![], s: None }  ,
					"Dynamic Linker Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as LD_PRELOAD on Linux or DYLD_INSERT_LIBRARIES on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name. These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library.", t:".006", o:vec![], s: None }  ,
					"Path Interception by PATH Environment Variable" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. Adversaries may place a program in an earlier entry in the list of directories stored in the PATH environment variable, which Windows will then execute when it searches sequentially through that PATH listing in search of the binary that was called from a script or the command line.", t:".007", o:vec![], s: None }  ,
					"Path Interception by Search Order Hijacking" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.", t:".008", o:vec![], s: None }  ,
					"Path Interception by Unquoted Path" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.", t:".009", o:vec![], s: None }  ,
					"Services File Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.", t:".010", o:vec![], s: None }  ,
					"Services Registry Permissions Weakness" => Hnode{ d:"Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under HKLM/SYSTEM/CurrentControlSet/Services. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, PowerShell, or Reg. Access to Registry keys is controlled through access control lists and user permissions.", t:".011", o:vec![], s: None }  ,
					"COR_PROFILER" => Hnode{ d:"Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.", t:".012", o:vec![], s: None }  ,
					"KernelCallbackTable" => Hnode{ d:"Adversaries may abuse the KernelCallbackTable of a process to hijack its execution flow in order to run their own payloads. The KernelCallbackTable can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once user32.dll is loaded.", t:".013", o:vec![], s: None }  
				)
			)} ,
				"Impair Defenses" => 		 Hnode{ 
			d:"Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.",
			t:"T1562",
			o:vec!["Disable or Modify Tools","Disable Windows Event Logging","Impair Command History Logging","Disable or Modify System Firewall","Indicator Blocking","Disable or Modify Cloud Firewall","Disable Cloud Logs","Safe Mode Boot","Downgrade Attack"],
			s: Some(
				hashmap!(
					"Disable or Modify Tools" => Hnode{ d:"Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or configuration files so that tools do not operate properly, or other methods to interfere with security tools scanning or reporting information. Adversaries may also disable updates to prevent the latest security patches from reaching tools on victim systems.", t:".001", o:vec![], s: None }  ,
					"Disable Windows Event Logging" => Hnode{ d:"Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more. This data is used by security tools and analysts to generate detections.", t:".002", o:vec![], s: None }  ,
					"Impair Command History Logging" => Hnode{ d:"Adversaries may impair command history logging to hide commands they run on a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.", t:".003", o:vec![], s: None }  ,
					"Disable or Modify System Firewall" => Hnode{ d:"Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depending on the operating system, including via command-line, editing Windows Registry keys, and Windows Control Panel.", t:".004", o:vec![], s: None }  ,
					"Indicator Blocking" => Hnode{ d:"An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting or even disabling host-based sensors, such as Event Tracing for Windows (ETW), by tampering settings that control the collection and flow of event telemetry. These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as PowerShell or Windows Management Instrumentation.", t:".006", o:vec![], s: None }  ,
					"Disable or Modify Cloud Firewall" => Hnode{ d:"Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources. Cloud firewalls are separate from system firewalls that are described in Disable or Modify System Firewall.", t:".007", o:vec![], s: None }  ,
					"Disable Cloud Logs" => Hnode{ d:"An adversary may disable cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection.", t:".008", o:vec![], s: None }  ,
					"Safe Mode Boot" => Hnode{ d:"Adversaries may abuse Windows safe mode to disable endpoint defenses. Safe mode starts up the Windows operating system with a limited set of drivers and services. Third-party security software such as endpoint detection and response (EDR) tools may not start after booting Windows in safe mode. There are two versions of safe mode: Safe Mode and Safe Mode with Networking. It is possible to start additional services after a safe mode boot.", t:".009", o:vec![], s: None }  ,
					"Downgrade Attack" => Hnode{ d:"Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls such as logging. For example, PowerShell versions 5+ includes Script Block Logging (SBL) which can record executed script content. However, adversaries may attempt to execute a previous version of PowerShell that does not support SBL with the intent to Impair Defenses while running malicious scripts that may have otherwise been detected.", t:".010", o:vec![], s: None }  
				)
			)} ,
				"Indicator Removal" => 		 Hnode{ 
			d:"Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.",
			t:"T1070",
			o:vec!["Clear Windows Event Logs","Clear Linux or Mac System Logs","Clear Command History","File Deletion","Network Share Connection Removal","Timestomp","Clear Network Connection History and Configurations","Clear Mailbox Data","Clear Persistence"],
			s: Some(
				hashmap!(
					"Clear Windows Event Logs" => Hnode{ d:"Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit.", t:".001", o:vec![], s: None }  ,
					"Clear Linux or Mac System Logs" => Hnode{ d:"Adversaries may clear system logs to hide evidence of an intrusion. macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the /var/log/ directory. Subfolders in this directory categorize logs by their related functions, such as:", t:".002", o:vec![], s: None }  ,
					"Clear Command History" => Hnode{ d:"In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.", t:".003", o:vec![], s: None }  ,
					"File Deletion" => Hnode{ d:"Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: Ingress Tool Transfer) may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.", t:".004", o:vec![], s: None }  ,
					"Network Share Connection Removal" => Hnode{ d:"Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and SMB/Windows Admin Shares connections can be removed when no longer needed. Net is an example utility that can be used to remove network share connections with the net use /system/share /delete command.", t:".005", o:vec![], s: None }  ,
					"Timestomp" => Hnode{ d:"Adversaries may modify file time attributes to hide new or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools.", t:".006", o:vec![], s: None }  ,
					"Clear Network Connection History and Configurations" => Hnode{ d:"Adversaries may clear or remove evidence of malicious network connections in order to clean up traces of their operations. Configuration settings as well as various artifacts that highlight connection history may be created on a system from behaviors that require network connections, such as Remote Services or External Remote Services. Defenders may use these artifacts to monitor or otherwise analyze network connections created by adversaries.", t:".007", o:vec![], s: None }  ,
					"Clear Mailbox Data" => Hnode{ d:"Adversaries may modify mail application data to remove evidence of their activity. Email applications allow users and other programs to export and delete mailbox data via command line tools or use of APIs. Mail application data can be emails or logs generated by the application or operating system, such as export requests.", t:".008", o:vec![], s: None }  ,
					"Clear Persistence" => Hnode{ d:"Adversaries may clear artifacts associated with previously established persistence on a host system to remove evidence of their activity. This may involve various actions, such as removing services, deleting executables, Modify Registry, Plist File Modification, or other methods of cleanup to prevent defenders from collecting evidence of their persistent presence.", t:".009", o:vec![], s: None }  
				)
			)} ,
				"Indirect Command Execution" => 		 Hnode{ 
			d:"Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command and Scripting Interpreter, Run window, or via scripts.",
			t:"T1202",
			o:vec![],
			s: None } ,
				"Masquerading" => 		 Hnode{ 
			d:"Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.",
			t:"T1036",
			o:vec!["Invalid Code Signature","Right-to-Left Override","Rename System Utilities","Masquerade Task or Service","Match Legitimate Name or Location","Space after Filename","Double File Extension"],
			s: Some(
				hashmap!(
					"Invalid Code Signature" => Hnode{ d:"Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. Adversaries can copy the metadata and signature information from a signed program, then use it as a template for an unsigned program. Files with invalid code signatures will fail digital signature validation checks, but they may appear more legitimate to users and security tools may improperly handle these files.", t:".001", o:vec![], s: None }  ,
					"Right-to-Left Override" => Hnode{ d:"Adversaries may abuse the right-to-left override (RTLO or RLO) character (U+202E) to disguise a string and/or file name to make it appear benign. RTLO is a non-printing Unicode character that causes the text that follows it to be displayed in reverse. For example, a Windows screensaver executable named March 25 /u202Excod.scr will display as March 25 rcs.docx. A JavaScript file named photo_high_re/u202Egnp.js will be displayed as photo_high_resj.png.", t:".002", o:vec![], s: None }  ,
					"Rename System Utilities" => Hnode{ d:"Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing. It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename rundll32.exe). An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths.", t:".003", o:vec![], s: None }  ,
					"Masquerade Task or Service" => Hnode{ d:"Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign. Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description. Windows services will have a service name as well as a display name. Many benign tasks and services exist that have commonly associated names. Adversaries may give tasks or services names that are similar or identical to those of legitimate ones.", t:".004", o:vec![], s: None }  ,
					"Match Legitimate Name or Location" => Hnode{ d:"Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing them. This is done for the sake of evading defenses and observation. This may be done by placing an executable in a commonly trusted directory (ex: under System32) or giving it the name of a legitimate, trusted program (ex: svchost.exe). In containerized environments, this may also be done by creating a resource in a namespace that matches the naming convention of a container pod or cluster. Alternatively, a file or container image name given may be a close approximation to legitimate programs/images or something innocuous.", t:".005", o:vec![], s: None }  ,
					"Space after Filename" => Hnode{ d:"Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system.", t:".006", o:vec![], s: None }  ,
					"Double File Extension" => Hnode{ d:"Adversaries may abuse a double extension in the filename as a means of masquerading the true file type. A file name may include a secondary file type extension that may cause only the first extension to be displayed (ex: File.txt.exe may render in some views as just File.txt). However, the second extension is the true file type that determines how the file is opened and executed. The real file extension may be hidden by the operating system in the file browser (ex: explorer.exe), as well as in any software configured using or similar to the system’s policies.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Modify Authentication Process" => 		 Hnode{ 
			d:"Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts.",
			t:"T1556",
			o:vec!["Domain Controller Authentication","Password Filter DLL","Pluggable Authentication Modules","Network Device Authentication","Reversible Encryption","Multi-Factor Authentication","Hybrid Identity"],
			s: Some(
				hashmap!(
					"Domain Controller Authentication" => Hnode{ d:"Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts.", t:".001", o:vec![], s: None }  ,
					"Password Filter DLL" => Hnode{ d:"Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.", t:".002", o:vec![], s: None }  ,
					"Pluggable Authentication Modules" => Hnode{ d:"Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow.", t:".003", o:vec![], s: None }  ,
					"Network Device Authentication" => Hnode{ d:"Adversaries may use Patch System Image to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.", t:".004", o:vec![], s: None }  ,
					"Reversible Encryption" => Hnode{ d:"An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it.", t:".005", o:vec![], s: None }  ,
					"Multi-Factor Authentication" => Hnode{ d:"Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.", t:".006", o:vec![], s: None }  ,
					"Hybrid Identity" => Hnode{ d:"Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Modify Cloud Compute Infrastructure" => 		 Hnode{ 
			d:"An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.",
			t:"T1578",
			o:vec!["Create Snapshot","Create Cloud Instance","Delete Cloud Instance","Revert Cloud Instance"],
			s: Some(
				hashmap!(
					"Create Snapshot" => Hnode{ d:"An adversary may create a snapshot or data backup within a cloud account to evade defenses. A snapshot is a point-in-time copy of an existing cloud compute component such as a virtual machine (VM), virtual hard drive, or volume. An adversary may leverage permissions to create a snapshot in order to bypass restrictions that prevent access to existing compute service infrastructure, unlike in Revert Cloud Instance where an adversary may revert to a snapshot to evade detection and remove evidence of their presence.", t:".001", o:vec![], s: None }  ,
					"Create Cloud Instance" => Hnode{ d:"An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses. Creating a new instance may allow an adversary to bypass firewall rules and permissions that exist on instances currently residing within an account. An adversary may Create Snapshot of one or more volumes in an account, create a new instance, mount the snapshots, and then apply a less restrictive security policy to collect Data from Local System or for Remote Data Staging.", t:".002", o:vec![], s: None }  ,
					"Delete Cloud Instance" => Hnode{ d:"An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence. Deleting an instance or virtual machine can remove valuable forensic artifacts and other evidence of suspicious behavior if the instance is not recoverable.", t:".003", o:vec![], s: None }  ,
					"Revert Cloud Instance" => Hnode{ d:"An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence. In highly virtualized environments, such as cloud-based infrastructure, this may be accomplished by restoring virtual machine (VM) or data storage snapshots through the cloud management dashboard or cloud APIs.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Modify Registry" => 		 Hnode{ 
			d:"Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.",
			t:"T1112",
			o:vec![],
			s: None } ,
				"Modify System Image" => 		 Hnode{ 
			d:"Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves. On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.",
			t:"T1601",
			o:vec!["Patch System Image","Downgrade System Image"],
			s: Some(
				hashmap!(
					"Patch System Image" => Hnode{ d:"Adversaries may modify the operating system of a network device to introduce new capabilities or weaken existing defenses. Some network devices are built with a monolithic architecture, where the entire operating system and most of the functionality of the device is contained within a single file. Adversaries may change this file in storage, to be loaded in a future boot, or in memory during runtime.", t:".001", o:vec![], s: None }  ,
					"Downgrade System Image" => Hnode{ d:"Adversaries may install an older version of the operating system of a network device to weaken security. Older operating system versions on network devices often have weaker encryption ciphers and, in general, fewer/less updated defensive features.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Network Boundary Bridging" => 		 Hnode{ 
			d:"Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.",
			t:"T1599",
			o:vec!["Network Address Translation Traversal"],
			s: Some(
				hashmap!(
					"Network Address Translation Traversal" => Hnode{ d:"Adversaries may bridge network boundaries by modifying a network device’s Network Address Translation (NAT) configuration. Malicious modifications to NAT may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"Obfuscated Files or Information" => 		 Hnode{ 
			d:"Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.",
			t:"T1027",
			o:vec!["Binary Padding","Software Packing","Steganography","Compile After Delivery","Indicator Removal from Tools","HTML Smuggling","Dynamic API Resolution","Stripped Payloads","Embedded Payloads"],
			s: Some(
				hashmap!(
					"Binary Padding" => Hnode{ d:"Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This can be done without affecting the functionality or behavior of a binary, but can increase the size of the binary beyond what some security tools are capable of handling due to file size limitations.", t:".001", o:vec![], s: None }  ,
					"Software Packing" => Hnode{ d:"Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.", t:".002", o:vec![], s: None }  ,
					"Steganography" => Hnode{ d:"Adversaries may use steganography techniques in order to prevent the detection of hidden information. Steganographic techniques can be used to hide data in digital media such as images, audio tracks, video clips, or text files.", t:".003", o:vec![], s: None }  ,
					"Compile After Delivery" => Hnode{ d:"Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.", t:".004", o:vec![], s: None }  ,
					"Indicator Removal from Tools" => Hnode{ d:"Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed. They can modify the tool by removing the indicator and using the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.", t:".005", o:vec![], s: None }  ,
					"HTML Smuggling" => Hnode{ d:"Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files. HTML documents can store large binary objects known as JavaScript Blobs (immutable data that represents raw bytes) that can later be constructed into file-like objects. Data may also be stored in Data URLs, which enable embedding media type or MIME files inline of HTML documents. HTML5 also introduced a download attribute that may be used to initiate file downloads.", t:".006", o:vec![], s: None }  ,
					"Dynamic API Resolution" => Hnode{ d:"Adversaries may obfuscate then dynamically resolve API functions called by their malware in order to conceal malicious functionalities and impair defensive analysis. Malware commonly uses various Native API functions provided by the OS to perform various tasks such as those involving processes, files, and other system artifacts.", t:".007", o:vec![], s: None }  ,
					"Stripped Payloads" => Hnode{ d:"Adversaries may attempt to make a payload difficult to analyze by removing symbols, strings, and other human readable information. Scripts and executables may contain variables names and other strings that help developers document code functionality. Symbols are often created by an operating system’s linker when executable payloads are compiled. Reverse engineers use these symbols and strings to analyze code and to identify functionality in payloads.", t:".008", o:vec![], s: None }  ,
					"Embedded Payloads" => Hnode{ d:"Adversaries may embed payloads within other files to conceal malicious content from defenses. Otherwise seemingly benign files (such as scripts and executables) may be abused to carry and obfuscate malicious payloads and content. In some cases, embedded payloads may also enable adversaries to Subvert Trust Controls by not impacting execution controls such as digital signatures and notarization tickets.", t:".009", o:vec![], s: None }  
				)
			)} ,
				"Plist File Modification" => 		 Hnode{ 
			d:"Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses. macOS applications use plist files, such as the info.plist file, to store properties and configuration settings that inform the operating system how to handle the application at runtime. Plist files are structured metadata in key-value pairs formatted in XML based on Apple's Core Foundation DTD. Plist files can be saved in text or binary format.",
			t:"T1647",
			o:vec![],
			s: None } ,
				"Pre-OS Boot" => 		 Hnode{ 
			d:"Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.",
			t:"T1542",
			o:vec!["System Firmware","Component Firmware","Bootkit","ROMMONkit","TFTP Boot"],
			s: Some(
				hashmap!(
					"System Firmware" => Hnode{ d:"Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.", t:".001", o:vec![], s: None }  ,
					"Component Firmware" => Hnode{ d:"Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to System Firmware but conducted upon other system components/devices that may not have the same capability or level of integrity checking.", t:".002", o:vec![], s: None }  ,
					"Bootkit" => Hnode{ d:"Adversaries may use bootkits to persist on systems. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly.", t:".003", o:vec![], s: None }  ,
					"ROMMONkit" => Hnode{ d:"Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect.", t:".004", o:vec![], s: None }  ,
					"TFTP Boot" => Hnode{ d:"Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Process Injection" => 		 Hnode{ 
			d:"Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.",
			t:"T1055",
			o:vec!["Dynamic-link Library Injection","Portable Executable Injection","Thread Execution Hijacking","Asynchronous Procedure Call","Thread Local Storage","Ptrace System Calls","Proc Memory","Extra Window Memory Injection","Process Hollowing","Process Doppelgänging","VDSO Hijacking","ListPlanting"],
			s: Some(
				hashmap!(
					"Dynamic-link Library Injection" => Hnode{ d:"Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.", t:".001", o:vec![], s: None }  ,
					"Portable Executable Injection" => Hnode{ d:"Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process.", t:".002", o:vec![], s: None }  ,
					"Thread Execution Hijacking" => Hnode{ d:"Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process.", t:".003", o:vec![], s: None }  ,
					"Asynchronous Procedure Call" => Hnode{ d:"Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process.", t:".004", o:vec![], s: None }  ,
					"Thread Local Storage" => Hnode{ d:"Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process.", t:".005", o:vec![], s: None }  ,
					"Ptrace System Calls" => Hnode{ d:"Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.", t:".008", o:vec![], s: None }  ,
					"Proc Memory" => Hnode{ d:"Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process.", t:".009", o:vec![], s: None }  ,
					"Extra Window Memory Injection" => Hnode{ d:"Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process.", t:".011", o:vec![], s: None }  ,
					"Process Hollowing" => Hnode{ d:"Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.", t:".012", o:vec![], s: None }  ,
					"Process Doppelgänging" => Hnode{ d:"Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a separate live process.", t:".013", o:vec![], s: None }  ,
					"VDSO Hijacking" => Hnode{ d:"Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process.", t:".014", o:vec![], s: None }  ,
					"ListPlanting" => Hnode{ d:"Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of a separate live process. Code executed via ListPlanting may also evade detection from security products since the execution is masked under a legitimate process.", t:".015", o:vec![], s: None }  
				)
			)} ,
				"Reflective Code Loading" => 		 Hnode{ 
			d:"Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk. Reflectively loaded payloads may be compiled binaries, anonymous files (only present in RAM), or just snubs of fileless executable code (ex: position-independent shellcode).",
			t:"T1620",
			o:vec![],
			s: None } ,
				"Rogue Domain Controller" => 		 Hnode{ 
			d:"Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC. Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.",
			t:"T1207",
			o:vec![],
			s: None } ,
				"Rootkit" => 		 Hnode{ 
			d:"Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information.",
			t:"T1014",
			o:vec![],
			s: None } ,
				"Subvert Trust Controls" => 		 Hnode{ 
			d:"Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.",
			t:"T1553",
			o:vec!["Gatekeeper Bypass","Code Signing","SIP and Trust Provider Hijacking","Install Root Certificate","Mark-of-the-Web Bypass","Code Signing Policy Modification"],
			s: Some(
				hashmap!(
					"Gatekeeper Bypass" => Hnode{ d:"Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs. Gatekeeper is a set of technologies that act as layer of Apple’s security model to ensure only trusted applications are executed on a host. Gatekeeper was built on top of File Quarantine in Snow Leopard (10.6, 2009) and has grown to include Code Signing, security policy compliance, Notarization, and more. Gatekeeper also treats applications running for the first time differently than reopened applications.", t:".001", o:vec![], s: None }  ,
					"Code Signing" => Hnode{ d:"Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. The certificates used during an operation may be created, acquired, or stolen by the adversary. Unlike Invalid Code Signature, this activity will result in a valid signature.", t:".002", o:vec![], s: None }  ,
					"SIP and Trust Provider Hijacking" => Hnode{ d:"Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks. In user mode, Windows Authenticode digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code (ex: a driver with a valid Microsoft signature may be handled as safe). The signature validation process is handled via the WinVerifyTrust application programming interface (API) function, which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a signature.", t:".003", o:vec![], s: None }  ,
					"Install Root Certificate" => Hnode{ d:"Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website.", t:".004", o:vec![], s: None }  ,
					"Mark-of-the-Web Bypass" => Hnode{ d:"Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. In Windows, when files are downloaded from the Internet, they are tagged with a hidden NTFS Alternate Data Stream (ADS) named Zone.Identifier with a specific value known as the MOTW. Files that are tagged with MOTW are protected and cannot perform certain actions. For example, starting in MS Office 10, if a MS Office file has the MOTW, it will open in Protected View. Executables tagged with the MOTW will be processed by Windows Defender SmartScreen that compares files with an allowlist of well-known executables. If the file in not known/trusted, SmartScreen will prevent the execution and warn the user not to run it.", t:".005", o:vec![], s: None }  ,
					"Code Signing Policy Modification" => Hnode{ d:"Adversaries may modify code signing policies to enable execution of unsigned or self-signed code. Code signing provides a level of authenticity on a program from a developer and a guarantee that the program has not been tampered with. Security controls can include enforcement mechanisms to ensure that only valid, signed code can be run on an operating system.", t:".006", o:vec![], s: None }  
				)
			)} ,
				"System Binary Proxy Execution" => 		 Hnode{ 
			d:"Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system. Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.",
			t:"T1218",
			o:vec!["Compiled HTML File","Control Panel","CMSTP","InstallUtil","Mshta","Msiexec","Odbcconf","Regsvcs/Regasm","Regsvr32","Rundll32","Verclsid","Mavinject","MMC"],
			s: Some(
				hashmap!(
					"Compiled HTML File" => Hnode{ d:"Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe).", t:".001", o:vec![], s: None }  ,
					"Control Panel" => Hnode{ d:"Adversaries may abuse control.exe to proxy execution of malicious payloads. The Windows Control Panel process binary (control.exe) handles execution of Control Panel items, which are utilities that allow users to view and adjust computer settings.", t:".002", o:vec![], s: None }  ,
					"CMSTP" => Hnode{ d:"Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.", t:".003", o:vec![], s: None }  ,
					"InstallUtil" => Hnode{ d:"Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. The InstallUtil binary may also be digitally signed by Microsoft and located in the .NET directories on a Windows system: C:/Windows/Microsoft.NET/Framework/v/InstallUtil.exe and C:/Windows/Microsoft.NET/Framework64/v/InstallUtil.exe.", t:".004", o:vec![], s: None }  ,
					"Mshta" => Hnode{ d:"Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code", t:".005", o:vec![], s: None }  ,
					"Msiexec" => Hnode{ d:"Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi). The Msiexec.exe binary may also be digitally signed by Microsoft.", t:".007", o:vec![], s: None }  ,
					"Odbcconf" => Hnode{ d:"Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names. The Odbcconf.exe binary may be digitally signed by Microsoft.", t:".008", o:vec![], s: None }  ,
					"Regsvcs/Regasm" => Hnode{ d:"Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are binaries that may be digitally signed by Microsoft.", t:".009", o:vec![], s: None }  ,
					"Regsvr32" => Hnode{ d:"Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. The Regsvr32.exe binary may also be signed by Microsoft.", t:".010", o:vec![], s: None }  ,
					"Rundll32" => Hnode{ d:"Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads (ex: rundll32.exe {DLLname, DLLfunction}).", t:".011", o:vec![], s: None }  ,
					"Verclsid" => Hnode{ d:"Adversaries may abuse verclsid.exe to proxy execution of malicious code. Verclsid.exe is known as the Extension CLSID Verification Host and is responsible for verifying each shell extension before they are used by Windows Explorer or the Windows Shell.", t:".012", o:vec![], s: None }  ,
					"Mavinject" => Hnode{ d:"Adversaries may abuse mavinject.exe to proxy execution of malicious code. Mavinject.exe is the Microsoft Application Virtualization Injector, a Windows utility that can inject code into external processes as part of Microsoft Application Virtualization (App-V).", t:".013", o:vec![], s: None }  ,
					"MMC" => Hnode{ d:"Adversaries may abuse mmc.exe to proxy execution of malicious .msc files. Microsoft Management Console (MMC) is a binary that may be signed by Microsoft and is used in several ways in either its GUI or in a command prompt. MMC can be used to create, open, and save custom consoles that contain administrative tools created by Microsoft, called snap-ins. These snap-ins may be used to manage Windows systems locally or remotely. MMC can also be used to open Microsoft created .msc files to manage system configuration.", t:".014", o:vec![], s: None }  
				)
			)} ,
				"System Script Proxy Execution" => 		 Hnode{ 
			d:"Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy execution of other files. This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.",
			t:"T1216",
			o:vec!["PubPrn"],
			s: Some(
				hashmap!(
					"PubPrn" => Hnode{ d:"Adversaries may use PubPrn to proxy execution of malicious remote files. PubPrn.vbs is a Visual Basic script that publishes a printer to Active Directory Domain Services. The script may be signed by Microsoft and is commonly executed through the Windows Command Shell via Cscript.exe. For example, the following code publishes a printer within the specified domain: cscript pubprn Printer1 LDAP://CN=Container1,DC=Domain1,DC=Com.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"Template Injection" => 		 Hnode{ 
			d:"Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts. For example, Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered.",
			t:"T1221",
			o:vec![],
			s: None } ,
				"Traffic Signaling" => 		 Hnode{ 
			d:"Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.",
			t:"T1205",
			o:vec!["Port Knocking","Socket Filters"],
			s: Some(
				hashmap!(
					"Port Knocking" => Hnode{ d:"Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.", t:".001", o:vec![], s: None }  ,
					"Socket Filters" => Hnode{ d:"Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the libpcap library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Trusted Developer Utilities Proxy Execution" => 		 Hnode{ 
			d:"Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.",
			t:"T1127",
			o:vec!["MSBuild"],
			s: Some(
				hashmap!(
					"MSBuild" => Hnode{ d:"Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for loading and building various platforms and configurations.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"Unused/Unsupported Cloud Regions" => 		 Hnode{ 
			d:"Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.",
			t:"T1535",
			o:vec![],
			s: None } ,
				"Use Alternate Authentication Material" => 		 Hnode{ 
			d:"Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.",
			t:"T1550",
			o:vec!["Application Access Token","Pass the Hash","Pass the Ticket","Web Session Cookie"],
			s: Some(
				hashmap!(
					"Application Access Token" => Hnode{ d:"Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials.", t:".001", o:vec![], s: None }  ,
					"Pass the Hash" => Hnode{ d:"Adversaries may QUOTEpass the hashQUOTE using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash.", t:".002", o:vec![], s: None }  ,
					"Pass the Ticket" => Hnode{ d:"Adversaries may QUOTEpass the ticketQUOTE using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.", t:".003", o:vec![], s: None }  ,
					"Web Session Cookie" => Hnode{ d:"Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Valid Accounts" => 		 Hnode{ 
			d:"Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
			t:"T1078",
			o:vec!["Default Accounts","Domain Accounts","Local Accounts","Cloud Accounts"],
			s: Some(
				hashmap!(
					"Default Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes.", t:".001", o:vec![], s: None }  ,
					"Domain Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.", t:".002", o:vec![], s: None }  ,
					"Local Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.", t:".003", o:vec![], s: None }  ,
					"Cloud Accounts" => Hnode{ d:"Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. In some cases, cloud accounts may be federated with traditional identity management system, such as Window Active Directory.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Virtualization/Sandbox Evasion" => 		 Hnode{ 
			d:"Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.",
			t:"T1497",
			o:vec!["System Checks","User Activity Based Checks","Time Based Evasion"],
			s: Some(
				hashmap!(
					"System Checks" => Hnode{ d:"Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.", t:".001", o:vec![], s: None }  ,
					"User Activity Based Checks" => Hnode{ d:"Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.", t:".002", o:vec![], s: None }  ,
					"Time Based Evasion" => Hnode{ d:"Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Weaken Encryption" => 		 Hnode{ 
			d:"Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.",
			t:"T1600",
			o:vec!["Reduce Key Space","Disable Crypto Hardware"],
			s: Some(
				hashmap!(
					"Reduce Key Space" => Hnode{ d:"Adversaries may reduce the level of effort required to decrypt data transmitted over the network by reducing the cipher strength of encrypted communications.", t:".001", o:vec![], s: None }  ,
					"Disable Crypto Hardware" => Hnode{ d:"Adversaries disable a network device’s dedicated hardware encryption, which may enable them to leverage weaknesses in software encryption in order to reduce the effort involved in collecting, manipulating, and exfiltrating transmitted data.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"XSL Script Processing" => 		 Hnode{ 
			d:"Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages.",
			t:"T1220",
			o:vec![],
			s: None } 
			)
		)} ,
	"CredentialAccess" => 	Hnode{ 
		d:"safe_str(The adversary is trying to steal account names and passwords.Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.)",
		t:"None",
		o:vec!["Adversary-in-the-Middle","Brute Force","Credentials from Password Stores","Exploitation for Credential Access","Forced Authentication","Forge Web Credentials","Input Capture","Modify Authentication Process","Multi-Factor Authentication Interception","Multi-Factor Authentication Request Generation","Network Sniffing","OS Credential Dumping","Steal Application Access Token","Steal or Forge Authentication Certificates","Steal or Forge Kerberos Tickets","Steal Web Session Cookie","Unsecured Credentials"],
		s: Some(
			hashmap!(
				"Adversary-in-the-Middle" => 		 Hnode{ 
			d:"Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.",
			t:"T1557",
			o:vec!["LLMNR/NBT-NS Poisoning and SMB Relay","ARP Cache Poisoning","DHCP Spoofing"],
			s: Some(
				hashmap!(
					"LLMNR/NBT-NS Poisoning and SMB Relay" => Hnode{ d:"By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.", t:".001", o:vec![], s: None }  ,
					"ARP Cache Poisoning" => Hnode{ d:"Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.", t:".002", o:vec![], s: None }  ,
					"DHCP Spoofing" => Hnode{ d:"Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Brute Force" => 		 Hnode{ 
			d:"Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.",
			t:"T1110",
			o:vec!["Password Guessing","Password Cracking","Password Spraying","Credential Stuffing"],
			s: Some(
				hashmap!(
					"Password Guessing" => Hnode{ d:"Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts.", t:".001", o:vec![], s: None }  ,
					"Password Cracking" => Hnode{ d:"Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. OS Credential Dumping can be used to obtain password hashes, this may only get an adversary so far when Pass the Hash is not an option. Further, adversaries may leverage Data from Configuration Repository in order to obtain hashed credentials for network devices.", t:".002", o:vec![], s: None }  ,
					"Password Spraying" => Hnode{ d:"Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords.", t:".003", o:vec![], s: None }  ,
					"Credential Stuffing" => Hnode{ d:"Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Credentials from Password Stores" => 		 Hnode{ 
			d:"Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.",
			t:"T1555",
			o:vec!["Keychain","Securityd Memory","Credentials from Web Browsers","Windows Credential Manager","Password Managers"],
			s: Some(
				hashmap!(
					"Keychain" => Hnode{ d:"Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes. There are three types of Keychains: Login Keychain, System Keychain, and Local Items (iCloud) Keychain. The default Keychain is the Login Keychain, which stores user passwords and information. The System Keychain stores items accessed by the operating system, such as items shared among users on a host. The Local Items (iCloud) Keychain is used for items synced with Apple’s iCloud service.", t:".001", o:vec![], s: None }  ,
					"Securityd Memory" => Hnode{ d:"An adversary may obtain root access (allowing them to read securityd’s memory), then they can scan through memory to find the correct sequence of keys in relatively few tries to decrypt the user’s logon keychain. This provides the adversary with all the plaintext passwords for users, WiFi, mail, browsers, certificates, secure notes, etc.", t:".002", o:vec![], s: None }  ,
					"Credentials from Web Browsers" => Hnode{ d:"Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.", t:".003", o:vec![], s: None }  ,
					"Windows Credential Manager" => Hnode{ d:"Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (previously known as Windows Vaults).", t:".004", o:vec![], s: None }  ,
					"Password Managers" => Hnode{ d:"Adversaries may acquire user credentials from third-party password managers. Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database. After the database is unlocked, these credentials may be copied to memory. These databases can be stored as files on disk.", t:".005", o:vec![], s: None }  
				)
			)} ,
				"Exploitation for Credential Access" => 		 Hnode{ 
			d:"Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain access to systems. One example of this is MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions. Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.",
			t:"T1212",
			o:vec![],
			s: None } ,
				"Forced Authentication" => 		 Hnode{ 
			d:"Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.",
			t:"T1187",
			o:vec![],
			s: None } ,
				"Forge Web Credentials" => 		 Hnode{ 
			d:"Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.",
			t:"T1606",
			o:vec!["Web Cookies","SAML Tokens"],
			s: Some(
				hashmap!(
					"Web Cookies" => Hnode{ d:"Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access.", t:".001", o:vec![], s: None }  ,
					"SAML Tokens" => Hnode{ d:"An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate. The default lifetime of a SAML token is one hour, but the validity period can be specified in the NotOnOrAfter value of the conditions ... element in a token. This value can be changed using the AccessTokenLifetime in a LifetimeTokenPolicy. Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO (single sign-on) mechanism.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Input Capture" => 		 Hnode{ 
			d:"Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).",
			t:"T1056",
			o:vec!["Keylogging","GUI Input Capture","Web Portal Capture","Credential API Hooking"],
			s: Some(
				hashmap!(
					"Keylogging" => Hnode{ d:"Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when OS Credential Dumping efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.", t:".001", o:vec![], s: None }  ,
					"GUI Input Capture" => Hnode{ d:"Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: Bypass User Account Control).", t:".002", o:vec![], s: None }  ,
					"Web Portal Capture" => Hnode{ d:"Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.", t:".003", o:vec![], s: None }  ,
					"Credential API Hooking" => Hnode{ d:"Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials. Unlike Keylogging, this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Modify Authentication Process" => 		 Hnode{ 
			d:"Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using Valid Accounts.",
			t:"T1556",
			o:vec!["Domain Controller Authentication","Password Filter DLL","Pluggable Authentication Modules","Network Device Authentication","Reversible Encryption","Multi-Factor Authentication","Hybrid Identity"],
			s: Some(
				hashmap!(
					"Domain Controller Authentication" => Hnode{ d:"Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts.", t:".001", o:vec![], s: None }  ,
					"Password Filter DLL" => Hnode{ d:"Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.", t:".002", o:vec![], s: None }  ,
					"Pluggable Authentication Modules" => Hnode{ d:"Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is pam_unix.so, which retrieves, sets, and verifies account authentication information in /etc/passwd and /etc/shadow.", t:".003", o:vec![], s: None }  ,
					"Network Device Authentication" => Hnode{ d:"Adversaries may use Patch System Image to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.", t:".004", o:vec![], s: None }  ,
					"Reversible Encryption" => Hnode{ d:"An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The AllowReversiblePasswordEncryption property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it.", t:".005", o:vec![], s: None }  ,
					"Multi-Factor Authentication" => Hnode{ d:"Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.", t:".006", o:vec![], s: None }  ,
					"Hybrid Identity" => Hnode{ d:"Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts.", t:".007", o:vec![], s: None }  
				)
			)} ,
				"Multi-Factor Authentication Interception" => 		 Hnode{ 
			d:"Adversaries may target multi-factor authentication (MFA) mechanisms, (I.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms.",
			t:"T1111",
			o:vec![],
			s: None } ,
				"Multi-Factor Authentication Request Generation" => 		 Hnode{ 
			d:"Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.",
			t:"T1621",
			o:vec![],
			s: None } ,
				"Network Sniffing" => 		 Hnode{ 
			d:"Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.",
			t:"T1040",
			o:vec![],
			s: None } ,
				"OS Credential Dumping" => 		 Hnode{ 
			d:"Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.",
			t:"T1003",
			o:vec!["LSASS Memory","Security Account Manager","NTDS","LSA Secrets","Cached Domain Credentials","DCSync","Proc Filesystem","/etc/passwd and /etc/shadow"],
			s: Some(
				hashmap!(
					"LSASS Memory" => Hnode{ d:"Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material.", t:".001", o:vec![], s: None }  ,
					"Security Account Manager" => Hnode{ d:"Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the net user command. Enumerating the SAM database requires SYSTEM level access.", t:".002", o:vec![], s: None }  ,
					"NTDS" => Hnode{ d:"Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in %SystemRoot%/NTDS/Ntds.dit of a domain controller.", t:".003", o:vec![], s: None }  ,
					"LSA Secrets" => Hnode{ d:"Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts. LSA secrets are stored in the registry at HKEY_LOCAL_MACHINE/SECURITY/Policy/Secrets. LSA secrets can also be dumped from memory.", t:".004", o:vec![], s: None }  ,
					"Cached Domain Credentials" => Hnode{ d:"Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.", t:".005", o:vec![], s: None }  ,
					"DCSync" => Hnode{ d:"Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.", t:".006", o:vec![], s: None }  ,
					"Proc Filesystem" => Hnode{ d:"Adversaries may gather credentials from information stored in the Proc filesystem or /proc. The Proc filesystem on Linux contains a great deal of information regarding the state of the running operating system. Processes running with root privileges can use this facility to scrape live memory of other running programs. If any of these programs store passwords in clear text or password hashes in memory, these values can then be harvested for either usage or brute force attacks, respectively.", t:".007", o:vec![], s: None }  ,
					"/etc/passwd and /etc/shadow" => Hnode{ d:"Adversaries may attempt to dump the contents of /etc/passwd and /etc/shadow to enable offline password cracking. Most modern Linux operating systems use a combination of /etc/passwd and /etc/shadow to store user account information including password hashes in /etc/shadow. By default, /etc/shadow is only readable by the root user.", t:".008", o:vec![], s: None }  
				)
			)} ,
				"Steal Application Access Token" => 		 Hnode{ 
			d:"Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.",
			t:"T1528",
			o:vec![],
			s: None } ,
				"Steal or Forge Authentication Certificates" => 		 Hnode{ 
			d:"Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For example, Azure AD device certificates and Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts.",
			t:"T1649",
			o:vec![],
			s: None } ,
				"Steal or Forge Kerberos Tickets" => 		 Hnode{ 
			d:"Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket. Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as QUOTErealmsQUOTE, there are three basic participants: client, service, and Key Distribution Center (KDC). Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting. Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.",
			t:"T1558",
			o:vec!["Golden Ticket","Silver Ticket","Kerberoasting","AS-REP Roasting"],
			s: Some(
				hashmap!(
					"Golden Ticket" => Hnode{ d:"Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory.", t:".001", o:vec![], s: None }  ,
					"Silver Ticket" => Hnode{ d:"Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets.", t:".002", o:vec![], s: None }  ,
					"Kerberoasting" => Hnode{ d:"Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force.", t:".003", o:vec![], s: None }  ,
					"AS-REP Roasting" => Hnode{ d:"Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by Password Cracking Kerberos messages.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Steal Web Session Cookie" => 		 Hnode{ 
			d:"An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.",
			t:"T1539",
			o:vec![],
			s: None } ,
				"Unsecured Credentials" => 		 Hnode{ 
			d:"Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Bash History), operating system or application-specific repositories (e.g. Credentials in Registry), or other specialized files/artifacts (e.g. Private Keys).",
			t:"T1552",
			o:vec!["Credentials In Files","Credentials in Registry","Bash History","Private Keys","Cloud Instance Metadata API","Group Policy Preferences","Container API"],
			s: Some(
				hashmap!(
					"Credentials In Files" => Hnode{ d:"Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.", t:".001", o:vec![], s: None }  ,
					"Credentials in Registry" => Hnode{ d:"Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.", t:".002", o:vec![], s: None }  ,
					"Bash History" => Hnode{ d:"Adversaries may search the bash command history on compromised systems for insecurely stored credentials. Bash keeps track of the commands users type on the command-line with the QUOTEhistoryQUOTE utility. Once a user logs out, the history is flushed to the user’s .bash_history file. For each user, this file resides at the same location: ~/.bash_history. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Adversaries can abuse this by looking through the file for potential credentials.", t:".003", o:vec![], s: None }  ,
					"Private Keys" => Hnode{ d:"Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures. Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc.", t:".004", o:vec![], s: None }  ,
					"Cloud Instance Metadata API" => Hnode{ d:"Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.", t:".005", o:vec![], s: None }  ,
					"Group Policy Preferences" => Hnode{ d:"Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts.", t:".006", o:vec![], s: None }  ,
					"Container API" => Hnode{ d:"Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components.", t:".007", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"Discovery" => 	Hnode{ 
		d:"safe_str(The adversary is trying to figure out your environment.Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what’s around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective.)",
		t:"None",
		o:vec!["Account Discovery","Application Window Discovery","Browser Bookmark Discovery","Cloud Infrastructure Discovery","Cloud Service Dashboard","Cloud Service Discovery","Cloud Storage Object Discovery","Container and Resource Discovery","Debugger Evasion","Domain Trust Discovery","File and Directory Discovery","Group Policy Discovery","Network Service Discovery","Network Share Discovery","Network Sniffing","Password Policy Discovery","Peripheral Device Discovery","Permission Groups Discovery","Process Discovery","Query Registry","Remote System Discovery","Software Discovery","System Information Discovery","System Location Discovery","System Network Configuration Discovery","System Network Connections Discovery","System Owner/User Discovery","System Service Discovery","System Time Discovery","Virtualization/Sandbox Evasion"],
		s: Some(
			hashmap!(
				"Account Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.",
			t:"T1087",
			o:vec!["Local Account","Domain Account","Email Account","Cloud Account"],
			s: Some(
				hashmap!(
					"Local Account" => Hnode{ d:"Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.", t:".001", o:vec![], s: None }  ,
					"Domain Account" => Hnode{ d:"Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior.", t:".002", o:vec![], s: None }  ,
					"Email Account" => Hnode{ d:"Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs).", t:".003", o:vec![], s: None }  ,
					"Cloud Account" => Hnode{ d:"Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Application Window Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.",
			t:"T1010",
			o:vec![],
			s: None } ,
				"Browser Bookmark Discovery" => 		 Hnode{ 
			d:"Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.",
			t:"T1217",
			o:vec![],
			s: None } ,
				"Cloud Infrastructure Discovery" => 		 Hnode{ 
			d:"An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.",
			t:"T1580",
			o:vec![],
			s: None } ,
				"Cloud Service Dashboard" => 		 Hnode{ 
			d:"An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.",
			t:"T1538",
			o:vec![],
			s: None } ,
				"Cloud Service Discovery" => 		 Hnode{ 
			d:"An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure AD, etc.",
			t:"T1526",
			o:vec![],
			s: None } ,
				"Cloud Storage Object Discovery" => 		 Hnode{ 
			d:"Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage. Similar to File and Directory Discovery on a local host, after identifying available storage services (i.e. Cloud Infrastructure Discovery) adversaries may access the contents/objects stored in cloud infrastructure.",
			t:"T1619",
			o:vec![],
			s: None } ,
				"Container and Resource Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.",
			t:"T1613",
			o:vec![],
			s: None } ,
				"Debugger Evasion" => 		 Hnode{ 
			d:"Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.",
			t:"T1622",
			o:vec![],
			s: None } ,
				"Domain Trust Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain. Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting. Domain trusts can be enumerated using the DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP. The Windows utility Nltest is known to be used by adversaries to enumerate domain trusts.",
			t:"T1482",
			o:vec![],
			s: None } ,
				"File and Directory Discovery" => 		 Hnode{ 
			d:"Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
			t:"T1083",
			o:vec![],
			s: None } ,
				"Group Policy Discovery" => 		 Hnode{ 
			d:"Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predicable network path //SYSVOL//Policies/.",
			t:"T1615",
			o:vec![],
			s: None } ,
				"Network Service Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system.",
			t:"T1046",
			o:vec![],
			s: None } ,
				"Network Share Discovery" => 		 Hnode{ 
			d:"Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.",
			t:"T1135",
			o:vec![],
			s: None } ,
				"Network Sniffing" => 		 Hnode{ 
			d:"Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.",
			t:"T1040",
			o:vec![],
			s: None } ,
				"Password Policy Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. This information may help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).",
			t:"T1201",
			o:vec![],
			s: None } ,
				"Peripheral Device Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.",
			t:"T1120",
			o:vec![],
			s: None } ,
				"Permission Groups Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.",
			t:"T1069",
			o:vec!["Local Groups","Domain Groups","Cloud Groups"],
			s: Some(
				hashmap!(
					"Local Groups" => Hnode{ d:"Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.", t:".001", o:vec![], s: None }  ,
					"Domain Groups" => Hnode{ d:"Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.", t:".002", o:vec![], s: None }  ,
					"Cloud Groups" => Hnode{ d:"Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Process Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from Process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
			t:"T1057",
			o:vec![],
			s: None } ,
				"Query Registry" => 		 Hnode{ 
			d:"Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
			t:"T1012",
			o:vec![],
			s: None } ,
				"Remote System Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as Ping or net view using Net.",
			t:"T1018",
			o:vec![],
			s: None } ,
				"Software Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
			t:"T1518",
			o:vec!["Security Software Discovery"],
			s: Some(
				hashmap!(
					"Security Software Discovery" => Hnode{ d:"Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"System Information Discovery" => 		 Hnode{ 
			d:"An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
			t:"T1082",
			o:vec![],
			s: None } ,
				"System Location Discovery" => 		 Hnode{ 
			d:"Adversaries may gather information in an attempt to calculate the geographical location of a victim host. Adversaries may use the information from System Location Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
			t:"T1614",
			o:vec!["System Language Discovery"],
			s: Some(
				hashmap!(
					"System Language Discovery" => Hnode{ d:"Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the target and/or attempts specific actions. This decision may be employed by malware developers and operators to reduce their risk of attracting the attention of specific law enforcement agencies or prosecution/scrutiny from other entities.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"System Network Configuration Discovery" => 		 Hnode{ 
			d:"Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.",
			t:"T1016",
			o:vec!["Internet Connection Discovery"],
			s: Some(
				hashmap!(
					"Internet Connection Discovery" => Hnode{ d:"Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using Ping, tracert, and GET requests to websites.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"System Network Connections Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.",
			t:"T1049",
			o:vec![],
			s: None } ,
				"System Owner/User Discovery" => 		 Hnode{ 
			d:"Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
			t:"T1033",
			o:vec![],
			s: None } ,
				"System Service Discovery" => 		 Hnode{ 
			d:"Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as sc query, tasklist /svc, systemctl --type=service, and net start.",
			t:"T1007",
			o:vec![],
			s: None } ,
				"System Time Discovery" => 		 Hnode{ 
			d:"An adversary may gather the system time and/or time zone from a local or remote system. The system time is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network.",
			t:"T1124",
			o:vec![],
			s: None } ,
				"Virtualization/Sandbox Evasion" => 		 Hnode{ 
			d:"Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.",
			t:"T1497",
			o:vec!["System Checks","User Activity Based Checks","Time Based Evasion"],
			s: Some(
				hashmap!(
					"System Checks" => Hnode{ d:"Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.", t:".001", o:vec![], s: None }  ,
					"User Activity Based Checks" => Hnode{ d:"Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.", t:".002", o:vec![], s: None }  ,
					"Time Based Evasion" => Hnode{ d:"Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time.", t:".003", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"LateralMovement" => 	Hnode{ 
		d:"safe_str(The adversary is trying to move through your environment.Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.)",
		t:"None",
		o:vec!["Exploitation of Remote Services","Internal Spearphishing","Lateral Tool Transfer","Remote Service Session Hijacking","Remote Services","Replication Through Removable Media","Software Deployment Tools","Taint Shared Content","Use Alternate Authentication Material"],
		s: Some(
			hashmap!(
				"Exploitation of Remote Services" => 		 Hnode{ 
			d:"Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.",
			t:"T1210",
			o:vec![],
			s: None } ,
				"Internal Spearphishing" => 		 Hnode{ 
			d:"Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or systems within the environment. Internal spearphishing is multi-staged campaign where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user. Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.",
			t:"T1534",
			o:vec![],
			s: None } ,
				"Lateral Tool Transfer" => 		 Hnode{ 
			d:"Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e. Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation. Adversaries may copy files between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB/Windows Admin Shares to connected network shares or with authenticated connections via Remote Desktop Protocol.",
			t:"T1570",
			o:vec![],
			s: None } ,
				"Remote Service Session Hijacking" => 		 Hnode{ 
			d:"Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.",
			t:"T1563",
			o:vec!["SSH Hijacking","RDP Hijacking"],
			s: Some(
				hashmap!(
					"SSH Hijacking" => Hnode{ d:"Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.", t:".001", o:vec![], s: None }  ,
					"RDP Hijacking" => Hnode{ d:"Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Remote Services" => 		 Hnode{ 
			d:"Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.",
			t:"T1021",
			o:vec!["Remote Desktop Protocol","SMB/Windows Admin Shares","Distributed Component Object Model","SSH","VNC","Windows Remote Management"],
			s: Some(
				hashmap!(
					"Remote Desktop Protocol" => Hnode{ d:"Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.", t:".001", o:vec![], s: None }  ,
					"SMB/Windows Admin Shares" => Hnode{ d:"Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.", t:".002", o:vec![], s: None }  ,
					"Distributed Component Object Model" => Hnode{ d:"Adversaries may use Valid Accounts to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user.", t:".003", o:vec![], s: None }  ,
					"SSH" => Hnode{ d:"Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user.", t:".004", o:vec![], s: None }  ,
					"VNC" => Hnode{ d:"Adversaries may use Valid Accounts to remotely control machines using Virtual Network Computing (VNC). VNC is a platform-independent desktop sharing system that uses the RFB (QUOTEremote framebufferQUOTE) protocol to enable users to remotely control another computer’s display by relaying the screen, mouse, and keyboard inputs over the network.", t:".005", o:vec![], s: None }  ,
					"Windows Remote Management" => Hnode{ d:"Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.", t:".006", o:vec![], s: None }  
				)
			)} ,
				"Replication Through Removable Media" => 		 Hnode{ 
			d:"Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.",
			t:"T1091",
			o:vec![],
			s: None } ,
				"Software Deployment Tools" => 		 Hnode{ 
			d:"Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, HBSS, Altiris, etc.).",
			t:"T1072",
			o:vec![],
			s: None } ,
				"Taint Shared Content" => 		 Hnode{ 
			d:"Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.",
			t:"T1080",
			o:vec![],
			s: None } ,
				"Use Alternate Authentication Material" => 		 Hnode{ 
			d:"Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.",
			t:"T1550",
			o:vec!["Application Access Token","Pass the Hash","Pass the Ticket","Web Session Cookie"],
			s: Some(
				hashmap!(
					"Application Access Token" => Hnode{ d:"Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials.", t:".001", o:vec![], s: None }  ,
					"Pass the Hash" => Hnode{ d:"Adversaries may QUOTEpass the hashQUOTE using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash.", t:".002", o:vec![], s: None }  ,
					"Pass the Ticket" => Hnode{ d:"Adversaries may QUOTEpass the ticketQUOTE using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.", t:".003", o:vec![], s: None }  ,
					"Web Session Cookie" => Hnode{ d:"Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.", t:".004", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"Collection" => 	Hnode{ 
		d:"safe_str(The adversary is trying to gather data of interest to their goal.Collection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the data. Common target sources include various drive types, browsers, audio, video, and email. Common collection methods include capturing screenshots and keyboard input.)",
		t:"None",
		o:vec!["Adversary-in-the-Middle","Archive Collected Data","Audio Capture","Automated Collection","Browser Session Hijacking","Clipboard Data","Data from Cloud Storage","Data from Configuration Repository","Data from Information Repositories","Data from Local System","Data from Network Shared Drive","Data from Removable Media","Data Staged","Email Collection","Input Capture","Screen Capture","Video Capture"],
		s: Some(
			hashmap!(
				"Adversary-in-the-Middle" => 		 Hnode{ 
			d:"Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation. By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.",
			t:"T1557",
			o:vec!["LLMNR/NBT-NS Poisoning and SMB Relay","ARP Cache Poisoning","DHCP Spoofing"],
			s: Some(
				hashmap!(
					"LLMNR/NBT-NS Poisoning and SMB Relay" => Hnode{ d:"By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.", t:".001", o:vec![], s: None }  ,
					"ARP Cache Poisoning" => Hnode{ d:"Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.", t:".002", o:vec![], s: None }  ,
					"DHCP Spoofing" => Hnode{ d:"Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Archive Collected Data" => 		 Hnode{ 
			d:"An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.",
			t:"T1560",
			o:vec!["Archive via Utility","Archive via Library","Archive via Custom Method"],
			s: Some(
				hashmap!(
					"Archive via Utility" => Hnode{ d:"Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.", t:".001", o:vec![], s: None }  ,
					"Archive via Library" => Hnode{ d:"An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including Python rarfile , libzip , and zlib . Most libraries include functionality to encrypt and/or compress data.", t:".002", o:vec![], s: None }  ,
					"Archive via Custom Method" => Hnode{ d:"An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Audio Capture" => 		 Hnode{ 
			d:"An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.",
			t:"T1123",
			o:vec![],
			s: None } ,
				"Automated Collection" => 		 Hnode{ 
			d:"Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a Command and Scripting Interpreter to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. In cloud-based environments, adversaries may also use cloud APIs, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data. This functionality could also be built into remote access tools.",
			t:"T1119",
			o:vec![],
			s: None } ,
				"Browser Session Hijacking" => 		 Hnode{ 
			d:"Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.",
			t:"T1185",
			o:vec![],
			s: None } ,
				"Clipboard Data" => 		 Hnode{ 
			d:"Adversaries may collect data stored in the clipboard from users copying information within or between applications.",
			t:"T1115",
			o:vec![],
			s: None } ,
				"Data from Cloud Storage" => 		 Hnode{ 
			d:"Adversaries may access data from improperly secured cloud storage.",
			t:"T1530",
			o:vec![],
			s: None } ,
				"Data from Configuration Repository" => 		 Hnode{ 
			d:"Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.",
			t:"T1602",
			o:vec!["SNMP (MIB Dump)","Network Device Configuration Dump"],
			s: Some(
				hashmap!(
					"SNMP (MIB Dump)" => Hnode{ d:"Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP).", t:".001", o:vec![], s: None }  ,
					"Network Device Configuration Dump" => Hnode{ d:"Adversaries may access network configuration files to collect sensitive data about the device and the network. The network configuration is a file containing parameters that determine the operation of the device. The device typically stores an in-memory copy of the configuration while operating, and a separate configuration on non-volatile storage to load after device reset. Adversaries can inspect the configuration files to reveal information about the target network and its layout, the network device and its software, or identifying legitimate accounts and credentials for later use.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Data from Information Repositories" => 		 Hnode{ 
			d:"Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information. Adversaries may also abuse external sharing features to share sensitive documents with recipients outside of the organization.",
			t:"T1213",
			o:vec!["Confluence","Sharepoint","Code Repositories"],
			s: Some(
				hashmap!(
					"Confluence" => Hnode{ d:"Adversaries may leverage Confluence repositories to mine valuable information. Often found in development environments alongside Atlassian JIRA, Confluence is generally used to store development-related documentation, however, in general may contain more diverse categories of useful information, such as:", t:".001", o:vec![], s: None }  ,
					"Sharepoint" => Hnode{ d:"Adversaries may leverage the SharePoint repository as a source to mine valuable information. SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems. For example, the following is a list of example information that may hold potential value to an adversary and may also be found on SharePoint:", t:".002", o:vec![], s: None }  ,
					"Code Repositories" => Hnode{ d:"Adversaries may leverage code repositories to collect valuable information. Code repositories are tools/services that store source code and automate software builds. They may be hosted internally or privately on third party sites such as Github, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Data from Local System" => 		 Hnode{ 
			d:"Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.",
			t:"T1005",
			o:vec![],
			s: None } ,
				"Data from Network Shared Drive" => 		 Hnode{ 
			d:"Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information.",
			t:"T1039",
			o:vec![],
			s: None } ,
				"Data from Removable Media" => 		 Hnode{ 
			d:"Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within cmd may be used to gather information.",
			t:"T1025",
			o:vec![],
			s: None } ,
				"Data Staged" => 		 Hnode{ 
			d:"Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.",
			t:"T1074",
			o:vec!["Local Data Staging","Remote Data Staging"],
			s: Some(
				hashmap!(
					"Local Data Staging" => Hnode{ d:"Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.", t:".001", o:vec![], s: None }  ,
					"Remote Data Staging" => Hnode{ d:"Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Email Collection" => 		 Hnode{ 
			d:"Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients.",
			t:"T1114",
			o:vec!["Local Email Collection","Remote Email Collection","Email Forwarding Rule"],
			s: Some(
				hashmap!(
					"Local Email Collection" => Hnode{ d:"Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files.", t:".001", o:vec![], s: None }  ,
					"Remote Email Collection" => Hnode{ d:"Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services, Office 365, or Google Workspace to access email using credentials or access tokens. Tools such as MailSniper can be used to automate searches for specific keywords.", t:".002", o:vec![], s: None }  ,
					"Email Forwarding Rule" => Hnode{ d:"Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email-forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations. Furthermore, email forwarding rules can allow adversaries to maintain persistent access to victim's emails even after compromised credentials are reset by administrators. Most email clients allow users to create inbox rules for various email functions, including forwarding to a different recipient. These rules may be created through a local email application, a web interface, or by command-line interface. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Input Capture" => 		 Hnode{ 
			d:"Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. Credential API Hooking) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. Web Portal Capture).",
			t:"T1056",
			o:vec!["Keylogging","GUI Input Capture","Web Portal Capture","Credential API Hooking"],
			s: Some(
				hashmap!(
					"Keylogging" => Hnode{ d:"Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when OS Credential Dumping efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured.", t:".001", o:vec![], s: None }  ,
					"GUI Input Capture" => Hnode{ d:"Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: Bypass User Account Control).", t:".002", o:vec![], s: None }  ,
					"Web Portal Capture" => Hnode{ d:"Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.", t:".003", o:vec![], s: None }  ,
					"Credential API Hooking" => Hnode{ d:"Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials. Unlike Keylogging, this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Screen Capture" => 		 Hnode{ 
			d:"Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as CopyFromScreen, xwd, or screencapture.",
			t:"T1113",
			o:vec![],
			s: None } ,
				"Video Capture" => 		 Hnode{ 
			d:"An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.",
			t:"T1125",
			o:vec![],
			s: None } 
			)
		)} ,
	"CommandandControl" => 	Hnode{ 
		d:"safe_str(The adversary is trying to communicate with compromised systems to control them.Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim’s network structure and defenses.)",
		t:"None",
		o:vec!["Application Layer Protocol","Communication Through Removable Media","Data Encoding","Data Obfuscation","Dynamic Resolution","Encrypted Channel","Fallback Channels","Ingress Tool Transfer","Multi-Stage Channels","Non-Application Layer Protocol","Non-Standard Port","Protocol Tunneling","Proxy","Remote Access Software","Traffic Signaling","Web Service"],
		s: Some(
			hashmap!(
				"Application Layer Protocol" => 		 Hnode{ 
			d:"Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
			t:"T1071",
			o:vec!["Web Protocols","File Transfer Protocols","Mail Protocols","DNS"],
			s: Some(
				hashmap!(
					"Web Protocols" => Hnode{ d:"Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.", t:".001", o:vec![], s: None }  ,
					"File Transfer Protocols" => Hnode{ d:"Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.", t:".002", o:vec![], s: None }  ,
					"Mail Protocols" => Hnode{ d:"Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.", t:".003", o:vec![], s: None }  ,
					"DNS" => Hnode{ d:"Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Communication Through Removable Media" => 		 Hnode{ 
			d:"Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.",
			t:"T1092",
			o:vec![],
			s: None } ,
				"Data Encoding" => 		 Hnode{ 
			d:"Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems. Some data encoding systems may also result in data compression, such as gzip.",
			t:"T1132",
			o:vec!["Standard Encoding","Non-Standard Encoding"],
			s: Some(
				hashmap!(
					"Standard Encoding" => Hnode{ d:"Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME. Some data encoding systems may also result in data compression, such as gzip.", t:".001", o:vec![], s: None }  ,
					"Non-Standard Encoding" => Hnode{ d:"Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a non-standard data encoding system that diverges from existing protocol specifications. Non-standard data encoding schemes may be based on or related to standard data encoding schemes, such as a modified Base64 encoding for the message body of an HTTP request.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Data Obfuscation" => 		 Hnode{ 
			d:"Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.",
			t:"T1001",
			o:vec!["Junk Data","Steganography","Protocol Impersonation"],
			s: Some(
				hashmap!(
					"Junk Data" => Hnode{ d:"Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic. Examples may include appending/prepending data with junk characters or writing junk characters between significant characters.", t:".001", o:vec![], s: None }  ,
					"Steganography" => Hnode{ d:"Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult. Steganographic techniques can be used to hide data in digital messages that are transferred between systems. This hidden information can be used for command and control of compromised systems. In some cases, the passing of files embedded using steganography, such as image or document files, can be used for command and control.", t:".002", o:vec![], s: None }  ,
					"Protocol Impersonation" => Hnode{ d:"Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control traffic blend in with legitimate network traffic.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Dynamic Resolution" => 		 Hnode{ 
			d:"Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.",
			t:"T1568",
			o:vec!["Fast Flux DNS","Domain Generation Algorithms","DNS Calculation"],
			s: Some(
				hashmap!(
					"Fast Flux DNS" => Hnode{ d:"Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution. This technique uses a fully qualified domain name, with multiple IP addresses assigned to it which are swapped with high frequency, using a combination of round robin IP addressing and short Time-To-Live (TTL) for a DNS resource record.", t:".001", o:vec![], s: None }  ,
					"Domain Generation Algorithms" => Hnode{ d:"Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains. This has the advantage of making it much harder for defenders to block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions.", t:".002", o:vec![], s: None }  ,
					"DNS Calculation" => Hnode{ d:"Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address. A IP and/or port number calculation can be used to bypass egress filtering on a C2 channel.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Encrypted Channel" => 		 Hnode{ 
			d:"Adversaries may employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.",
			t:"T1573",
			o:vec!["Symmetric Cryptography","Asymmetric Cryptography"],
			s: Some(
				hashmap!(
					"Symmetric Cryptography" => Hnode{ d:"Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4.", t:".001", o:vec![], s: None }  ,
					"Asymmetric Cryptography" => Hnode{ d:"Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Asymmetric cryptography, also known as public key cryptography, uses a keypair per party: one public that can be freely distributed, and one private. Due to how the keys are generated, the sender encrypts data with the receiver’s public key and the receiver decrypts the data with their private key. This ensures that only the intended recipient can read the encrypted data. Common public key encryption algorithms include RSA and ElGamal.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Fallback Channels" => 		 Hnode{ 
			d:"Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.",
			t:"T1008",
			o:vec![],
			s: None } ,
				"Ingress Tool Transfer" => 		 Hnode{ 
			d:"Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp. Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. Lateral Tool Transfer).",
			t:"T1105",
			o:vec![],
			s: None } ,
				"Multi-Stage Channels" => 		 Hnode{ 
			d:"Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.",
			t:"T1104",
			o:vec![],
			s: None } ,
				"Non-Application Layer Protocol" => 		 Hnode{ 
			d:"Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).",
			t:"T1095",
			o:vec![],
			s: None } ,
				"Non-Standard Port" => 		 Hnode{ 
			d:"Adversaries may communicate using a protocol and port paring that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.",
			t:"T1571",
			o:vec![],
			s: None } ,
				"Protocol Tunneling" => 		 Hnode{ 
			d:"Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.",
			t:"T1572",
			o:vec![],
			s: None } ,
				"Proxy" => 		 Hnode{ 
			d:"Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.",
			t:"T1090",
			o:vec!["Internal Proxy","External Proxy","Multi-hop Proxy","Domain Fronting"],
			s: Some(
				hashmap!(
					"Internal Proxy" => Hnode{ d:"Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment.", t:".001", o:vec![], s: None }  ,
					"External Proxy" => Hnode{ d:"Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap. Adversaries use these types of proxies to manage command and control communications, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths to avoid suspicion.", t:".002", o:vec![], s: None }  ,
					"Multi-hop Proxy" => Hnode{ d:"To disguise the source of malicious traffic, adversaries may chain together multiple proxies. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source. A particular variant of this behavior is to use onion routing networks, such as the publicly available TOR network.", t:".003", o:vec![], s: None }  ,
					"Domain Fronting" => Hnode{ d:"Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. Domain fronting involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, QUOTEdomainlessQUOTE fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored).", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Remote Access Software" => 		 Hnode{ 
			d:"An adversary may use legitimate desktop support and remote access software, such as Team Viewer, AnyDesk, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks. These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment. Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries.",
			t:"T1219",
			o:vec![],
			s: None } ,
				"Traffic Signaling" => 		 Hnode{ 
			d:"Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control. Traffic signaling involves the use of a magic value or sequence that must be sent to a system to trigger a special response, such as opening a closed port or executing a malicious task. This may take the form of sending a series of packets with certain characteristics before a port will be opened that the adversary can use for command and control. Usually this series of packets consists of attempted connections to a predefined sequence of closed ports (i.e. Port Knocking), but can involve unusual flags, specific strings, or other unique characteristics. After the sequence is completed, opening a port may be accomplished by the host-based firewall, but could also be implemented by custom software.",
			t:"T1205",
			o:vec!["Port Knocking","Socket Filters"],
			s: Some(
				hashmap!(
					"Port Knocking" => Hnode{ d:"Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.", t:".001", o:vec![], s: None }  ,
					"Socket Filters" => Hnode{ d:"Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the libpcap library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Web Service" => 		 Hnode{ 
			d:"Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.",
			t:"T1102",
			o:vec!["Dead Drop Resolver","Bidirectional Communication","One-Way Communication"],
			s: Some(
				hashmap!(
					"Dead Drop Resolver" => Hnode{ d:"Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers.", t:".001", o:vec![], s: None }  ,
					"Bidirectional Communication" => Hnode{ d:"Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet.", t:".002", o:vec![], s: None }  ,
					"One-Way Communication" => Hnode{ d:"Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems may opt to send the output from those commands back over a different C2 channel, including to another distinct Web service. Alternatively, compromised systems may return no output at all in cases where adversaries want to send instructions to systems and do not want a response.", t:".003", o:vec![], s: None }  
				)
			)} 
			)
		)} ,
	"Exfiltration" => 	Hnode{ 
		d:"safe_str(The adversary is trying to steal data.Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.)",
		t:"None",
		o:vec!["Automated Exfiltration","Data Transfer Size Limits","Exfiltration Over Alternative Protocol","Exfiltration Over C2 Channel","Exfiltration Over Other Network Medium","Exfiltration Over Physical Medium","Exfiltration Over Web Service","Scheduled Transfer","Transfer Data to Cloud Account"],
		s: Some(
			hashmap!(
				"Automated Exfiltration" => 		 Hnode{ 
			d:"Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.",
			t:"T1020",
			o:vec!["Traffic Duplication"],
			s: Some(
				hashmap!(
					"Traffic Duplication" => Hnode{ d:"Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised network infrastructure. Traffic mirroring is a native feature for some network devices and used for network analysis and may be configured to duplicate traffic and forward to one or more destinations for analysis by a network analyzer or other monitoring device.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"Data Transfer Size Limits" => 		 Hnode{ 
			d:"An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.",
			t:"T1030",
			o:vec![],
			s: None } ,
				"Exfiltration Over Alternative Protocol" => 		 Hnode{ 
			d:"Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.",
			t:"T1048",
			o:vec!["Exfiltration Over Symmetric Encrypted Non-C2 Protocol","Exfiltration Over Asymmetric Encrypted Non-C2 Protocol","Exfiltration Over Unencrypted Non-C2 Protocol"],
			s: Some(
				hashmap!(
					"Exfiltration Over Symmetric Encrypted Non-C2 Protocol" => Hnode{ d:"Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.", t:".001", o:vec![], s: None }  ,
					"Exfiltration Over Asymmetric Encrypted Non-C2 Protocol" => Hnode{ d:"Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.", t:".002", o:vec![], s: None }  ,
					"Exfiltration Over Unencrypted Non-C2 Protocol" => Hnode{ d:"Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Exfiltration Over C2 Channel" => 		 Hnode{ 
			d:"Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.",
			t:"T1041",
			o:vec![],
			s: None } ,
				"Exfiltration Over Other Network Medium" => 		 Hnode{ 
			d:"Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.",
			t:"T1011",
			o:vec!["Exfiltration Over Bluetooth"],
			s: Some(
				hashmap!(
					"Exfiltration Over Bluetooth" => Hnode{ d:"Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"Exfiltration Over Physical Medium" => 		 Hnode{ 
			d:"Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.",
			t:"T1052",
			o:vec!["Exfiltration over USB"],
			s: Some(
				hashmap!(
					"Exfiltration over USB" => Hnode{ d:"Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.", t:".001", o:vec![], s: None }  
				)
			)} ,
				"Exfiltration Over Web Service" => 		 Hnode{ 
			d:"Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.",
			t:"T1567",
			o:vec!["Exfiltration to Code Repository","Exfiltration to Cloud Storage"],
			s: Some(
				hashmap!(
					"Exfiltration to Code Repository" => Hnode{ d:"Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection.", t:".001", o:vec![], s: None }  ,
					"Exfiltration to Cloud Storage" => Hnode{ d:"Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Scheduled Transfer" => 		 Hnode{ 
			d:"Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.",
			t:"T1029",
			o:vec![],
			s: None } ,
				"Transfer Data to Cloud Account" => 		 Hnode{ 
			d:"Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control on the same service to avoid typical file transfers/downloads and network-based exfiltration detection.",
			t:"T1537",
			o:vec![],
			s: None } 
			)
		)} ,
	"Impact" => 	Hnode{ 
		d:"safe_str(The adversary is trying to manipulate, interrupt, or destroy your systems and data.Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Techniques used for impact can include destroying or tampering with data. In some cases, business processes can look fine, but may have been altered to benefit the adversaries’ goals. These techniques might be used by adversaries to follow through on their end goal or to provide cover for a confidentiality breach.)",
		t:"None",
		o:vec!["Account Access Removal","Data Destruction","Data Encrypted for Impact","Data Manipulation","Defacement","Disk Wipe","Endpoint Denial of Service","Firmware Corruption","Inhibit System Recovery","Network Denial of Service","Resource Hijacking","Service Stop","System Shutdown/Reboot"],
		s: Some(
			hashmap!(
				"Account Access Removal" => 		 Hnode{ 
			d:"Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. Adversaries may also subsequently log off and/or perform a System Shutdown/Reboot to set malicious changes into place.",
			t:"T1531",
			o:vec![],
			s: None } ,
				"Data Destruction" => 		 Hnode{ 
			d:"Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives. Common operating system file deletion commands such as del and rm often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from Disk Content Wipe and Disk Structure Wipe because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.",
			t:"T1485",
			o:vec![],
			s: None } ,
				"Data Encrypted for Impact" => 		 Hnode{ 
			d:"Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.",
			t:"T1486",
			o:vec![],
			s: None } ,
				"Data Manipulation" => 		 Hnode{ 
			d:"Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.",
			t:"T1565",
			o:vec!["Stored Data Manipulation","Transmitted Data Manipulation","Runtime Data Manipulation"],
			s: Some(
				hashmap!(
					"Stored Data Manipulation" => Hnode{ d:"Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making.", t:".001", o:vec![], s: None }  ,
					"Transmitted Data Manipulation" => Hnode{ d:"Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data. By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making.", t:".002", o:vec![], s: None }  ,
					"Runtime Data Manipulation" => Hnode{ d:"Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data. By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making.", t:".003", o:vec![], s: None }  
				)
			)} ,
				"Defacement" => 		 Hnode{ 
			d:"Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for Defacement include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages.",
			t:"T1491",
			o:vec!["Internal Defacement","External Defacement"],
			s: Some(
				hashmap!(
					"Internal Defacement" => Hnode{ d:"An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper. Disturbing or offensive images may be used as a part of Internal Defacement in order to cause user discomfort, or to pressure compliance with accompanying messages. Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished.", t:".001", o:vec![], s: None }  ,
					"External Defacement" => Hnode{ d:"An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. External Defacement may ultimately cause users to distrust the systems and to question/discredit the system’s integrity. Externally-facing websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda. External Defacement may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government. Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as Drive-by Compromise.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Disk Wipe" => 		 Hnode{ 
			d:"Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.",
			t:"T1561",
			o:vec!["Disk Content Wipe","Disk Structure Wipe"],
			s: Some(
				hashmap!(
					"Disk Content Wipe" => Hnode{ d:"Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources.", t:".001", o:vec![], s: None }  ,
					"Disk Structure Wipe" => Hnode{ d:"Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Endpoint Denial of Service" => 		 Hnode{ 
			d:"Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition. Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.",
			t:"T1499",
			o:vec!["OS Exhaustion Flood","Service Exhaustion Flood","Application Exhaustion Flood","Application or System Exploitation"],
			s: Some(
				hashmap!(
					"OS Exhaustion Flood" => Hnode{ d:"Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity. These attacks do not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes.", t:".001", o:vec![], s: None }  ,
					"Service Exhaustion Flood" => Hnode{ d:"Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well. Web server software can be attacked through a variety of means, some of which apply generally while others are specific to the software being used to provide the service.", t:".002", o:vec![], s: None }  ,
					"Application Exhaustion Flood" => Hnode{ d:"Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself.", t:".003", o:vec![], s: None }  ,
					"Application or System Exploitation" => Hnode{ d:"Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition.", t:".004", o:vec![], s: None }  
				)
			)} ,
				"Firmware Corruption" => 		 Hnode{ 
			d:"Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system. Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards.",
			t:"T1495",
			o:vec![],
			s: None } ,
				"Inhibit System Recovery" => 		 Hnode{ 
			d:"Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options.",
			t:"T1490",
			o:vec![],
			s: None } ,
				"Network Denial of Service" => 		 Hnode{ 
			d:"Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion.",
			t:"T1498",
			o:vec!["Direct Network Flood","Reflection Amplification"],
			s: Some(
				hashmap!(
					"Direct Network Flood" => Hnode{ d:"Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. Direct Network Floods are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well.", t:".001", o:vec![], s: None }  ,
					"Reflection Amplification" => Hnode{ d:"Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector. An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim. Similar to Direct Network Floods, more than one system may be used to conduct the attack, or a botnet may be used. Likewise, one or more reflectors may be used to focus traffic on the target. This Network DoS attack may also reduce the availability and functionality of the targeted system(s) and network.", t:".002", o:vec![], s: None }  
				)
			)} ,
				"Resource Hijacking" => 		 Hnode{ 
			d:"Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems, which may impact system and/or hosted service availability.",
			t:"T1496",
			o:vec![],
			s: None } ,
				"Service Stop" => 		 Hnode{ 
			d:"Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.",
			t:"T1489",
			o:vec![],
			s: None } ,
				"System Shutdown/Reboot" => 		 Hnode{ 
			d:"Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via Network Device CLI (e.g. reload). Shutting down or rebooting systems may disrupt access to computer resources for legitimate users.",
			t:"T1529",
			o:vec![],
			s: None } 
			)
		)} 
	))}

}

fn main() -> (){
    let MITRE12 = mitre12();
    println!( "{:?}", MITRE12 ); 
}


