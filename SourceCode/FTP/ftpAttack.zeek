##! FTP brute-forcing detector, triggering when too many rejected usernames or
##! failed passwords have occurred from a single address.

@load base/protocols/ftp
@load base/frameworks/sumstats
@load base/utils/exec.zeek
@load base/utils/time

module FTP;
module Exec;

export {
	redef enum Notice::Type += {
		## Indicates a host bruteforcing FTP logins by watching for too
		## many rejected usernames or failed passwords.
		Bruteforcing
	};

	## How many rejected usernames or passwords are required before being
	## considered to be bruteforcing.
	const bruteforce_threshold: double = 5 &redef;

	## The time period in which the threshold needs to be crossed before
	## being reset.
	const bruteforce_measurement_interval = 30 mins &redef;
}


event zeek_init()
	{
	local r1: SumStats::Reducer = [$stream="ftp.failed_auth", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(bruteforce_threshold+2)];
	SumStats::create([$name="ftp-detect-bruteforcing",
	                  $epoch=bruteforce_measurement_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["ftp.failed_auth"]$num+0.0;
	                  	},
	                  $threshold=bruteforce_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["ftp.failed_auth"];
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local plural = r$unique>1 ? "s" : "";
	                  	local message = fmt("%s had %d failed logins on %d FTP server%s in %s", key$host, r$num, r$unique, plural, dur);
	                  	NOTICE([$note=Bruteforcing,
	                  	        $src=key$host,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	        print fmt("%s appears to be guessing FTP passwords (seen in %d connections).", key$host, r$num);
	                  	        
	                  	        local ip : string;
					ip =fmt("%s", key$host);
					
					local t : string;
					local firstPart = "iptables -I INPUT -s ";
					local lastPart = " -j DROP";
					t = string_cat(firstPart,ip,lastPart);
					#print t;
					local cmd=Exec::Command($cmd=t);
					#local res = Exec::run(cmd);
					when(local res = Exec::run(cmd))
					{
					    print "IP Dropped";
					}
					
					t= "./action.sh";
					cmd=Exec::Command($cmd=t);
					when(local res2 = Exec::run(cmd))
					{
					    print "Notified to Admin";
					}
					
					firstPart = "sleep 30m && iptables -D INPUT -s ";
					lastPart = " -j DROP";
					t = string_cat(firstPart,ip,lastPart);
					print "IP address blacklisted for 30 mins";
					cmd=Exec::Command($cmd=t);
					when(local res3 = Exec::run(cmd))
					{
					    print "IP address removed from blacklist";
					}
	                  	}]);
	                  	
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	local cmd = c$ftp$cmdarg$cmd;
	if ( cmd == "USER" || cmd == "PASS" )
		{
		if ( FTP::parse_ftp_reply_code(code)$x == 5 )
			SumStats::observe("ftp.failed_auth", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
		}
	}
