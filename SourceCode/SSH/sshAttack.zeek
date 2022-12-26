##! Detect hosts which are doing password guessing attacks and/or password
##! bruteforcing over SSH.

@load base/protocols/ssh
@load base/frameworks/sumstats
@load base/frameworks/notice
@load base/frameworks/intel
@load base/utils/exec.zeek


module Exec;
module SSH;

redef exit_only_after_terminate=T;

export {
	redef enum Notice::Type += {
		## Indicates that a host has been identified as crossing the
		## :zeek:id:`SSH::password_guesses_limit` threshold with
		## failed logins.
		Password_Guessing,
	};

	redef enum Intel::Where += {
		## An indicator of the login for the intel framework.
		SSH::SUCCESSFUL_LOGIN,
	};

	## The number of failed SSH connections before a host is designated as
	## guessing passwords.
	const password_guesses_limit: double = 5 &redef;

	## The amount of time to remember presumed non-successful logins to
	## build a model of a password guesser.
	const guessing_timeout = 30 mins &redef;

	## This value can be used to exclude hosts or entire networks from being
	## tracked as potential "guessers". The index represents
	## client subnets and the yield value represents server subnets.
	const ignore_guessers: table[subnet] of subnet &redef;
}

event zeek_init()
	{
	local r1: SumStats::Reducer = [$stream="ssh.login.failure", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=5];
	SumStats::create([$name="detect-ssh-bruteforcing",
	                  $epoch=guessing_timeout,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["ssh.login.failure"]$sum;
	                  	},
	                  $threshold=password_guesses_limit,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["ssh.login.failure"];
	                  	local sub_msg = fmt("Sampled servers: ");
	                  	local samples = r$samples;
	                  	for ( i in samples )
	                  		{
	                  		if ( samples[i]?$str )
	                  			sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
	                  		}
	                  	# Generate the notice.
	                  	NOTICE([$note=Password_Guessing,
	                  	        $msg=fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num),
	                  	        $sub=sub_msg,
	                  	        $src=key$host,
	                  	        $identifier=cat(key$host)]);
	                  	    	print fmt("%s appears to be guessing SSH passwords (seen in %d connections).", key$host, r$num);
					
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

event ssh_auth_successful(c: connection, auth_method_none: bool)
	{
	local id = c$id;

	Intel::seen([$host=id$orig_h,
	             $conn=c,
	             $where=SSH::SUCCESSFUL_LOGIN]);
	}

event ssh_auth_failed(c: connection)
	{
	local id = c$id;

	# Add data to the FAILED_LOGIN metric unless this connection should
	# be ignored.
	if ( ! (id$orig_h in ignore_guessers &&
	        id$resp_h in ignore_guessers[id$orig_h]) )
		SumStats::observe("ssh.login.failure", [$host=id$orig_h], [$str=cat(id$resp_h)]);
	}

event NetControl::init(){
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin,0);
}

hook Notice::policy(n: Notice::Info){
	if(n$note == SSH::Password_Guessing){
		NetControl::drop_address(n$src,30 mins);
		add n$actions[Notice::ACTION_DROP];
    		add n$actions[Notice::ACTION_LOG];
    		print "Dropped";
	}
}

