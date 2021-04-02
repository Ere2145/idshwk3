global ipTable :table[addr] of set[string] = table();

event http_all_headers (c: connection, is_orig: bool, hlist: mime_header_list){
	local ip :addr = c$id$orig_h;
	for(key in hlist){
		if(hlist[key]$name=="USER-AGENT"){
            local usragt:string=to_lower(hlist[key]$value);
	    	if (ip in ipTable){
		    	if(usragt !in ipTable[ip]){
			    	add (ipTable[ip])[usragt];
		    	}
			}
			else{
	        	ipTable[ip] = set(usragt);
			}
		}
	}
}

event zeek_done()
{
	for(key in ipTable)
	{
		if(|ipTable[key]| >= 3)
		{
			print(fmt("%s is a proxy",key));
		}
	}
}
