//Omar Mansour



const FNET_ODS = 'F5-Silverline';
const context = 'F5-Silverline';
const path='/api/v1/ip_lists/denylist/ip_objects';
const enableResponseEvent = true;

//triggered on an HTTP request
if(event=="HTTP_REQUEST"||event=="HTTP_RESPONSE"){
    
    var dip=Flow.server.ipaddr;
    if(dip.toString()=='HTTP server IP'){
        var sip=Flow.client.ipaddr;
		
    //looks for the origin IP (x-forward-for) as incoming requests will have F5-silverline IPs as source	
    var originalIP=HTTP.origin;
    debug("sip="+ sip +" dip="+ dip+" original ip="+ originalIP);
    debug(ThreatIntel.hasIP(originalIP));
if(ThreatIntel.hasIP(originalIP)==1){

var req= {
        "data": {
            "list_target": "proxy",
            "id": "e12f16ed-9bf2-46bf-b5ce-7dc3827adcd3",
            "type": "ip_objects",
        "attributes": {
            "mask": "32",
            "ip": "",
            "duration": 0
},
"meta": {
"note": "string",
"tags": [ ]
}
}
}

let finalReq=req;
finalReq["data"]["attributes"]["ip"]=originalIP.toString();

let sendpayload = {
            'path': path,
            'headers': {
                "Content-Type": "application/json",
                "X-Authorization-Token": "API-Token",
                'context': context
            },
            'payload': JSON.stringify(finalReq),
            'enableResponseEvent': enableResponseEvent
        };

debug("Create  Payload is " + JSON.stringify(finalReq, null, 1));
Remote.HTTP(FNET_ODS).request('POST', sendpayload);
    }
    

    }
}
 if (event === 'REMOTE_RESPONSE') {
    if (!Remote.response) {
        return;
    }
    var responseObject = Remote.response;
    var buffer = responseObject.body;
    var headers = responseObject.headers;   
    log ('responseObject = '+responseObject.statusCode+', '+JSON.stringify(headers,null,'\t'));

 }