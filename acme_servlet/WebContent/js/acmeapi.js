function initapi(){
	
	// disable the button while processing
	
	var btnprocess = document.getElementById("btnprocess");
	
	btnprocess.disabled = true;
	
	document.getElementById("messages").innerHTML = "";
	
	//save the config in case something changed 
	
	saveconfig();
	
	// grab all the form values
	
	var challenge_type = document.getElementById("challenge_type").value;
	var timeout = document.getElementById("timeout").value;	
	var request_type = document.getElementById("request_type").value;
	var domain = document.getElementById("domain").value;
	var account_key = document.getElementById("account_key").value;
	var certificate_path = document.getElementById("certificate_path").value;
	var well_known_dir = document.getElementById("well_known_dir").value;	
	var csr = document.getElementById("csr").value;
	var wrk_folder = document.getElementById("wrk_folder").value;
	
	var action = "init";
	

    var data = encodeURI("?challenge_type="+challenge_type+"&timeout=" + timeout +"&action=" +action + "&request_type="+request_type+"&domain="+domain+"&account_key="+account_key+"&certificate_path="+certificate_path+"&well_known_dir="+well_known_dir+"&csr="+csr+"&wrk_folder="+wrk_folder);

    var url = "/acme_dcm/process/api"+data;

    startmsg();

    makeRequest('GET', url)
    .then(function (datums) {
      console.log(datums);
    })
    .catch(function (err) {
      console.error('Augh, there was an error!', err.statusText);
    });
    

	
   
}

function startmsg() {
		
		    document.getElementById("messages").innerHTML = "";

            var sse = new EventSource("/acme_dcm/process/getmessages");
			var btnprocess = document.getElementById("btnprocess");
	
           sse.onmessage = function (event) {
	
            document.getElementById("messages").innerHTML = event.data;
	
			if(event.data.indexOf("Close") > -1)
				sse.close();
				btnprocess.disabled = false;
            }

}

// Wrapped in a Promise so we can handle Async nature of call

function makeRequest (method, url) {
	  return new Promise(function (resolve, reject) {
	    var xhr = new XMLHttpRequest();

	    xhr.onload = function () {
	      if (this.status >= 200 && this.status < 300) {
	        resolve(xhr.response);
	      } else {
	        reject({
	          status: this.status,
	          statusText: xhr.statusText
	        });
	      }
	    };
	    xhr.onerror = function () {
	      reject({
	        status: this.status,
	        statusText: xhr.statusText
	      });
	    };
	    xhr.open(method, url);
	    xhr.send();
	  });
	}



function init(){
	
	// Load the list of json files that have acme configs
	var url = "/acme_dcm/process/configlist";
    let data = "";

    makeRequest('GET', url)
    .then(function (datums) {
	
		document.getElementById("challenge_type").value = "";
		document.getElementById("timeout").value = "";
		document.getElementById("request_type").value="";
		document.getElementById("domain").value = "";
	 	document.getElementById("account_key").value = "";
		document.getElementById("certificate_path").value = "";
		document.getElementById("well_known_dir").value = "";	
		document.getElementById("csr").value = "";
		document.getElementById("wrk_folder").value = "";
		document.getElementById("new_name").value = "";
		
		let settings = document.getElementById('saved_settings');
		let challenge = document.getElementById('challenge_type');
		let well_known_dir = document.getElementById('wellknown');
		let dnsrec = document.getElementById('dnsrec');
				
		challenge.onchange = function(){

			document.getElementById("messages").innerHTML = "";
			well_known_dir.style.visibility = "visible";
			dnsrec.style.visibility = "visible";	
					
			if(this.value == "dns")
				// clear the value and hide it
				{
					well_known_dir.style.visibility = "hidden";
					well_known_dir.value = "";		
				}

				
			if(this.value == "http")
				{
					dnsrec.style.visibility = "hidden";
					dnsrec.value = "";
				}
					
		}
		
		
		settings.length = 0;
		
		let defaultOption = document.createElement('option');		
			
	    defaultOption.text = "*NEW";
		defaultOption.value = "new";
		
		settings.add(defaultOption);
		
	    data = JSON.parse(datums);

		let array = data.configs;
	
	    let option;
	
	    for (let i = 0; i < array.length; i++) {

		  option = document.createElement('option');

	      option.text = array[i].configname;
	      option.value = array[i].configpath;

		  settings.add(option);
	    }

		
    })
    .catch(function (err) {
      console.error('Augh, there was an error!', err.statusText);
    });


}

function saveconfig(){
	
	// grab all the form values
	
	var challenge_type = document.getElementById("challenge_type").value;
	var timeout = document.getElementById("timeout").value;
	var request_type = document.getElementById("request_type").value;
	var domain = document.getElementById("domain").value;
	var account_key = document.getElementById("account_key").value;
	var certificate_path = document.getElementById("certificate_path").value;
	var well_known_dir = document.getElementById("well_known_dir").value;	
	var csr = document.getElementById("csr").value;
	var wrk_folder = document.getElementById("wrk_folder").value;
	var e = document.getElementById("saved_settings");
	var new_name = document.getElementById("new_name");
	var action = "init";
	
	var settings_text = e.options[e.selectedIndex].text;
	
	if(settings_text == '*NEW' && new_name.value.length>0) // use the 
		settings_text = document.getElementById("new_name").value;

    var data = encodeURI("?challenge_type="+challenge_type + "&timeout="+timeout +"&action=" +action
        + "&request_type="+request_type+"&domain="+domain+"&account_key="+account_key
        +"&certificate_path="+certificate_path+"&well_known_dir="+well_known_dir
        +"&csr="+csr+"&wrk_folder="+wrk_folder+"&settings_text="+settings_text);

 
    var url = "/acme_dcm/process/saveconfig"+data;

    makeRequest('GET', url)
    .then(function (datums) {
      console.log(datums);
    })
    .catch(function (err) {
      console.error('Augh, there was an error!', err.statusText);
    });
    
	let config_name = document.getElementById("config_name");
	let save_config = document.getElementById("save_config");
	
		save_config.style.visibility = "hidden";
		config_name.style.visibility = "hidden";
}

function loadConfig(){
	
	document.getElementById("messages").value = "";
	let msgcontent = document.getElementById("messages");
	

	let saved_settings = document.getElementById("saved_settings");
	let configpath = encodeURI(saved_settings.value);
	let config_name = document.getElementById("config_name");
	let save_config = document.getElementById("save_config");	
	let well_known_dir = document.getElementById('wellknown');
	let challenge = document.getElementById('challenge_type');
			
	if(configpath === 'new')
	{
		config_name.style.display = 'block';
		document.getElementById("challenge_type").value = "";
		document.getElementById("timeout").value = "";
		document.getElementById("request_type").value="";
		document.getElementById("domain").value = "";
	 	document.getElementById("account_key").value = "";
		document.getElementById("certificate_path").value = "";
		document.getElementById("well_known_dir").value = "";	
		document.getElementById("csr").value = "";
		document.getElementById("wrk_folder").value = "";
		document.getElementById("new_name").value = "";		
				
		//saved_settings.style.visibility = "visible";
		config_name.style.visibility = "visible";
		save_config.style.visibility = "visible";
			
	}
	else
	 // skip the whole thing when selection value is "new"
	{
		config_name.style.display = 'none';
		
	   var url = "/acme_dcm/process/getconfig?configpath="+configpath;

    makeRequest('GET', url)
    .then(function (datums) {

	    array = JSON.parse(datums);
	// grab the values from the array and pop them 
	// back into the field values

	    for (let i = 0; i < array.length; i++) {
		// kinda messy
			if(array[i].challenge_type)
				document.getElementById("challenge_type").value = array[i].challenge_type;

			if(array[i].timeout)
				document.getElementById("timeout").value = array[i].timeout;
				
			if(array[i].request_type)
				document.getElementById("request_type").value = array[i].request_type;
				
			if(array[i].domain)
				document.getElementById("domain").value = array[i].domain;
				
			if(array[i].account_key)
				document.getElementById("account_key").value = array[i].account_key;
				
			if(array[i].certificate_path)
				document.getElementById("certificate_path").value = array[i].certificate_path;
				
			if(array[i].well_known_dir)
				document.getElementById("well_known_dir").value = array[i].well_known_dir;
				
			if(array[i].csr)
				document.getElementById("csr").value = array[i].csr;
				
			if(array[i].wrk_folder)
				document.getElementById("wrk_folder").value = array[i].wrk_folder;

	    }
	

    })
    .catch(function (err) {
      console.error('Augh, there was an error!', err.statusText);
    });

		save_config.style.visibility = "hidden";
		config_name.style.visibility = "hidden";
		
		if(challenge.value == 'http')	
			well_known_dir.style.visibility = "visible";
		else
		well_known_dir.style.visibility = "hidden"
    
	}
	

}