<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DCM with ACME provider</title>
    <link rel="stylesheet" href="css/pure-min.css">
    <link rel="stylesheet" href="css/grids-responsive-min.css">
    <link rel="stylesheet" href="https://netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css">
    <link rel="stylesheet" href="css/styles.css">
    
    <script src="js/acmeapi.js"></script>
</head>
<body>

<div class="header">
    <div class="home-menu pure-menu pure-menu-horizontal pure-menu-fixed">
        <a class="pure-menu-heading" href="">LetsEncrypt with DCM</a>
    </div>
</div>

    <div class="content">
        <h2 class="content-head is-center">LetsEncrypt settings</h2>
                <div class="pure-form pure-form-stacked">
                    <fieldset>
                    
                    <legend>Configuration</legend>
                    
                    <div class="pure-g">
                        <div class="pure-u-1-3">
               	 			<label for="saved_settings">Saved configs</label>
                				<select onchange="loadConfig()" id="saved_settings" name="saved_settings" class="pure-input-1-2">
                				</select>
            			</div>
            		    <div id="config_name" name="config_name" class="pure-u-1-3">
	                        <label for="new_name">Config name </label>
	                        <input id="new_name" name="new_name" type="text" placeholder="Name of config" class="pure-input-1-2">
	                    </div>
	                    <div id="save_config" name="save_config" class="pure-u-1-3">
	                    	<button onclick="saveconfig()" class="pure-button">Save</button>
	                    </div>
            		</div>
                    
                    	<div class="pure-g">
                    
	                    	<div class="pure-u-1-6">
	               	 			<label for="challenge_type">Challenge type</label>
	                				<select id="challenge_type" name="challenge_type" class="pure-input-1">
	                    				<option value="http">HTTP-01</option>
	                    				<option value="dns">DNS-01</option>
	                				</select>
	            			</div>
	            			
	            			<div class="pure-u-1-6">
	               	 			<label for="timeout">Timeout (seconds)</label>
	                				<select id="timeout" name="timeout" class="pure-input-1">
	                    				<option value="30">30</option>
	                    				<option value="60">60</option>
	                    				<option value="120">120</option>
	                    				<option value="180">180</option>
	                    				<option value="300">300</option>
	                				</select>
	            			</div>
	            			
	                    	<div class="pure-u-1-3">
	               	 			<label for="request_type">Request type</label>
	                				<select id="request_type" name="request_type" class="pure-input-1-2">
	                    				<option value="new">New</option>
	                    				<option value="renew">Renew</option>
	                				</select>
	            			</div>
	            			
		                    <div class="pure-u-1-3">
		                        <label for="domain">Domain name (*. wildcard if needed) </label>
		                        <input id="domain" name="domain" type="text" class="pure-input-1-2" placeholder="Domain to process">
		                    </div>
	                    
	                    </div>
	                    
	                    <div class="pure-g">
		                    <div class="pure-u-1 pure-u-md-1-3">
	                        	<label for="account_key">LetsEncrypt account </label>
	                        	<input id="account_key" name="account_key"type="text" placeholder="Path to Let's Encrypt account file">
							</div>
							<div class="pure-u-1 pure-u-md-1-3">
	                        	<label for="csr">Certificate Signing Request</label>
	                        	<input id="csr" name="csr" type="text" placeholder="Path to Certificate Signing Request">
							</div>
							<div id=wellknown class="pure-u-1 pure-u-md-1-3">
	                        	<label for="well_known_dir">Well known dir for HTTP01 challenge</label>
	                        	<input id="well_known_dir" name="well_known_dir" type="text" placeholder="Well known folder">
	                        </div>
                        
                        </div>
                        
                        <div class="pure-g">
	                        <div class="pure-u-1 pure-u-md-1-3">
	                        	<label for="certificate_path">Returned certificate path </label>
	                        	<input id="certificate_path" name="certificate_path" type="text" placeholder="path to returned certificate">
	                        </div>
	                        <div class="pure-u-1 pure-u-md-1-3">
	                        	<label for="wrk_folder">Working directory</label>
	                        	<input id="wrk_folder" name="wrk_folder" type="text" placeholder="path and folder">
	                        </div>
							<div id=dnsrec class="pure-u-1 pure-u-md-1-3">
	                        	<label for="dns_txt_record">DNS txt record value</label>
	                        	<input id="dns_txt_record" name="dns_txt_record" type="text" placeholder="txt record value">
	                        </div>
	
	                        <div id=messages name=messages class="pure-u-1 pure-u-md-2-3">
	                        </div>
                        </div>
                        
              		</div>                      

                    </fieldset>

			</div>
			
			<button id=btnprocess name="btnprocess" onclick="initapi()" class="pure-button">Process request</button>
                        
          </div>

</body>

<script type="text/javascript">
window.onload = function(){

	init();
	
}

</script>
</html>