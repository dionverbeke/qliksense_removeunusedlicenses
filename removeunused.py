import requests
import json
import random
import string
import datetime
# Code derived from Clint Carr
# ============================


requests.packages.urllib3.disable_warnings()

def set_xrf():
    characters = string.ascii_letters + string.digits
    return ''.join(random.sample(characters, 16))

xrf = set_xrf()

headers = {"X-Qlik-XrfKey": xrf,
           "Accept": "application/json",
           "X-Qlik-User": "UserDirectory=Internal;UserID=sa_repository",
           "Content-Type": "application/json"}

session = requests.session()

class ConnectQlik:
    """
    Instantiates the Qlik Repository Service Class
    """

    def __init__(self, server, certificate=False, root=False, userdirectory=False,
                 userid=False, credential=False, password=False):
        """
        Establishes connectivity with Qlik Sense Repository Service
        :param server: servername.domain:4242
        :param certificate: path to client.pem and client_key.pem certificates
        :param root: path to root.pem certificate
        :param userdirectory: userdirectory to use for queries
        :param userid: user to use for queries
        :param credential: domain\\username for Windows Authentication
        :param password: password of windows credential
        """
        self.server = server
        self.certificate = certificate
        self.root = root
        if userdirectory is not False:
            headers["X-Qlik-User"] = "UserDirectory={0};UserID={1}".format(userdirectory, userid)
        self.credential = credential
        self.password = password

    def get(self, endpoint, filterparam=None, filtervalue=None):
        """
        Function that performs GET method to Qlik Repository Service endpoints
        :param endpoint: API endpoint path
        :param filterparam: Filter for endpoint, use None for no filtering
        :param filtervalue: Value to filter on, use None for no filtering
        """
        if self.credential is not False:
            session.auth = HttpNtlmAuth(self.credential, self.password, session)
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36'
        if filterparam is None:
            if '?' in endpoint:
                response = session.get('https://{0}/{1}&xrfkey={2}'.format(self.server, endpoint, xrf),
                                        headers=headers, verify=False, cert=self.certificate)
                return response.content
            else:
                response = session.get('https://{0}/{1}?xrfkey={2}'.format(self.server, endpoint, xrf),
                                        headers=headers, verify=False, cert=self.certificate)
                return response.content
        else:
            response = session.get("https://{0}/{1}?filter={2} '{3}'&xrfkey={4}".format 
                                    (self.server, endpoint, filterparam, filtervalue, xrf), 
                                    headers=headers, verify=False, cert=self.certificate)
            
            return response.content

    def delete(self, endpoint):
        """
        Function that performs DELETE method to Qlik Repository Service endpoints
        :param endpoint: API endpoint path
        """
        if '?' in endpoint: 
            response = session.delete('https://{0}/{1}&xrfkey={2}'.format (self.server, endpoint, xrf),
                                            headers=headers, verify=False, cert=self.certificate)
            return response.status_code
        else:
            response = session.delete('https://{0}/{1}?xrfkey={2}'.format (self.server, endpoint, xrf),
                                            headers=headers, verify=False, cert=self.certificate)
            return response.status_code

    def put(self, endpoint, data=None):
        """
        Function that performs PUT method to Qlik Repository Service endpoints
        :param endpoint: API endpoint path
        """
        if '?' in endpoint:
            if data is None:
                response = session.put('https://{0}/{1}&xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, verify=False, cert=self.certificate)
                return response.status_code
            else:
                response = session.put('https://{0}/{1}&xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, data=data,verify=False, cert=self.certificate)

                return response.status_code
        else:
            if data is None:
                response = session.put('https://{0}/{1}?xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, verify=False, cert=self.certificate)
                return response.status_code
            else:
                response = session.put('https://{0}/{1}?xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, data=data, verify=False, cert=self.certificate)
                return response.status_code

    def post(self, endpoint, data=None):
        """
        Function that performs POST method to Qlik Repository Service endpoints
        :param endpoint: API endpoint path
        :param data: Data that is posted in body of request.
        """
        if '?' in endpoint:
            if data is None:
                response = session.post('https://{0}/{1}&xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, 
                                                verify=False, cert=self.certificate)
                return response.status_code
            else:
                response = session.post('https://{0}/{1}&xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, data=data, 
                                                verify=False, cert=self.certificate)
                return response.status_code
        else:
            if data is None:
                response = session.post('https://{0}/{1}?xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, 
                                                verify=False, cert=self.certificate)
                return response.status_code
            else:
                response = session.post('https://{0}/{1}?xrfkey={2}'.format (self.server, endpoint, xrf),
                                                headers=headers, data=data, 
                                                verify=False, cert=self.certificate)
                return response.status_code

    def get_qps(self, endpoint):
        """
        Function that performs GET method to Qlik Proxy Service endpoints
        :param endpoint: API endpoint path
        """
        server = self.server
        qps = server[:server.index(':')]

        response = session.get('https://{0}/{1}?xrfkey={2}'.format (qps, endpoint, xrf),
                                        headers=headers, verify=False, cert=self.certificate)
        return response.status_code

    
    def get_useraccesstype(self, opt=None,filterparam=None, filtervalue=None):
        """
        Returns the users with user access type
        :param filterparam: Property and operator of the filter
        :param filtervalue: Value of the filter
        :returns: JSON
        """
        path = 'qrs/license/useraccesstype'
        if opt:
            path += '/full'
        return json.loads(self.get(path, filterparam, filtervalue).decode('utf-8'))

    def get_loginaccesstype(self, opt=None,filterparam=None, filtervalue=None):
        """
        Returns the login access type rule
        :param filterparam: Property and operator of the filter
        :param filtervalue: Value of the filter
        :returns: JSON
        """
        path = 'qrs/license/loginaccesstype'
        if opt:
            path += '/full'
        return json.loads(self.get(path, filterparam, filtervalue))

    
    def delete_useraccesstype(self, useraccessid):
        """
        Deletes a user access token (quarantine)
        :returns: HTTP Status Code
        """
        path = 'qrs/license/useraccesstype/{0}'.format (useraccessid)
        return self.delete(path)


    def delete_unused_licenses(self):
        x  = self.get_useraccesstype(opt='full')
        today = datetime.date.today()
        last = today - datetime.timedelta(days=8)
        today = today.isoformat()
        last = last.isoformat()
        print('delete_unused_licenses from=', last, ' today=',today)
   
        for item in range(len(x)):
            y = x[item]['lastUsed']
            y1 = y[:10]
            if str(y1) <= str(last):
                print ('user_name=',y1 + last + x[item]['user']['name'])
                # print(json.dumps(x[item], indent=4, sort_keys=True))
                print('result=',qrs.delete_useraccesstype(x[item]['id']))

        return self


if __name__ == '__main__':
    server = '10.67.30.160'
    client = 'C:\\client.pem'
    client_key = 'C:\\client_key.pem'
    root = 'C:\\root.pem'

    qrs = ConnectQlik(server=server + ':4242', certificate=(client,client_key,root))
    print('connecting to QRS')

    print('deleting unused licenses')
    qrs.delete_unused_licenses()  
  