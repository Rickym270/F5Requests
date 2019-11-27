#!/path/to/python3

import netrc
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#TODO: REMOVE
from pprint import pprint

IP_REGEX = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

class NetrcError(Exception):
    '''
        Custom exceptionL
            There is an error for acquiring netrc credentials
    '''
    pass;

class InvalidIP(Exception):
    '''
        Custom Exception:
           The ip given is invalid.
    '''
    pass;

class NoDataGroupError(Exception):
    '''
        Custom Exception:
           The There was no data-group specified
    '''
    pass;

class F5Requests(object):
    def __init__(self, f5_device_ip):
        '''
            Initialize F5Requests object. The ip of the device is required but the password isn't.
            This assumees that it is to be found in the netrc file
        '''
        import re
        if re.match(IP_REGEX, f5_device_ip): self.f5_ip = f5_device_ip
        else: raise InvalidIP("The ip entered is invalid: {}".format(self.f5_ip))

        try:
            self.__get_credentials()
        except Exception as e:
            # NOTE: Default credentials
            self.__default_credentials()

    def __get_credentials(self):
        import netrc

        try:
            auth_info = netrc.netrc('/path/to/.netrc').authenticators(self.f5_ip)
            if auth_info is not None:
                self.username = auth_info[0]
                self.password = auth_info[2]
        except Exception as e:
            raise netrc.NetrcParseError("Unable to obtain credentials from netrc:\n{}".format(e))

    def __default_credentials(self):
        self.username = 'admin'
        self.password = 'password'

    def __create_session(self):
        '''
            Creates the requests session.
            TODO: Change this so that there is an option to disable SSL Verification

            @returns: s <sessionObject>
        '''
        # TODO: Creates the session
        try:
            self.session = requests.Session()
            # NOTE: Disable cert verification.
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except Exception as e:
            raise Exception("Unable to open a requests session: {}".format(e))

        # TODO: Authenticate the session
        try:
            self.__get_credentials()
            self.session.auth = (self.username, self.password)
        except Exception:
            try:
                self.__default_credentials()
                self.session.auth = (self.username, self.password)
            except Exception as e:
                self.session = None
                raise Exception("Unable to open a requests session: {}".format(e))

    def __getDGroupInfo(self, grepDataGroup):
        '''
            Gets all data-groups from the device.  Saves information to self.dataGroupInfo
            @params:
                grepDataGroup < class 'string' >: Greps for a certain datagroup by name!
        '''
        self.dataGroupInfo = []
        ENV_CURL = "https://{}/mgmt/tm/ltm/data-group/internal/".format(self.f5_ip)
        r = self.session.get(ENV_CURL, verify=False)
        r = r.json()

        for line in r['items']:
            if grepDataGroup:
                if grepDataGroup in line['name']:
                    self.dataGroupInfo.append({ "Name":         line['name'],
                                                "Partition":    line['partition'],
                                                "Records":      line['records'],
                                                "fullPath":     line['fullPath']})
                    #self.dataGroupInfo[line['name']].append(line)
                else: continue
            else:
                self.dataGroupInfo.append({ "Name":         line['name'],
                                            "Partition":    line['partition'],
                                            "Records":      line['records'] if 'records' in line else None,
                                            "fullPath":     line['fullPath']})

    def __getDataGroupNames(self, dataGroupName = None):
        self.dataGroupNames = []

        ENV_CURL = "https://{}/mgmt/tm/ltm/data-group/internal/".format(self.f5_ip)
        r = self.session.get(ENV_CURL, verify=False)
        r = r.json()

        for line in r['items']:
            if dataGroupName:
                if dataGroupName in line['name']:
                    self.dataGroupNames.append(line['name'])
            else:
                self.dataGroupNames.append(line['name'])

    def __getDataGroupRecords(self, dataGroup = None):
        '''
            Gets all brand info of a particular data-group
            @required: dataGroup <class 'string'>
            #params:
                dataGroup <class 'string'>: Contains the datagroup that will be searched for brands

        '''
        self.dataGroupRecordsInfo = []
        if not dataGroup:
            raise NoDataGroupError("Unable to get brands. There was a problem with the dataGroup (not?) specified\ndataGroup: {}".format(dataGroup))

        if dataGroup is not None:
            DATAGROUP_CURL = "https://{}/mgmt/tm/ltm/data-group/internal/{}".format(self.f5_ip, dataGroup)
            r = self.session.get(DATAGROUP_CURL, verify=False)
            r = r.json()
            for item in r['records']:
                if 'none' not in item['name']:
                    self.dataGroupRecordsInfo.append(item)
        else:
            raise NoDataGroupError("No data-group specified in __GetDataGroupRecords()")

    def connect(self):
        self.__create_session()

    def get_dataGroupInfo(self, dataGroupName = None):
        '''
            @returns
                dataGroupInfo <class 'dict'>: contains information about all the data-groups
        '''
        self.__getDGroupInfo(dataGroupName)
        return self.dataGroupInfo

    def get_dataGroupNames(self, dataGroupName = None):
        self.__getDataGroupNames(dataGroupName = dataGroupName)
        return self.dataGroupNames

    def get_dataGroupRecords(self, dataGroup = None):
        '''
            @params:
                dataGroup <class 'string'>: specifies the data-group
            @returns
                dataGroupInfo <class 'dict'>: modified dataGroupInfo
        '''
        self.__getDataGroupRecords(dataGroup)
        return self.dataGroupRecordsInfo

if __name__ == "__main__":
    #NOTE: Insantiating
    QA1BrandNames = []
    TST1BrandNames = []

    f5_dev = F5Requests('xxx.xxx.xxx.xxx')
    f5_dev.connect()
    dg_info = f5_dev.get_dataGroupInfo(grepDataGroup='Hybrid')

    QA1Records = f5_dev.get_dataGroupRecords(dataGroup = 'QA1')
    for record in QA1Records:
        QA1BrandNames.append(record['name'][1:-1])
    print("QA1 Brands: {}".format(QA1BrandNames))

    TST1Records = f5_dev.get_dataGroupRecords(dataGroup = 'TST1-Hybrid')
    for record in TST1Records:
        TST1BrandNames.append(record['name'][1:-1])
    print("TST1 Brands: {}".format(TST1BrandNames))
