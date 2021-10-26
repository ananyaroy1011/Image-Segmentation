'''Note: Change the filename, filepath correctly before executing this script'''
import sys
import requests
import json
import xmltodict
import getpass  
import xml.etree.ElementTree as ET
from datetime import *
import xml.etree.ElementTree as ET

### Global Variables ###
baseURL = "https://dast.newyorklife.com:9443/ase/api"
jobID = ""
etag = ""
configFilePath = ""
root=ET.parse("Config.xml")
cookies = ""
ascXSRFToken = ""
### Login details for AppScan ###
userName = input("Enter the AppScan User Name: ")
userPassword = getpass.getpass(prompt="Enter the AppScan password: ")
dateTime= datetime.today()
timestamp = dateTime.strftime('%d_%m_%y_%I_%M_%p')   
tree=ET.parse("Config.xml")
name=tree.findall('.//name')
for elem in name:
                elem.text="DEV_Demo_Application"+timestamp+"_scan"
tree.write("Config.xml")
        

### Function to login to AppScan Enterprise ###
#userName: The username used to login to AppScan Enterprise
#userPassword: The password used to login to AppScan Enterprise
#returns the post request status code for the AppScan login sequence
def login(userName, userPassword):
    try:
        with open(configFilePath,"r") as file:
            configDict = xmltodict.parse(file.read())
        isRescan = str((configDict["Application_details"]["Create_JOB_params"]["Rescan"]))
        jobID = str((configDict["Application_details"]["Create_JOB_params"]["jobid"]))
        #Config file Rescan and jobID parameters read successfully: Status Code 200
    except:
        print("Error reading Config file - Ending Script")
    url = baseURL + "/login"
    data = {"userId":userName, "password":userPassword, "featureKey":"AppScanEnterpriseUser"}
    requests.packages.urllib3.disable_warnings (requests.packages.urllib3.exceptions.InsecureRequestWarning)
    requestLogin = requests.post(url = url, json = data, verify = False)
    cookies = requestLogin.cookies
    #if login is successful, then create a job to run the scan
    if requestLogin.status_code == 200:
        print("Login Successful")
        loginMetadata = json.loads(requestLogin.text)
        ascXSRFToken = loginMetadata["sessionId"]
        if isRescan == "true" and jobID != "NA":
            get_job(jobID, cookies, ascXSRFToken, 'true')
        elif isRescan == "false":         
            create_jobs(cookies, ascXSRFToken)
        else:
            print("Please check the Rescan field in the config file")                                                                       
    else:
            print("Login not successful")
    return requestLogin.status_code

### Function to create a job using template id ###
#cookies: The Appscan session cookie used to track the job updates in the server
#ascXSRFToken: The unique CSRF token used to validate requests in the servers
def create_jobs(cookies, ascXSRFToken):
                url = baseURL + "/jobs/4843/dastconfig/createjob"
                params = {"templateId":4843}
                headers = {
        'asc_xsrf_token': ascXSRFToken,
        'Content-Type': 'application/json',
                                'Accept': 'application/json'
            }
                #This try block attempts to read the Config file, if an invalid config file it will print an error statement
                try:
                                with open(configFilePath,"r") as file:
                                                configDict = xmltodict.parse(file.read())
                                testPolicyID = str((configDict["Application_details"]["Create_JOB_params"]["testpolicyid"]))
                                folderID = str((configDict["Application_details"]["Create_JOB_params"]["folderid"]))
                                appID = str((configDict["Application_details"]["Create_JOB_params"]["appid"]))
                                name = str((configDict["Application_details"]["Create_JOB_params"]["name"]))
                                description = str((configDict["Application_details"]["Create_JOB_params"]["description"]))
                                contact = str((configDict["Application_details"]["Create_JOB_params"]["contact"]))
                                loginPath = str((configDict["Application_details"]["Update_traffic_file"]["loginpath"]))
                                trafficPath = str((configDict["Application_details"]["Update_traffic_file"]["trafficpath"]))
                                body = {"testPolicyId": str(testPolicyID), "folderId": str(folderID), "applicationId": str(appID), "name": name, "description": description, "contact": contact}
        #Config file parameters read successfully: Status Code 200
                except:
                                print("Error reading Config file - Ending Script")
                else: 
                                postResponse = requests.post(url = url, data=json.dumps(body), params=params, verify = False, headers = headers, cookies = cookies)    
                #If the DAST job is created successfully, update the jobID traffic and print the jobID created
                                if postResponse.status_code == 201:
                                                loginMetadata = json.loads(postResponse.text)
                                                jobID = loginMetadata["id"]
                                                print ("The jobID "+str(jobID)+" has been created successfully, record this jobID for future rescans")
                                #If Login har file is present, update the login of the job
                                                if(loginPath!='None'):
                                                                update_login(jobID, cookies, ascXSRFToken)
                                                else:
                                                                print("Warning: Lack of login.har file will not generate full scan results")
                                #If Traffic har file is present, update the traffic of the job
                                                if(trafficPath!='None'):
                                                                update_traffic(jobID, cookies, ascXSRFToken) 
                                #Run the job
                                                get_job(jobID, cookies, ascXSRFToken)
                #If the scan name already exists, return status code and end the script
                                elif postResponse.status_code == 409:
                                                print("The scan name already exists, please change the scan name in config file")
                #If you do not have access to the test policy, return status code and end the script
                                elif postResponse.status_code == 403:
                                                print("You do not have access to this test policy, please confirm the test policy id in config file") 
                                                print(postResponse)
                                else:
                                                print(postResponse)       
                
### Function to update the login of a job ###
#jobID: The token ID used to create the job          
#cookies: The Appscan session cookie used to track the job updates in the server
#ascXSRFToken: The unique CSRF token used to validate requests in the server  
#returns the post response status code for the application login sequence       
def update_login(jobID, cookies, ascXSRFToken):
                url = baseURL + "/jobs/"+str(jobID)+"/dastconfig/updatetraffic/login"
                headers = {"asc_xsrf_token":ascXSRFToken}
                #This try block attempts to read the Config file, if an invalid config file is provided it returns an error 
                try:
                                with open(configFilePath) as file:
                                                configDict = xmltodict.parse(file.read())
                                loginPath = str((configDict["Application_details"]["Update_traffic_file"]["loginpath"]))
                                location = loginPath.rfind("\\")
                                fileName = loginPath[location+1:]
                                fileData = {'uploadedfile': (fileName, open(loginPath, 'rb'))}
                except:
                                print("Error reading login filepath in Config file - Ending Script")
                Login = requests.post(url = url, files = fileData, verify = False, headers = headers, cookies = cookies)
                return Login.status_code    
### Function to update the traffic of a job ###
#jobID: The token ID used to create the job          
#cookies: The Appscan session cookie used to track the job updates in the server
#ascXSRFToken: The unique CSRF token used to validate requests in the server 
#returns the post response status code for the application traffic sequence       
def update_traffic(jobID, cookies, ascXSRFToken):
                url = baseURL + "/jobs/"+str(jobID)+"/dastconfig/updatetraffic/add"
                headers = {"asc_xsrf_token":ascXSRFToken}
                #This try block attempts to read the Config file, if an invalid config file is provided it returns an error
                try:
                                with open(configFilePath) as file:
                                                configDict = xmltodict.parse(file.read())
                                trafficPath = str((configDict["Application_details"]["Update_traffic_file"]["trafficpath"]))
                                location = trafficPath.rfind("\\")
                                fileName = trafficPath[location+1:]
                                fileData = {'uploadedfile': (fileName, open(trafficPath, 'rb'))}
                except:
                                print("Error reading traffic filepath in Config file - Ending Script")
                Traffic = requests.post(url = url, files = fileData, verify = False, headers = headers, cookies = cookies)
                return Traffic.status_code    
            
### Get job ###
#jobID: The token ID used to create the job
#cookies: The Appscan session cookie used to track the job updates in the server
#ascXSRFToken: The unique CSRF token used to validate requests in the server        
#isRescan: boolean element in Config.xml file to check whether the application needs to be rescanned
#returns the post response status code for the API fetching the job details
def get_job(jobID, cookies, ascXSRFToken, isRescan = 'false'):
    url = str(baseURL) + "/jobs/" +str(jobID)
    headers = {"asc_xsrf_token":ascXSRFToken}
    jobDetails = requests.get(url = url, verify = False, headers = headers, cookies = cookies)
                #If the API successfully runs the job, return the successful status code and end the script 
    if jobDetails.status_code == 200:
        etag = jobDetails.headers['Etag']
        run_jobs(etag, jobID, cookies, ascXSRFToken, isRescan)
    else:
        print("Error! Incorrect jobID field in config file - Ending Script")                                           
    return jobDetails.status_code
                
### Run job ###
#etag: Parameter containing the job details metadata
#jobID: The token ID used to create the job
#cookies: The Appscan session cookie used to track the job updates in the server
#ascXSRFToken: The unique CSRF token used to validate requests in the server        
#isRescan: Boolean element in Config.xml file to check whether the application needs to be rescanned
#returns the post response status code for the API running the job
def run_jobs(etag, jobID,cookies, ascXSRFToken, isRescan = 'false'):
    if isRescan == "true":
        urlRescan = str(baseURL)+"/jobs/"+str(jobID)+"/actions?isIncremental=true&isRetest=true"
    else:
        urlRescan = str(baseURL)+"/jobs/"+str(jobID)+"/actions"
    url = urlRescan.strip()
    body = "{ \n \"type\": \"run\"\n}"
    headers = {
        'asc_xsrf_token': ascXSRFToken,
        'If-Match': etag,
        'Content-Type': 'application/json'
        }
    runJob = requests.post(url = url, data = body, verify = False, headers = headers, cookies = cookies)
                #If the API successfully runs the job, return the successful status code and end the script
    if runJob.status_code == 200:
        print("Success: The request has succeeded and the Scan is running. Please login to dast.newyorklife.com to view the scan progress.")  
    else:
        print("Error: Scan not Running.")
    return runJob.status_code

#Check the file path of the Config.xml file passed in when running the script
try:
                configFilePath = sys.argv[1]
except:
                print("No Config filepath provided - Ending Script")

#Check the status code during login process and retry if login fails
statusCode = login(userName, userPassword)      
if (statusCode != 200):
                print("Login failed - Ending Script")
sys.exit(0)

