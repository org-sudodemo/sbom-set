from logging import critical
from os import set_blocking
import shutil
import boto3
from crtsh import crtshAPI
import boto3
import json
import requests 
import base64
import requests
from flask import Flask, jsonify, render_template, request
from datetime import datetime
import time
from collections import Counter
from itertools import product
import json
import re
import os
from dotenv import load_dotenv
load_dotenv()

#testdev testing
app = Flask(__name__)
Session = boto3.Session(
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_KEY'),
    region_name='us-east-2',
)


@app.route("/api/create/product", methods=["POST"])
def createProduct():
    endpoint = request.json["strapi-url"]
    endpoint = endpoint + "products"
    header = request.json["strapi-auth"]
    product = request.json["product"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]    
     data = {"name": product,"teams":teamid }
    else:
        data = {"name": product }   
    headers = {"Authorization": header}
    res = requests.post(endpoint, data=data, headers=headers).json()
    print(res)
    value = res["id"]
    result = {"result": value}
    return result


@app.route("/api/create/component", methods=["POST"])
def createComponent():
    endpoint = request.json["strapi-url"]
    endpoint = endpoint + "components"
    header = request.json["strapi-auth"]
    component = request.json["component"]
    githubUrl = request.json["githuburl"]
    product = request.json["products"]
    language=request.json['language'],
    type= request.json['type']

    branch=request.json['branch']
    types=request.json['types']
    if(types=='Company'):
     teamid=request.json["teams"]        
     data = {"name": component, "githubURL": githubUrl, "teams":teamid,"products": product,"description":language,"type":type,"branch":branch}
    else:
       data = {"name": component, "githubURL": githubUrl,"products": product,"description":language,"type":type,"branch":branch} 
    headers = {"Authorization": header}
    res = requests.post(endpoint, data=data, headers=headers).json()
    value = res["id"]
    result = {"result": value}
    return result


@app.route("/api/create/scan", methods=["POST"])
def createScan():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]    
     endpoint = endpoint + "scans"
     header = request.json["strapi-auth"]
     tool = request.json["tool"]
     component = request.json["components"]
     startTs=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
     data = {
            "tool": tool, 
            "components": component,  
            "startTS":startTs,
            "teams":teamid
}
    else:
     endpoint = endpoint + "scans"
     header = request.json["strapi-auth"]
     tool = request.json["tool"]
     component = request.json["components"]
     startTs=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
     data = {
            "tool": tool, 
            "components": component,  
            "startTS":startTs
}

    headers = {"Authorization": header}
    res = requests.post(endpoint, data=data, headers=headers).json()
    value = res["id"]
    result = {"result": value}
    return result

@app.route("/api/update/scan", methods=["POST"])
def updateScan():
    endpoint = request.json["strapi-url"]
    endpoint = endpoint + "scans/" + str(request.json['id'])
    header = request.json["strapi-auth"]
    teamid=request.json["teams"]    
    version = request.json["version"]
    data = {
            "version": version
}
    headers = {"Authorization": header}
    res = requests.put(endpoint, data=data, headers=headers).json()
    value = res["id"]
    result = {"result": value}
    return result    


@app.route("/api/fetch/vulns", methods=["POST"])
def fetchVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    header = request.json["strapi-auth"]

    headers = {"Authorization": header}
    if(type=='Company'):
     teamid=request.json["teams"]         
     endpoint = endpoint + "vulns"
  
     urlInfo = endpoint + "/count?severity=Info&&scans.teams="+str(teamid)
     urlHigh = endpoint + "/count?severity=High&&scans.teams="+str(teamid)
     urlMedium = endpoint + "/count?severity=Medium&&scans.teams="+str(teamid)
     urlCritical = endpoint + "/count?severity=Critical&&scans.teams="+str(teamid)
     urlLow = endpoint + "/count?severity=Low&&scans.teams="+str(teamid)
     urlCount = endpoint + "/count?scans.teams="+str(teamid)
     info = requests.get(urlInfo, headers=headers).json()
     print(info)
    else:
      endpoint = endpoint + "vulns"
  
      urlInfo = endpoint + "/count?severity=Info"
      urlHigh = endpoint + "/count?severity=High"
      urlMedium = endpoint + "/count?severity=Medium"
      urlCritical = endpoint + "/count?severity=Critical"
      urlLow = endpoint + "/count?severity=Low"
      urlCount = endpoint + "/count"

    info = requests.get(urlInfo, headers=headers).json()        
    high = requests.get(urlHigh, headers=headers).json()
    medium = requests.get(urlMedium, headers=headers).json()
    critical = requests.get(urlCritical, headers=headers).json()
    low = requests.get(urlLow, headers=headers).json()
    total = requests.get(urlCount, headers=headers).json()
    result = {
        "high": high,
        "low": low,
        "medium": medium,
        "info": info,
        "critical": critical,
        "total": total,
    }
    return result


@app.route("/api/fetch/top", methods=["POST"])
def FetchTopVulnsAPI():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]    
     endpoint = endpoint + "vulns?teams="+str(teamid)
    else:
        endpoint = endpoint + "vulns"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    urlTop = endpoint + "?cwe_ne=NULL"
    high = requests.get(urlTop, headers=headers).json()
    result={"result":high}

   
    return result



@app.route("/api/fetch/components/vulns", methods=["POST"])
def FetchComponentVulns():
    endpoint = request.json["strapi-url"]
    endpoint = endpoint + "scans"
    header = request.json["strapi-auth"]
    teamid=request.json["teams"]    
    headers = {"Authorization": header}
    reshigh = requests.get(endpoint, headers=headers).json()
    dictData = {"result": reshigh}
    c = 0
    result = []
    for index in dictData["result"]:
        row = index["components"]
        cname = row[c]["name"]
        col = index["vulns"]
        critical = 0
        high = 0
        info = 0
        medium = 0
        low = 0
        for row in col:
            data = row["severity"]
            if data == "Critical":
                critical = critical + 1
            if data == "High":
                high = high + 1
            if data == "Medium":
                medium = medium + 1
            if data == "Info":
                info = info + 1
            if data == "Low":
                low = low + 1
        total = critical + high + medium + low + info
        data = {
            "component": cname,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }
        result.append(data)
    result = {"result": result}
    return result


@app.route("/api/fetch/oss", methods=["POST"])
def fetchOss():
    S3 = Session.resource("s3")
    org = request.json["org-data"]
    endpoint = "data" + "/" + org + "/" + "result" + "/"
    S3.Bucket(name="myairflow")
    BUCKET_NAME = "myairflow"
    KEY = "index.html"
    FILE_PATH = endpoint + "index.html"
    s3 = Session.resource("s3")
    s3.Bucket(BUCKET_NAME).download_file(FILE_PATH, KEY)
    shutil.copy2("index.html", "templates/index.html")
    return render_template("index.html")


@app.route("/api/fetch/status", methods=["POST"])
def fetchStatus():
    endpoint = request.json["strapi-url"]
    teamid=request.json["teams"]    
    endpoint = endpoint + "vulns/count"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    res = requests.get(endpoint, headers=headers).json()
    return str(res)


@app.route("/api/fetch/package/vulns", methods=["POST"])
def fetchpackageVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]      
     endpoint = endpoint + "vulns?packageName_ne=NULL"+"&_limit=-1&&scans.teams="+str(teamid)
    else:
         endpoint = endpoint + "vulns?packageName_ne=NULL"+"&_limit=-1" 
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoint, headers=headers).json()
    dictData = {"result": reshigh}
    counter = Counter(item["packageName"] for item in dictData["result"])
    top = counter.most_common(20)
    ans=[]
    for key, value in top:
        data={}
        data[key]=value
        ans.append(data)

    return jsonify(ans)    

@app.route("/api/fetch/components/vuln", methods=["POST"])
def fetchcompVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]         
     endpoint = endpoint + "scans?teams="+str(teamid)
    else:
              endpoint = endpoint + "scans"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoint, headers=headers).json()
    dictData = {"result": reshigh}
    endpoints = endpoint+"/count"
    count = requests.get(endpoints, headers=headers).json()
    a=0
    result=[]
    for item in dictData['result']:
        giturl=item['components'][0]['githubURL']
        language=item['components'][0]['description']
        print(language)
        giturl=giturl[:-4]
        giturl=giturl+"/blob/master"
        for key in item['vulns']:
            file=key['file']
            file=file[1:]
            file=file[file.find('/'):]
            url=giturl + file
            key['githubPath']=url
            key['language']=language
            result.append(key)
    return jsonify(result)
def componentData(url,key,duration,auth):
    endpoint = url
    try:
     endpoint = endpoint + "vulns?scans=" +str(key) + "&_limit=-1"
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
     githuburl=res['components'][0]['githubURL']
     #print(githuburl) 
     giturl=githuburl[:-4]   
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)   
     print(giturl)    
     for index in dictData["result"]:
         print(index['file'])
         file=index['file']
         file=file[1:]
         file=file[file.find('/'):]
         url=giturl + file
         url=url[1:]
         index['githubPath']=url        
         severity.append(index)
         data = index["severity"]
         if data == "Critical":
             critical = critical + 1
         if data == "High":
             high = high + 1
         if data == "Medium":
             medium = medium + 1
         if data == "Info":
             info = info + 1
         if data == "Low":
             low = low + 1
     total = critical + high + medium + low + info
     data = {
            "duration":duration,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }
     res={"count":data,"severity":severity}    
     result.append(res)    
     result = {"result": result}
     return result
    except:
        return {"result":{}}



def componentDockerData(url,key,duration,auth):
    endpoint = url
    try:
     endpoint = endpoint + "vulns?cvss_ne=null&&scans=" +str(key)
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
     githuburl=res['components'][0]['githubURL']
     #print(githuburl) 
     giturl=githuburl[:-4]   
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)   
     print(giturl)    
     for index in dictData["result"]:
         print(index['file'])
         file=index['file']
         file=file[1:]
         file=file[file.find('/'):]
         url=giturl + file
         url=url[1:]
         index['githubPath']=url        
         severity.append(index)
         data = index["severity"]
         if data == "Critical":
             critical = critical + 1
         if data == "High":
             high = high + 1
         if data == "Medium":
             medium = medium + 1
         if data == "Info":
             info = info + 1
         if data == "Low":
             low = low + 1
     total = critical + high + medium + low + info
     data = {
            "duration":duration,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }
     res={"count":data,"severity":severity}    
     result.append(res)    
     result = {"result": result}
     return result
    except:
        return {"result":{}}        

def scanData(url,key,auth):
    endpoint = url
    try: 
     endpoint = endpoint + "components/" +str(key)
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     key=dictData['result']['scans']
     value=""
     duration=""
     for k in key:
         value=k['id']
         duration=k['duration']
         start=k['startTS']
     print('------')
     result=componentData(url,value,duration,auth)
     return result
    except:
        return {"result":{}} 

def componentCodeData(url,key,duration,auth):
     endpoint = url
  #  try:
     endpoint = endpoint + "vulns?scans=" +str(key) +  "&_limit=-1"
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
    
     githuburl=res['components'][0]['githubURL']
     #print(githuburl) 
     giturl=githuburl[:-4]   
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)      
     for index in dictData["result"]:
         file=index['file']
         try:
          file=file[1:]
          file=file[file.find('/'):]
          url=giturl + file
          url=url[1:]
         except:
           url="not found"           
         index['githubPath']=url        
         cwe= index['cwe']
         print(url)
         value=""
         try:
          value = cwe[1]
         except TypeError:
          value = 'S'

         if(value=='W' or value=='S'):
           severity.append(index)
           data = index.get("severity")
           print(data)
           if data == "Critical":
             critical = critical + 1
           if data == "High":
             high = high + 1
           if data == "Medium":
             medium = medium + 1
           if data == "Info":
             info = info + 1
           if data == "Low":
             low = low + 1
      

     total = critical + high + medium + low + info
     data = {
            "duration":duration,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }

     print(data)
     res={"count":data,"severity":severity}    
     result.append(res)    
     result = {"result": result}
     return result


def scanCodeData(url,key,auth):
    endpoint = url
    try: 
     endpoint = endpoint + "components/" +str(key)
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     key=dictData['result']['scans']
     value=""
     duration=""
     for k in key:
         value=k['id']
         duration=k['duration']
         start=k['startTS']
     result=componentCodeData(url,value,duration,auth)
     return result
    except:
        return {"result":{}} 

def scanDockerData(url,key,auth):
    endpoint = url
    try: 
     endpoint = endpoint + "components/" +str(key)
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     key=dictData['result']['scans']
     value=""
     duration=""
     for k in key:
         value=k['id']
         duration=k['duration']
         start=k['startTS']
     print('------')
     result=componentDockerData(url,value,duration,auth)
     return result
    except:
        return {"result":{}}         

def comData(url,key,duration,auth):
    endpoint = url
    try:
     endpoint = endpoint + "vulns?scans=" +str(key) + "&&packageName_ne=NULL"
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
     githuburl=res['components'][0]['githubURL']
    #print(githuburl)
     giturl=githuburl[:-4]
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)   
     print(giturl)    
     for index in dictData["result"]:
         print(index['file'])
         file=index['file']
         file=file[1:]
         file=file[file.find('/'):]
         url=giturl + file
         url=url[1:]
         index['githubPath']=url        
         severity.append(index)
         data = index["severity"]
         if data == "Critical":
             critical = critical + 1
         if data == "High":
             high = high + 1
         if data == "Medium":
             medium = medium + 1
         if data == "Info":
             info = info + 1
         if data == "Low":
             low = low + 1
     total = critical + high + medium + low + info
     data = {
            "duration":duration,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }
     res={"count":data,"severity":severity}    
     result.append(res)    
     result = {"result": result}
     return result
    except:
        return {"result":{}} 


def dependencyData(url,key,auth):
    endpoint = url
    try: 
     endpoint = endpoint + "components/" +str(key)
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     key=dictData['result']['scans']
     value=""
     duration=""
     for k in key:
         value=k['id']
         duration=k['duration']
         start=k['startTS']
     print('------')
     result=comData(url,value,duration,auth)
     return result
    except:
        return {"result":{}} 

@app.route("/api/fetch/project/vulns", methods=["POST"])
def fetchprojectVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]     
     endpoints = endpoint + "products?teams="+str(teamid)
    else:
            endpoints = endpoint + "products"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result=[]
    for item in dictData["result"]:
        ans={}
        ans['product']=item['name']
        res=[]
        for key in item['components']:
            data={}
            data['id']=key['id']
            data['name']=key['name']
            a=scanData(endpoint,key['id'],header)
            data['severity']=a
            res.append(data)
        print('--------')
        ans['component']=res
        result.append(ans)

    return {"result":result}

def historyData(url,key,auth):
    endpoint = url
    endpoint = endpoint + "vulns?scans=" +str(key) + "&_limit=-1"
    header = auth
    headers = {"Authorization": header}
    print(endpoint)
    reshigh = requests.get(endpoint, headers=headers).json()
    dictData = {"result": reshigh}
    print(dictData['result'])
    c = 0
    critical = 0
    high = 0
    info = 0
    medium = 0
    low = 0
    result = []
    severity=[]
    endpoints=url+"scans/"+str(key)
    res = requests.get(endpoints, headers=headers).json()
    githuburl=res['components'][0]['githubURL']
    #print(githuburl) 
    giturl=githuburl[:-4]   
    branch=giturl[4:]
    giturl=giturl[4:]
    index = giturl.find(' ') #stores the index of a substring or char
    giturl=giturl[index:]
       # print(branch)
    branch=branch.split(' ')[0]
    giturl=giturl+"/blob/" +str(branch)   
    print(giturl)        
    for index in dictData["result"]:
        print(index['file'])
        file=index['file']
        file=file[1:]
        file=file[file.find('/'):]
        url=giturl + file
        url=url[1:]
        index['githubPath']=url
        severity.append(index)
        data = index["severity"]
        if data == "Critical":
            critical = critical + 1
        if data == "High":
            high = high + 1
        if data == "Medium":
            medium = medium + 1
        if data == "Info":
            info = info + 1
        if data == "Low":
            low = low + 1
    total = critical + high + medium + low + info
    data = {

            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }
    dictData = {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info
    }    
    sol = max(dictData, key=dictData.get)
    if(critical==0 and sol=="critical"):
        sol="low"
    res={"count":data,"severity":severity,"priority":sol}    
    result.append(res)    
    result = {"result": result}
    return result

@app.route("/api/fetch/scan/history", methods=["POST"])
def scanHistory():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]   
     endpoints = endpoint + "components?teams="+str(teamid)
    else:
      endpoints = endpoint + "components"   
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result=[]
    for item in dictData["result"]:
        ans={}
        res=[]
        data={}
        data['name']=item['name'],
        data['url']=item['githubURL'],
        data['description']=item['description']
        for key in item['scans']:
            data['id']=key['id']
            data['tool']=key['tool']
            data['duration']=key['duration']
            data['start time']=key['startTS']
            a=historyData(endpoint,key['id'],header)
            data['severity']=a
            data['priority']=a['result'][0]['priority']
            data['branch']='master'
            data['version']='1.0'
            data['run by']='umakant dubey'
        print('--------')
        result.append(data)

    return {"result":result}

@app.route("/api/fetch/dependency/vulns", methods=["POST"])
def fetchdependencyVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]      
     endpoints = endpoint + "products?teams="+str(teamid)
    else:
              endpoints = endpoint + "products"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result=[]
    for item in dictData["result"]:
        ans={}
        ans['product']=item['name']
        res=[]
        for key in item['components']:
            data={}
            data['id']=key['id']
            data['name']=key['name']
            a=dependencyData(endpoint,key['id'],header)
            data['severity']=a
            res.append(data)
        print('--------')
        ans['component']=res
        result.append(ans)

    return {"result":result}


@app.route("/api/fetch/scans/vulns", methods=["POST"])
def fetchscansVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]       

     endpoints = endpoint + "scan-histories?teams="+str(teamid)
    else:
          endpoints = endpoint + "scan-histories"
    print(endpoint)

    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result={}
    scanlist=[]
    for item in dictData["result"]:
        res={}
        res['id']=item['id']
        res['type']=item['type']
        res['run date']=item['runDate']  
        res['product']=item['products'][0]['name']
        res['run by']=item['org_users'][0]['name']
        count=0
        ans=[]
        totalcount={}
        critical=0
        high=0
        medium=0
        low=0
        info=0
        for i in item['scans']:
            list={}
            print(i['id'])
            print(endpoint)
            endpoints=endpoint +"components?scans=" +str(i['id'])
            response=requests.get(endpoints, headers=headers).json()
            name=response[0]['name']
            giturl=response[0]['githubURL']

            results=historyData(endpoint,i['id'],header)
            critical+=results['result'][0]['count']['critical']
            high+=results['result'][0]['count']['high']
            medium+=results['result'][0]['count']['medium']
            low+=results['result'][0]['count']['low']
            info+=results['result'][0]['count']['info']                                                      
            list['results']=results
            list['component name']=name
            giturl=giturl[:-4]   
            branch=giturl[4:]
            giturl=giturl[4:]
            index = giturl.find(' ') #stores the index of a substring or char
            giturl=giturl[index:]
             # print(branch)
            branch=branch.split(' ')[0]
            list['branch']=branch
            list['githubURL']=giturl[1:]
            print(giturl)
            ans.append(list)
            count=count+1
        res['component count']=count    
        res['scans']=ans
        totalcount['critical']=critical
        totalcount['high']=high
        totalcount['medium']=medium
        totalcount['low']=low
        totalcount['info']=info
        res['total severity']=totalcount
        scanlist.append(res)
    result['result']=scanlist    
    return result

@app.route("/api/fetch/container/vulns", methods=["POST"])
def fetchcontainerVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]                 
     endpoints = endpoint + "products?teams="+str(teamid)
    else:
         endpoints = endpoint + "products"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result=[]
    for item in dictData["result"]:
        ans={}
        ans['product']=item['name']
        res=[]
        for key in item['components']:
            data={}
            type=key['type']
            if(type=='container'):
              data['id']=key['id']
              data['name']=key['name']
              a=scanData(endpoint,key['id'],header)
              data['severity']=a
              res.append(data)
            if(type=='repo'):
              data['id']=key['id']
              data['name']=key['name']
              a=scanDockerData(endpoint,key['id'],header)
              data['severity']=a
              res.append(data)                  
        print('--------')
        ans['component']=res
        result.append(ans)

    return {"result":result}
   
@app.route("/api/fetch/code/vulns", methods=["POST"])
def fetchcodeVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]            
     endpoints = endpoint + "products?components.type=repo&&teams="+str(teamid)
    else:
            endpoints = endpoint + "products?components.type=repo"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result=[]
    for item in dictData["result"]:
        ans={}
        ans['product']=item['name']
        res=[]
        for key in item['components']:
            data={}
            type=key['type']
            if(type=='repo'):
              data['id']=key['id']
              data['name']=key['name']
              a=scanCodeData(endpoint,key['id'],header)
             # a=scanCodeData(endpoint,48,header)
              data['severity']=a
              res.append(data)
        print('--------')
        ans['component']=res
        result.append(ans)

    return {"result":result}
      

@app.route("/api/fetch/license/vulns", methods=["POST"])
def fetchlicenseVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]          
     endpoints = endpoint + "products?components.type=repo&&teams="+str(teamid)
    else:
             endpoints = endpoint + "products?components.type=repo"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result=[]
    for item in dictData["result"]:
        ans={}
        ans['product']=item['name']
        res=[]
        for key in item['components']:
            data={}
            type=key['type']
            if(type=='repo'):
              data['id']=key['id']
              data['name']=key['name']
              a=scanCodeData(endpoint,key['id'],header)
              data['severity']=a
              res.append(data)
        print('--------')
        ans['component']=res
        result.append(ans)

    return {"result":result}


@app.route("/api/fetch/scan/status", methods=["GET"])
def fetchScanStatus():
 mwaa_env_name = 'MyAirflowEnvironment'
 client = boto3.client('mwaa', 
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_KEY'),
               region_name='us-east-2' )
 mwaa_cli_token = client.create_cli_token(
    Name=mwaa_env_name
)
 mwaa_auth_token = 'Bearer ' + mwaa_cli_token['CliToken']
 print(mwaa_auth_token)
 mwaa_webserver_hostname = 'https://{0}/aws_mwaa/cli'.format(mwaa_cli_token['WebServerHostname'])

 print(mwaa_webserver_hostname)
 print(mwaa_auth_token)
 
 url = mwaa_webserver_hostname
 token=mwaa_auth_token
 payload = "dags list-runs -o json"
 headers = {
  'Content-Type': 'text/plain',
  'Authorization': token
}

 response = requests.request("POST", url, headers=headers, data=payload)
 mwaa_std_err_message = base64.b64decode(response.json()['stderr']).decode('utf8')
 mwaa_std_out_message = base64.b64decode(response.json()['stdout']).decode('utf8')
 json_object = json.loads(mwaa_std_out_message)
 return jsonify(json_object)

def statusCheck():
    urls = "https://dev.sudoviz.com/api/aspm/account/fetch/scan/status"

    payload={}
    headerss = {}
    responses = requests.request("GET", urls, headers=headerss, data=payload).json()
    return responses

@app.route("/api/fetch/scan/history/vulns", methods=["POST"])
def fetchscansHistoryVulns():
    endpoint = request.json["strapi-url"]
    teamid=request.json["teams"]  
    print(endpoint) 
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]    
     endpoints = endpoint + "scan-histories?_sort=id:desc&_limit=15&&teams="+str(teamid)
    else:
     endpoints = endpoint + "scan-histories?_sort=id:desc&_limit=15"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    print(endpoints)
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    print(dictData)
    air={} #statusCheck()
    result={}
    scanlist=[]
    for item in dictData["result"]:
        for i in item['scans']:
        #    print(i)
            res={}
            count=0
            ans=[]
            totalcount={}          
            res['id']=item['id']
            res['type']=item['type']
            res['product']=item['products'][0]['name']
            res['run date']=item['runDate']  
            res['run by']=item['org_users'][0]['name']
            res['duration']=i['duration']
            res['tool']="Semgrep & Trivy"
            res['scanid']=i['id']
            res['dagid']=i['version']
            p=""
            res['status']=p
            res['count']={

                "critical":i['critical'],
                "medium":i['medium'],
                "high":i['high'],
                "low":i['low'],
                "info":i['info']
            }
            print(i['id']) 
            url=endpoint+"components?scans="+str(i['id'])

            print(endpoint)
            reshigh = requests.get(url, headers=headers).json()
            url=""
           # print(reshigh)
            giturl=reshigh[0]['githubURL']
            res['branch']=reshigh[0]['branch']
            res['repo-name']=reshigh[0]['name']
            giturl=giturl[:-4]   
            branch=giturl[4:]
            giturl=giturl[4:]
            index = giturl.find(' ') #stores the index of a substring or char
            giturl=giturl[index:]
            res['githuburl']=giturl[1:]            
            scanlist.append(res)


    result['result']=scanlist 

 




    return result


@app.route("/api/fetch/timeout", methods=["GET"])
def checkTimeout():
    time.sleep(30)
    return "timeout checked"    

def componenttoolData(url,key,duration,auth):
     endpoint = url
  
     endpoint = endpoint + "vulns?scans=" +str(key) +"&_limit=-1"
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     critical1 = 0
     high1 = 0
     info1 = 0
     medium1 = 0
     low1 = 0     
     total1=0
     total2=0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
     githuburl=res['components'][0]['githubURL']
     #print(githuburl) 
     giturl=githuburl[:-4]   
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)   
     print(giturl)    
     count1=0
     count2=0
     for index in dictData["result"]:
         print(index['file'])
         file=index['file']
         file=file[1:]
         file=file[file.find('/'):]
         url=giturl + file
         url=url[1:]
         index['githubPath']=url        
         severity.append(index)
         data = index["severity"]
         cve= index['cwe']
         print(cve)
         try:
          if(cve[1]=='V'):
      
           if data == "Critical":
             critical = critical + 1
           if data == "High":
             high = high + 1
           if data == "Medium":
             medium = medium + 1
           if data == "Info":
             info = info + 1
           if data == "Low":
             low = low + 1

          elif(cve[1]=='W'):
      
           if data == "Critical":
             critical1 = critical1 + 1
           if data == "High":
             high1 = high1 + 1
           if data == "Medium":
             medium1 = medium1 + 1
           if data == "Info":
             info1 = info1 + 1
           if data == "Low":
             low1 = low1 + 1
          else:
            if data == "Critical":
             critical1 = critical1 + 1
            if data == "High":
              high1 = high1 + 1
            if data == "Medium":
             medium1 = medium1 + 1
            if data == "Info":
             info1 = info1 + 1
            if data == "Low":
             low1 = low1 + 1

         except:
            if data == "Critical":
             critical1 = critical1 + 1
            if data == "High":
              high1 = high1 + 1
            if data == "Medium":
             medium1 = medium1 + 1
            if data == "Info":
             info1 = info1 + 1
            if data == "Low":
             low1 = low1 + 1   
            print("data")
     total = critical + high + medium + low + info
     data = {
            "semgrep": {
              "total":critical1 + high1 + medium1 + low1 + info1,
              "critical":critical1,
              "high":high1,
              "medium":medium1,
              "low":low1,
              "info":info1            },
            "trivy": {
              "total":critical + high + medium + low + info,
              "critical":critical,
              "high":high,
              "medium":medium,
              "low":low,
              "info":info      


            }
        }     
    
     return data
    

@app.route("/api/fetch/tool/vulns", methods=["POST"])
def fetchtoolVulns():
    endpoint = request.json["strapi-url"]
    scanid=    request.json['scanid']
    teamid=request.json["teams"]    
    endpoints = endpoint + "scans/"+str(scanid)
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    data={}
    a=   componenttoolData(endpoint,scanid,"2",header)
    data['severity']=a
 
    return data

def componenttimelineData(url,key,duration,auth):
     endpoint = url
  
     endpoint = endpoint + "vulns?scans=" +str(key) +"&_limit=-1"
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
     githuburl=res['components'][0]['githubURL']
     #print(githuburl) 
     giturl=githuburl[:-4]   
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)   
     print(giturl)    
     count1=0
     count2=0
     for index in dictData["result"]:
         print(index['file'])
         file=index['file']
         file=file[1:]
         file=file[file.find('/'):]
         url=giturl + file
         url=url[1:]
         index['githubPath']=url        
         severity.append(index)
         data = index["severity"]
         if data == "Critical":
             critical = critical + 1
         if data == "High":
             high = high + 1
         if data == "Medium":
             medium = medium + 1
         if data == "Info":
             info = info + 1
         if data == "Low":
             low = low + 1

       
     total = critical + high + medium + low + info
     data = {
              "total":critical + high + medium + low + info,
              "critical":critical,
              "high":high,
              "medium":medium,
              "low":low,
              "info":info
            }
        
    
     return data
    

@app.route("/api/fetch/timeline/vulns", methods=["POST"])
def fetchtimelineVulns():
    endpoint = request.json["strapi-url"]
    name=    request.json['name']
    type=request.json['type']
    branch = request.json['branch']
    if(type=='Company'):
            teamid=request.json["teams"]
            endpoints = endpoint + "components?name="+str(name)+"&&branch="+str(branch) +"&&teams="+str(teamid) 
            print(endpoints)
            header = request.json["strapi-auth"]
            headers = {"Authorization": header}
            res = requests.get(endpoints, headers=headers).json()    
            data={}
            result=[]
            for item in res:
              sol={}
              print(item['scans'])
              scanid= item['scans'][0]['id']
              dates= item['scans'][0]['created_at']
              a= componenttimelineData(endpoint,scanid,scanid,header)
              sol['date']=dates
              sol['count']=a
              result.append(sol)
            data={"result":result}
            return data     
    else:
            endpoints = endpoint + "components?name="+str(name)+"&branch="+str(branch) 
            print(endpoints)
            header = request.json["strapi-auth"]
            headers = {"Authorization": header}
            res = requests.get(endpoints, headers=headers).json()    
            data={}
            result=[]
            for item in res:
              sol={}
              scanid= item['scans'][0]['id']
              dates= item['scans'][0]['created_at']
              a= componenttimelineData(endpoint,scanid,scanid,header)
              sol['date']=dates
              sol['count']=a
              result.append(sol)
            data={"result":result}
            return data

def componentbranchData(url,key,duration,auth):
     endpoint = url

     endpoint = endpoint + "vulns?scans=" +str(key) + "&_limit=-1"
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
     githuburl=res['components'][0]['githubURL']
     #print(githuburl) 
     giturl=githuburl[:-4]   
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)   
     print(giturl)    
     count1=0
     count2=0
     for index in dictData["result"]:
         print(index['file'])
         file=index['file']
         file=file[1:]
         file=file[file.find('/'):]
         url=giturl + file
         url=url[1:]
         index['githubPath']=url        
         severity.append(index)
         data = index["severity"]
         if data == "Critical":
             critical = critical + 1
         if data == "High":
             high = high + 1
         if data == "Medium":
             medium = medium + 1
         if data == "Info":
             info = info + 1
         if data == "Low":
             low = low + 1

       
     total = critical + high + medium + low + info
     data = {
              "critical":critical,
              "high":high,
              "medium":medium,
              "low":low,
              "info":info
            }
     sol = max(data, key=data.get)
     if(critical==0 and sol=="critical"):
        sol="low"        
     
     return sol
    


@app.route("/api/fetch/branch/vulns", methods=["POST"])
def fetchbranchVulns():
    endpoint = request.json["strapi-url"]
    name=    request.json['name']
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]    
     endpoints = endpoint + "components?name="+str(name) +"&&teams="+str(teamid)
    else:
         endpoints = endpoint + "components?name="+str(name)
    print(endpoints)     
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    res = requests.get(endpoints, headers=headers).json()    
    data={}
    result=[]
    critical = 0
    high = 0
    info = 0
    medium = 0
    low = 0 
    ans={}      
 
    for item in res:
       branch=item['branch']
       print(item['scans'])
       scanid= item['scans'][0]['id']
       dates= item['scans'][0]['created_at']
       if(branch in ans.keys()):
        if(dates > ans[branch]):
            ans[branch]=dates
       else:
        ans[branch]=dates
    for item in res:
       sol={}
       branch=item['branch']
       scanid= item['scans'][0]['id']
       dates= item['scans'][0]['created_at']
       if(ans[branch]==dates):
         a= componentbranchData(endpoint,scanid,scanid,header)
         sol['branch']=branch
         sol['date']=dates
         sol['count']=a
         if a == "critical":
             critical = critical + 1
         if a == "high":
             high = high + 1
         if a == "medium":
             medium = medium + 1
         if a == "info":
             info = info + 1
         if a == "low":
             low = low + 1
         result.append(sol)
    data = {
              "critical":critical,
              "high":high,
              "medium":medium,
              "low":low,
              "info":info
            }   
    return data




@app.route("/api/fetch/top/project/vulns", methods=["POST"])
def fetchtopProjectVulns():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]          
     end=endpoint+'products?teams='+str(teamid)
    else:
     end=endpoint+'products'
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    sols = requests.get(end, headers=headers).json()
    high=0
    medium=0
    low=0
    info=0
    critical=0
    scanlist=[]
    for i in sols: #product
        res={}
        product=i['name']
        high=0
        medium=0
        low=0
        info=0
        critical=0
        res['product']=i['name']
        for j in i['components']:  # component
            print(j['id'])
            endpoints=endpoint + 'scans?components.id='+str(j['id'])
            resk = requests.get(endpoints, headers=headers).json()
            for k in resk:
                 
              if(k['info']==None):
               k['info']=0
              if(k['medium']==None):
               k['medium']=0
              if(k['low']==None):
               k['low']=0
              if(k['high']==None):
               k['high']=0 
              if(k['critical']==None):
               k['critical']=0    
              print(critical)  
              critical+=int(k['critical'])
              medium+=int(k['medium'])
              high+=int(k['high'])
              low+=int(k['low'])
              info+=int(k['info'])
        res['count']={

                "critical":critical,
                "medium":medium,
                "high":high,
                "low":low,
                "info":info,
                "total":critical+high+medium+low+info
            }          
        scanlist.append(res)
    result={}
    result['result']=scanlist       
    return result



@app.route("/api/fetch/scan/summary", methods=["POST"])
def fetchscanSummary():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]   
     endpoints1 = endpoint + "components/count?type=repo&&teams="+str(teamid)
     endpoints2 = endpoint + "components/count?type=container&&teams="+str(teamid)
    else:
          endpoints1 = endpoint + "components/count?type=repo"
          endpoints2 = endpoint + "components/count?type=container"
    header = request.json["strapi-auth"]
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints1, headers=headers).json()
    print(reshigh)


    res = requests.get(endpoints2, headers=headers).json()
    print(res)
 
    result={
        "container":res,
        "sast":reshigh,
        "sca":reshigh
    } 
    return result


@app.route("/api/fetch/code/summary", methods=["POST"])
def fetchcodeSummary():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]      
     endpoints = endpoint + "vulns?_limit=-1&&scans.teams="+str(teamid)
    else:
          endpoints = endpoint + "vulns?_limit=-1"
    header = request.json["strapi-auth"]
   
    headers = {"Authorization": header}
    cve=0
    cwe=0
    reshigh = requests.get(endpoints, headers=headers).json()
    for item in reshigh :
        severity= item['cwe']
        print(severity)
        try:
          if(severity[1]=='V'):
              cve+=1
          elif(severity[1]=='W'):
              cwe+=1
        except:
            continue; 
    result={
        "CVE":cve,
        "CWE":cwe
    } 
    return result    


@app.route("/api/fetch/vuln/timeline", methods=["POST"])
def fetchtimelineSummary():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]      
     endpoints = endpoint + "vulns?_limit=-1&&scans.teams="+str(teamid)
    else:
         endpoints = endpoint + "vulns?_limit=-1"
    header = request.json["strapi-auth"]

    headers = {"Authorization": header}
    cve=0
    cwe=0
    reshigh = requests.get(endpoints, headers=headers).json()
    ans={}
    count=0
    for item in reshigh :
        count+=1
        severity= item['created_at']
        dates=severity[:10]
        priority= item['severity']
        if dates in ans:
         ans[dates] += 1
        else:
           ans[dates]=1  
    sol=[]
    for item in ans:
        critical = 0
        high = 0
        info = 0
        medium = 0
        low = 0 
        for j in reshigh:
         severity= j['created_at']
         dates=severity[:10]      
         if(item==dates):
             if(j['severity']=='Critical'):
                 critical+=1
             if(j['severity']=='High'):
                 high+=1
             if(j['severity']=='Low'):
                 low+=1
             if(j['severity']=='Medium'):
                 medium+=1
             if(j['severity']=='Info'):
                 info+=1
     
        res={
            "date":item,
            "count":{
                "high":high,
                "medium":medium,
                "low":low,
                "critical":critical,
                "info":info
            }
        }
        sol.append(res)
    result={"result":sol}
    return result


@app.route("/api/fetch/project/list", methods=["POST"])
def fetchprojectSummary():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]        
     endpoints = endpoint + "products?teams="+str(teamid)
    else:
       endpoints = endpoint + "products"   
    header = request.json["strapi-auth"]
   
    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    ans={}
    repo=[]
    for item in reshigh:
        product= item['name']
        critical = 0
        high = 0
        info = 0
        medium = 0
        low = 0 
        count=0
        for key in item['components']:
            data={}
            type=key['type']
            data['id']=key['id']
            print(key)
            url=endpoint+'components/'+str(key['id'])
            resp=requests.get(url, headers=headers).json()
            for i in resp['scans']:
             if(i['info']==None):
              i['info']=0
             if(i['medium']==None):
              i['medium']=0
             if(i['low']==None):
              i['low']=0
             if(i['high']==None):
              i['high']=0 
             if(i['critical']==None):
               i['critical']=0    
             print(critical)  
             critical+=int(i['critical'])
             medium+=int(i['medium'])
             high+=int(i['high'])
             low+=int(i['low'])
             info+=int(i['info'])
            count+=1
        dictData = {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info
    }    
        sol = max(dictData, key=dictData.get)
        componentCount=count
        typeCount=type
        if(critical==0 and sol=="critical"):
         sol="low"
        res={"product":product,"component_count":componentCount,"integration":typeCount,"priority":sol}            
        repo.append(res)


    result={"result":repo}
    return result

@app.route("/api/fetch/crt/list", methods=["POST"])
def crtChecker():
    domain = request.json["domain"]
    teamid=request.json["teams"]    
    data=json.dumps(crtshAPI().search(domain))
    json_object = json.loads(data)
    return jsonify(json_object)


def componentlicenseData(url,key,duration,auth):
     endpoint = url
  #  try:
     endpoint = endpoint + "vulns?scans=" +str(key) +  "&_limit=-1"
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     c = 0
     critical = 0
     high = 0
     info = 0
     medium = 0
     low = 0
     result = []
     severity=[]
     endpoints=url+"scans/"+str(key)
     res = requests.get(endpoints, headers=headers).json()
    
     githuburl=res['components'][0]['githubURL']
     #print(githuburl) 
     giturl=githuburl[:-4]   
     branch=giturl[4:]
     giturl=giturl[4:]
     index = giturl.find(' ') #stores the index of a substring or char
     giturl=giturl[index:]
       # print(branch)
     branch=branch.split(' ')[0]
     giturl=giturl+"/blob/" +str(branch)      
     for index in dictData["result"]:
         file=index.get('file')
         try:
          file=file[1:]
          file=file[file.find('/'):]
          url=giturl + file
          url=url[1:]
         except:
           url="not found"   
         index['githubPath']=url        
         cwe= index['cwe']
         #print(url)
         value=""
         try:
          value = cwe[1]
         except TypeError:
          value = 'S'

         if(index['language']=='license'):
           dicts={}
           dicts['license']=index['license']
           dicts['copyright']=index['category']
           dicts['file']=index['githubPath']
           dicts['name']=index['title']
           dicts['id']=index['id']
           dicts['jiraIssueUrl']=index['jiraIssueUrl']
           dicts['jiraTicketOwner']=index['jiraTicketOwner']
           severity.append(dicts)
           print(index)
           data = index.get("severity")
           print(data)
           if data == "Critical":
             critical = critical + 1
           if data == "High":
             high = high + 1
           if data == "Medium":
             medium = medium + 1
           if data == "Info":
             info = info + 1
           if data == "Low":
             low = low + 1
      

     total = critical + high + medium + low + info
     data = {
            "duration":duration,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "total": total,
        }

     print(data)
     res={"count":data,"severity":severity}    
     result.append(res)    
     result = {"result": result}
     print("--------")
     print(result)
     return result


def scanlicenseData(url,key,auth):
    endpoint = url
    try: 
     endpoint = endpoint + "components/" +str(key)
     print(endpoint)
     header = auth
     headers = {"Authorization": header}
     reshigh = requests.get(endpoint, headers=headers).json()
     dictData = {"result": reshigh}
     #print(reshigh)
     key=dictData['result']['scans']
     value=""
     duration=""
     for k in key:
         value=k['id']
         duration=k['duration']
         start=k['startTS']
     result=componentlicenseData(url,value,duration,auth)
     print(result)
     #print(result)
     return result
     #return {"result":{}} 
    except Exception as e: 
        print(e)
        print("Ff")
        return {"result":{}} 

@app.route("/api/fetch/license/summary", methods=["POST"])
def fetchlicenseSummary():
    endpoint = request.json["strapi-url"]
    type=request.json['type']
    if(type=='Company'):
     teamid=request.json["teams"]  
     endpoints = endpoint + "products?components.type=repo&&teams="+str(teamid)
    else:
     endpoints = endpoint + "products?components.type=repo"
    header = request.json["strapi-auth"]

    headers = {"Authorization": header}
    reshigh = requests.get(endpoints, headers=headers).json()
    dictData = {"result": reshigh}
    result=[]
    for item in dictData["result"]:
        ans={}
        ans['product']=item['name']
        res=[]
        for key in item['components']:
            data={}
            type=key['type']
            if(type=='repo'):
              data['id']=key['id']
              data['name']=key['name']
              a=scanlicenseData(endpoint,key['id'],header)
              data['severity']=a
              res.append(data)
        print('--------')
        ans['component']=res
        result.append(ans)
    return jsonify(result)   

@app.route("/api/fetch/deployment/testing", methods=["POST"])
def fetchDeployment():
    result={1}
    return {"result":result}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6000, debug=True)
