import json
import os
import re
import sys
from tokenize import String
from urllib import request
import mysql.connector as mysql
import paramiko


def firewall(server_id:int,Task:String):

    host = 'localhost'   
    DATABASE = "firewall_module"
    DB_USER = "root"
    DB_PASSWORD = ""

    ### database connection ###
    db_connection = mysql.connect(host=host, database=DATABASE, user=DB_USER, password=DB_PASSWORD)
    #print("Connected to:", db_connection.get_server_info())

    if(Task=="Connect"):
        try:
            connection = mysql.connect(host=host,database=DATABASE,user=DB_USER,password=DB_PASSWORD)
            if connection.is_connected():
                db_Info = connection.get_server_info()
                #print("Connected to MySQL Server version ", db_Info)
                cursor = connection.cursor(buffered=True)
                cursor.execute("select database();")
                record = cursor.fetchone()
                #print("You're connected to database: ", record)
                #print("----------------------------------------")
                
                ###### get server IP Address ####
                query2 = ("select * FROM firewall_servers WHERE firewall_servers.id = %s AND firewall_servers.status IN (1,2,3)") 
                cursor.execute(query2,(server_id,))
                server_info = cursor.fetchall()
                print(server_info[0])
                ##### connect to the server #####
                con = paramiko.SSHClient()   
                con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                print(json.dumps({"data":"Connectiong to the Server...","code":"success"}))
                #response = '{ "code":"success", "message":"Connectiong to the Server..." }'
                #print(json.loads(response))
                try:
                    print(server_info[0][3])
                    con.connect(hostname=server_info[0][3], port=sys.argv[5], username=sys.argv[3], password=sys.argv[4], look_for_keys=False, allow_agent=False)  
                    print(json.dumps({"data":"Successfully connected to the Server","code":"success"}))
                    #response = '{ "code":"success", "message":"Successfully connected to the Server" }'
                    #print(json.loads(response))
                    
                except:
                    print(json.dumps({"data":"Cannot connect to the Server","code":"error"}))
                    #response = '{ "code":"error", "message":"Cannot connect to the Server" }'
                    #print(json.loads(response))
                    
        except :
            print(json.dumps({"data":"Cannot connect to the Server","code":"error"}))
            #response = '{ "code":"error", "message":"Cannot connect to the Server" }'
            #print(json.loads(response))

    elif(Task=="from_desktop") :
        try:
            connection = mysql.connect(host=host,database=DATABASE,user=DB_USER,password=DB_PASSWORD)
            if connection.is_connected():
                db_Info = connection.get_server_info()
                #print("Connected to MySQL Server version ", db_Info)
                cursor = connection.cursor(buffered=True)
                cursor.execute("select database();")
                record = cursor.fetchone()
                #print("You're connected to database: ", record)
                #print("----------------------------------------")
                
                query1 = ("SELECT * FROM firewall_credentials_accounts WHERE firewall_credentials_accounts.source =%s AND firewall_credentials_accounts.source_id = %s AND firewall_credentials_accounts.status IN (1,2,3)") 
                ###### get server IP Address ####
                query2 = ("select * FROM firewall_servers WHERE firewall_servers.id = %s AND firewall_servers.status IN (1,2,3)") 
                cursor.execute(query1,(1,server_id))
                ssh_credentials = cursor.fetchall()
                print(ssh_credentials[0])
                cursor.execute(query2,(server_id,))
                server_info = cursor.fetchall()
                print(server_info[0])
                ##### connect to the server #####
                con = paramiko.SSHClient()   
                con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                response = '{ "code":"success", "message":"Connectiong to the SSH Server..." }'
                print(json.loads(response))
                try:
                    ##con.connect(ip_address, operating_system, username=ssh_credentials[0][2], password=ssh_credentials[0][4], look_for_keys=False, allow_agent=False)  
                    con.connect(server_info[0][3], username=ssh_credentials[0][2], password=ssh_credentials[0][4], look_for_keys=False, allow_agent=False)  
                    response = '{ "code":"success", "message":"Successfully connected to the SSH Server" }'
                    print(json.loads(response))

                    stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[3]+' -p '+sys.argv[5]+' --dport '+sys.argv[4]+' -j '+sys.argv[6])
                    out = stdout.read()
                    stdin, stdout, stderr = con.exec_command('service iptables save')
                    stdin, stdout, stderr = con.exec_command('service iptables restart')
                    print(json.dumps({"message":"Rule added successfully","code":"success"}))

                except:
                    response = '{ "code":"error", "message":"Cannot connect to the SSH Server..." }'
                    print(json.loads(response))
                    exit()
                    
        except :
            print(json.dumps({"data":"Cannot connect to the Server","code":"error"}))
            #response = '{ "code":"error", "message":"Cannot connect to the Server" }'
            #print(json.loads(response)) 

    elif(Task=="deny") :
        try:
            connection = mysql.connect(host=host,database=DATABASE,user=DB_USER,password=DB_PASSWORD)
            if connection.is_connected():
                db_Info = connection.get_server_info()
                #print("Connected to MySQL Server version ", db_Info)
                cursor = connection.cursor(buffered=True)
                cursor.execute("select database();")
                record = cursor.fetchone()
                #print("You're connected to database: ", record)
                #print("----------------------------------------")
                
                query1 = ("SELECT * FROM firewall_credentials_accounts WHERE firewall_credentials_accounts.source =%s AND firewall_credentials_accounts.source_id = %s AND firewall_credentials_accounts.status IN (1,2,3)") 
                ###### get server IP Address ####
                query2 = ("select * FROM firewall_servers WHERE firewall_servers.id = %s AND firewall_servers.status IN (1,2,3)") 
                cursor.execute(query1,(1,server_id))
                ssh_credentials = cursor.fetchall()
                print(ssh_credentials[0])
                cursor.execute(query2,(server_id,))
                server_info = cursor.fetchall()
                print(server_info[0])

                query3 = ("SELECT * FROM firewall_rules WHERE firewall_rules.id = %s AND firewall_rules.status IN (1,2,3)") 
                cursor.execute(query3,(sys.argv[3],))
                rule = cursor.fetchall()
                print(rule[0])

                ##### connect to the server #####
                con = paramiko.SSHClient()   
                con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                response = '{ "code":"success", "message":"Connectiong to the SSH Server..." }'
                print(json.loads(response))
                try:
                    ##con.connect(ip_address, operating_system, username=ssh_credentials[0][2], password=ssh_credentials[0][4], look_for_keys=False, allow_agent=False)  
                    con.connect(server_info[0][3], username=ssh_credentials[0][2], password=ssh_credentials[0][4], look_for_keys=False, allow_agent=False)  
                    response = '{ "code":"success", "message":"Successfully connected to the SSH Server" }'
                    print(json.loads(response))
                    if rule[0][6] == 'HTTP' or rule[0][6] == 'HTTPS' or rule[0][6] == 'SSH':
                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -p tcp --dport '+rule[0][5]+' -j DROP')
                        out = stdout.read()
                    else:
                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -p '+rule[0][6]+' --dport '+rule[0][5]+' -j DROP')
                        out = stdout.read()

                    stdin, stdout, stderr = con.exec_command('service iptables save')
                    stdin, stdout, stderr = con.exec_command('service iptables restart')
                    print(json.dumps({"message":"Rule added successfully","code":"success"}))
                except:
                    response = '{ "code":"error", "message":"Cannot connect to the SSH Server..." }'
                    print(json.loads(response))
                    exit()        
        except :
            print(json.dumps({"data":"Cannot connect to the Server","code":"error"}))
            #response = '{ "code":"error", "message":"Cannot connect to the Server" }'
            #print(json.loads(response))       
    else :
    
        try:
            connection = mysql.connect(host=host,database=DATABASE,user=DB_USER,password=DB_PASSWORD)
            if connection.is_connected():
                db_Info = connection.get_server_info()
                #print("Connected to MySQL Server version ", db_Info)
                cursor = connection.cursor(buffered=True)
                cursor.execute("select database();")
                record = cursor.fetchone()
                #print("You're connected to database: ", record)
                #print("----------------------------------------")
                ###### get ssh credentials ####
                query1 = ("SELECT * FROM firewall_credentials_accounts WHERE firewall_credentials_accounts.source =%s AND firewall_credentials_accounts.source_id = %s AND firewall_credentials_accounts.status IN (1,2,3)") 
                ###### get server IP Address ####
                query2 = ("select * FROM firewall_servers WHERE firewall_servers.id = %s AND firewall_servers.status IN (1,2,3)") 
                cursor.execute(query1,(1,server_id))
                ssh_credentials = cursor.fetchall()
                cursor.execute(query2,(server_id,))
                server_info = cursor.fetchall()
                print(server_info[0])
                ##### connect to the server #####
                con = paramiko.SSHClient()   
                con.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                response = '{ "code":"success", "message":"Connectiong to the SSH Server..." }'
                print(json.loads(response))
                try:
                    ##con.connect(ip_address, operating_system, username=ssh_credentials[0][2], password=ssh_credentials[0][4], look_for_keys=False, allow_agent=False)  
                    con.connect(server_info[0][3], username=ssh_credentials[0][2], password=ssh_credentials[0][4], look_for_keys=False, allow_agent=False)  
                    response = '{ "code":"success", "message":"Successfully connected to the SSH Server" }'
                    print(json.loads(response))
                except:
                    response = '{ "code":"error", "message":"Cannot connect to the SSH Server..." }'
                    print(json.loads(response))
                    exit()


                if(Task == "check_os"):
                    try:
                        stdin, stdout, stderr = con.exec_command("cat /etc/*-release")
                        os_version = stdout.readline()
                        out = os_version.split()
                        global OperatingSystem
                        global SystemVersion
                        OperatingSystem = out[0]
                        if out[2][0] == "6":
                            SystemVersion = out[2][0]
                        else :
                            SystemVersion = out[3]
                        print(json.dumps({"data":[OperatingSystem,SystemVersion[0]],"code":"success"}))
                        #response = '{ "code":"success", "message":"'+OperatingSystem+','+SystemVersion[0]+'" }'
                        #print(json.loads(response))
                    except:
                        #print(json.dumps({"data":"Error... OS NOT SUPPORTED !","code":"error"}))
                        #response = '{ "code":"error", "message":"Error... OS NOT SUPPORTED !" }'
                        #print(json.loads(response))
                        try:
                            stdin, stdout, stderr = con.exec_command("cat /etc/os-release")
                            data = stdout.readlines()
                            OperatingSystem = (data[0].split("="))[1]
                            SystemVersion = (data[1].split("="))[1]
                            if "openSUSE" in json.loads(OperatingSystem) :
                                OperatingSystem1 = "openSUSE"
                            SystemVersion1 = json.loads(SystemVersion)
                            print(json.dumps({"data":[OperatingSystem1,SystemVersion1],"code":"success"}))
                        except:
                            print(json.dumps({"data":"Error... OS NOT SUPPORTED !","code":"error"}))
                else:
                    try:
                        try:
                            stdin, stdout, stderr = con.exec_command("cat /etc/*-release")
                            os_version = stdout.readline()
                            out = os_version.split()
                            OperatingSystem = out[0]
                            if out[2][0] == "6":
                                SystemVersion = out[2][0]
                            else :
                                SystemVersion = out[3]
                            
                            print(json.dumps({"data":[OperatingSystem,SystemVersion],"code":"success"}))

                        except:
                            try:
                                stdin, stdout, stderr = con.exec_command("cat /etc/os-release")
                                data = stdout.readlines()
                                OperatingSystem = (data[0].split("="))[1]
                                SystemVersion = (data[1].split("="))[1]
                                print(json.dumps({"data":[OperatingSystem,SystemVersion],"code":"success"}))
                                #response = '{ "code":"success", "message":"'+OperatingSystem+','+SystemVersion[0]+'" }'
                                #print(json.loads(response))
                            except:
                                print(json.dumps({"data":"Error... OS NOT SUPPORTED !","code":"error"}))


                        if OperatingSystem=="CentOS" and int(SystemVersion[0])== 7:
                        ##### Add rule #####
                            if(Task == "add"):  
                                try:
                                    if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[3]+' -p tcp --dport '+sys.argv[5]+' -j '+sys.argv[6])
                                        #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[3]+' --dport '+sys.argv[5]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[6])
                                        out = stdout.read()
                                        #print(out)
                                        #response = '{ "code":"success", "message":"Rule added successfully" }'
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule added successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[3]+' -p '+sys.argv[4]+' --dport '+sys.argv[5]+' -j '+sys.argv[6])
                                        #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[3]+' --dport '+sys.argv[5]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[6])
                                        out = stdout.read()
                                        #print(out)
                                        #response = '{ "code":"success", "message":"Rule added successfully" }'
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule added successfully","code":"success"}))
                                except:
                                    #response = '{ "code":"error", "message":"Error... Add rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Add rule failed","code":"error"}))
                                    
                            ##### Edit rule #####
                            elif(Task == "edit"):
                                try:
                                    #### get the selected rule ####
                                    query2 = ("SELECT * FROM firewall_rules WHERE firewall_rules.id=%s")
                                    cursor.execute(query2,(sys.argv[3],))
                                    r = cursor.fetchall()
                                    print(r[0])
                                    if r[0][6] == 'HTTP' or r[0][6] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+r[0][3]+' -p tcp --dport '+r[0][5]+' -j '+r[0][1])
                                        if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p tcp --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p '+sys.argv[4]+' --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+r[0][3]+' -p '+r[0][6]+' --dport '+r[0][5]+' -j '+r[0][1])
                                        if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p tcp --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p '+sys.argv[4]+' --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                except:
                                    print(json.dumps({"message":"Error... Edit rule failed","code":"error"}))
                                    

                            ##### Delete rule #####
                            elif(Task == "delete"):
                            
                                try:
                                    
                                    query2 = ("SELECT * FROM firewall_rules WHERE firewall_rules.id=%s")
                                    cursor.execute(query2,(sys.argv[3],))
                                    records = cursor.fetchall()
                                    #print(records[0][1],records[0][3])
                                    if records[0][6] == 'HTTP' or records[0][6] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+records[0][3]+' -p tcp --dport '+records[0][5]+' -j '+records[0][1])
                                        #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 66.66.66.66/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                        output = stdout.read()
                                        #print(output)
                                        #response = '{ "code":"success", "message":"Rule deleted successfully" }'
                                        #print(json.loads(response))
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule deleted successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+records[0][3]+' -p '+records[0][6]+' --dport '+records[0][5]+' -j '+records[0][1])
                                        #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 66.66.66.66/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                        output = stdout.read()
                                        #print(output)
                                        #response = '{ "code":"success", "message":"Rule deleted successfully" }'
                                        #print(json.loads(response))
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule deleted successfully","code":"success"}))
                                
                                    #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 196.179.158.204/32 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')

                                except:
                                    #response = '{ "code":"error", "message":"Error... Delete rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Delete rule failed","code":"error"}))
                                    

                            ##### List rules #####
                            elif(Task == "list"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    rules = stdout.readlines()
                                    print(rules)
                                except:
                                    #response = '{ "code":"error", "message":"Error... !" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... !","code":"error"}))
                        
                            elif(Task == "check"): 
                                r_source = '197.1.49.81'
                                r_protocol='http'
                                r_port = '80'
                                r_action='DENY'
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    output = stdout.readlines()
                                    ##print(output)
                                    rule_match = [s for s in output if r_source in s]
                                    #rule_match = [s for s in output if (sys.argv[3] or sys.argv[4]) in s]
                                    if(len(rule_match) != 0):
                                        #response = '{ "code":"success", "message":"%s" }'%rule_match
                                        print(json.dumps({"message":"success","code":rule_match}))
                                    else :
                                        #response = '{ "code":"error", "message":"Rule does not exists in iptables... !" }'
                                        #print(json.loads(response))
                                        print(json.dumps({"message":"Rule does not exists in iptables... !","code":"error"}))
                                except:
                                    print(json.dumps({"message":"Error... !","code":"error"}))
                                    #response = '{ "code":"error", "message":"Error ... !" }'
                                    #print(json.loads(response))
                        
                            elif(Task == "accesslogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo tail -100 /usr/local/apache/logs/access_log")
                                    access_logs = stdout.readlines()
                                    out = []
                                    for i in access_logs:
                                        i.split()
                                        out.append(re.split(r'"|- -',i))
                                    print(json.dumps({"data":out,"code":"success"}))

                                except:
                                    print(json.dumps({"message":"Error... !","code":"error"}))
                                    #response = '{ "code":"error", "message":"Error... !" }'
                                    #print(json.loads(response))
                        
                            elif(Task == "securelogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo head -10 /var/log/secure")
                                    secure_logs = stdout.readlines()
                                    output = []
                                    for i in secure_logs:
                                        out = i.split()
                                        output.append(out)
                                        response = '{ "code":"success", "message":"%s" }'%output
                                    print(response)
                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "csf"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.deny")
                                    csf_deny = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.allow")
                                    csf_allow = stdout.readlines()
                                    output = []
                                    output1 = []
                                    for i in csf_deny:
                                        out = re.findall("^#",i)
                                        if not out:
                                            output.append(i.split())

                                    for j in csf_allow:
                                        out = re.findall("^#",j)
                                        if not out:
                                            output1.append(j.split())

                                    print(json.dumps({'data':(output,output1),'code' : "success"}))

                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "openedports"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.conf")
                                    csf_conf = stdout.readlines()
                                    output = []
                                    for i in csf_conf:
                                        x = re.findall("^TCP_IN",i)
                                        y = re.findall("^TCP_OUT",i)
                                        z = re.findall("^UDP_IN",i)
                                        w = re.findall("^UDP_OUT",i)
                                        if (x or y or z or w) :
                                            output.append(i)
                                            response = json.dumps({'data':output,'code' : "success"})
                                    print(response)
                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "services"):
                        
                                try:

                                    stdin, stdout, stderr = con.exec_command("service httpd status")
                                    service1 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service nginx status")
                                    service2 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service vsftpd status")
                                    service3 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service mysqld status")
                                    service4 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service mariadb status")
                                    service5 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service sshd status")
                                    service6 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service crond status")
                                    service7 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service firewalld status")
                                    service8 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service csf status")
                                    service9 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service fail2ban status")
                                    service10 = stdout.readlines()

                                    if service1 == [] or "could not be found" in str(service1):
                                        response1 = "Unknown"
                                        print("Unknown")
                                    elif "running" in str(service1) :
                                        response1 = "Active"
                                        print("Active")
                                    elif "stopped" in str(service1) :
                                        response1 = "Stopped"
                                    elif "disabled" in str(service1) :
                                        response1 = "Disabled"
                                        print("Disabled")
                                    if service2 == [] or "could not be found" in str(service2):
                                        response2 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service2) :
                                        response2 = "Stopped"
                                    elif "running" in str(service2) :
                                        response2 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service2) :
                                        response2 = "Disabled"
                                        print("Disabled")
                                    if service3 == [] or "could not be found" in str(service3):
                                        response3 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service3) :
                                        response3 = "Stopped"
                                    elif "running" in str(service3) :
                                        response3 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service3) :
                                        response3 = "Disabled"
                                        print("Disabled")
                                    if service4 == [] or "could not be found" in str(service4):
                                        response4 = "Unknown"
                                        print("Unknown")

                                    elif "running" in str(service4) :
                                        response4 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service4) :
                                        response4 = "Disabled"
                                        print("Disabled")
                                    if service5 == [] or "could not be found" in str(service5):
                                        response5 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service5) :
                                        response5 = "Stopped"
                                    elif "running" in str(service5) :
                                        response5 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service5) :
                                        response5 = "Disabled"
                                        print("Disabled")
                                    if service6 == [] or "could not be found" in str(service6):
                                        response6 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service6) :
                                        response6 = "Stopped"
                                    elif "running" in str(service6) :
                                        response6 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service6) :
                                        response6 = "Disabled"
                                        print("Disabled")
                                    if service7 == [] or "could not be found" in str(service7):
                                        response7 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service7) :
                                        response7 = "Stopped"
                                    elif "running" in str(service7) :
                                        response7 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service7) :
                                        response7 = "Disabled"
                                        print("Disabled")
                                    if service8 == [] or "could not be found" in str(service8):
                                        response8 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service8) :
                                        response8 = "Stopped"
                                    elif "Table:" or "Chain" in str(service8) :
                                        response8 = "Active"
                                        print("Active")
                                    elif "disabled" or "dead" in str(service8) :
                                        response8 = "Disabled"
                                        print("Disabled")
                                    if service9 == [] or "could not be found" in str(service9):
                                        response9 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service9) :
                                        response9 = "Stopped"
                                    elif "running" in str(service9) :
                                        response9 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service9) :
                                        response9 = "Disabled"
                                        print("Disabled")
                                    if service10 == [] or "could not be found" in str(service10):
                                        response10 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service10) :
                                        response10 = "Stopped"
                                    elif "running" in str(service10) :
                                        response10 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service10) :
                                        response10 = "Disabled"
                                        print("Disabled")

                                    response = json.dumps({'data':[["Apache Web Server",response1],["Nginx Web Server",response2],["FTP Server",response3],["MySQL Database Server",response4],["Mariadb Database Server",response5],["SSH Server",response6],["Crontab",response7],["Iptables Firewall",response8],["ConfigServer Security & Firewall",response9],["Intrusion Prevention System",response10]],'code' : "success"})
                                    print(response)

                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))
                            
                            elif(Task == "restartservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld restart")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server restarted successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service firewalld restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -e")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                            elif(Task == "startservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld start")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server started successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service firewalld start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -s")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                            elif(Task == "stopservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld stop")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server stopped successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service firewalld stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -x")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                        
                            elif(Task == "checkport"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('nmap '+sys.argv[3]+' -p '+sys.argv[4])
                                    output = stdout.readlines()
                                    if "STATE" and "open" in str(output):
                                        print(json.dumps({'data':"This port is reachable",'code' : "success"}))
                                    else:
                                        print(json.dumps({'data':"This port is not reachable",'code' : "success"}))
                                except:
                                    print(json.dumps({'data':"Error",'code' : "error"}))
                                
                        
                            elif(Task == "checkip"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    output = stdout.readlines()
                                    ##print(output)
                                    rule_match = [s for s in output if sys.argv[3] in s]

                                    stdin, stdout, stderr = con.exec_command('host '+sys.argv[3])
                                    output1 = stdout.readlines()

                                    if(len(rule_match) != 0):
                                        #response = '{ "code":"success", "message":"%s" }'%rule_match
                                        print(json.dumps({"code":"success","data":"IP Adress exists in iptables \n"+str(rule_match)}))
                                    elif "name pointer" in str(output1):
                                        print(json.dumps({"code":"success","data":str(output1)}))

                                    else :
                                        #response = '{ "code":"error", "message":"Rule does not exists in iptables... !" }'
                                        #print(json.loads(response))
                                        print(json.dumps({"data":"IP Address NOT found","code":"error"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "installservice"):
                                if sys.argv[3] == "Intrusion Prevention System":
                                    try:

                                        stdin, stdout, stderr = con.exec_command('yum install fail2ban')
                                        output1 = stdout.readlines()

                                        stdin, stdout, stderr = con.exec_command('systemctl enable fail2ban')
                                        output2 = stdout.readlines()

                                        stdin, stdout, stderr = con.exec_command('systemctl start fail2ban')
                                        output3 = stdout.readlines()

                                        response = json.dumps({'data':"fail2ban started successfully",'code' : "success"})
                                        print(response)

                                    except:
                                        response = '{ "code":"error", "message":"Error ... !" }'
                                        print(json.loads(response))

                            elif(Task == "fail2banlogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('sudo cat /var/log/fail2ban.log')
                                    logs = stdout.readlines()
                                    output=[]
                                    for i in logs:
                                        output.append(i.split(" ",2))
                                    print(json.dumps({'data':output,'code' : "success"}))

                                except:
                                    print(json.dumps({'data':'Error','code' : "Error"}))
                        
                            elif(Task == "fail2banIPbanned"):
                                try:
                                    search_term = 'Ban'
                                    stdin, stdout, stderr = con.exec_command('sudo zgrep '+search_term+' /var/log/fail2ban.log')
                                    banned_ips = stdout.readlines()
                                    output = []
                                    for i in banned_ips:

                                        output.append(i.split(" ",2))
                                        print(output)
                                    print(json.dumps({'data':output,'code' : "success"}))

                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))

                            elif(Task == "addurl"):
                                try:
                                    url_to_protect = sys.argv[3]
                                    ip_add = sys.argv[4]
                                    stdin, stdout, stderr = con.exec_command('ls -a '+url_to_protect+'')
                                    output = stdout.readlines()
                                    if "htaccess" in str(output):
                                        #stdin, stdout, stderr = con.exec_command('touch '+url_to_protect+'/.htaccess')
                                        #stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+url_to_protect+'/.htaccess')
                                        #stdin, stdout, stderr = con.exec_command('echo deny from all >> '+url_to_protect+'/.htaccess')
                                        query = ("SELECT * FROM firewall_url_protection WHERE firewall_url_protection.ip_address=%s and firewall_url_protection.status IN (1,2,3)")
                                        cursor.execute(query,(sys.argv[4],))
                                        r = cursor.fetchall()
                                        print(r)
                                        if ip_add in str(r):
                                            print(json.dumps({'data':"IP Address already exists",'code' : "success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('echo "\nallow from '+ip_add+'" >> '+url_to_protect+'/.htaccess')
                                            print(json.dumps({'data':"URL added successfully",'code' : "success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('touch '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo deny from all >> '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo allow from '+ip_add+' >> '+url_to_protect+'/.htaccess')

                                        print(json.dumps({'data':"URL added successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "updateurl"):
                                try:
                                    query = ("SELECT * FROM firewall_url_protection WHERE firewall_url_protection.id=%s")
                                    cursor.execute(query,(sys.argv[3],))
                                    r = cursor.fetchall()
                                    stdin, stdout, stderr = con.exec_command('rm -f '+r[0][2]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('touch '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo deny from all >> '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo allow from '+sys.argv[5]+' >> '+sys.argv[4]+'/.htaccess')

                                    print(json.dumps({'data':"URL updated successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                            
                            elif(Task == "deleteurl"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('rm -f '+sys.argv[3]+'/.htaccess')
                                    print(json.dumps({'data':"URL delete successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                
                            else:
                                response = '{ "code":"error", "message":"Function not defined!" }'
                                print(json.loads(response))   

                        elif OperatingSystem=="CentOS" and int(SystemVersion[0]) == 6:
                        ##### Add rule #####
                            if(Task == "add"):  
                                try:
                                    if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[3]+' -p tcp --dport '+sys.argv[5]+' -j '+sys.argv[6])
                                        #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[3]+' --dport '+sys.argv[5]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[6])
                                        out = stdout.read()
                                        #print(out)
                                        #response = '{ "code":"success", "message":"Rule added successfully" }'
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule added successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[3]+' -p '+sys.argv[4]+' --dport '+sys.argv[5]+' -j '+sys.argv[6])
                                        #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[3]+' --dport '+sys.argv[5]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[6])
                                        out = stdout.read()
                                        #print(out)
                                        #response = '{ "code":"success", "message":"Rule added successfully" }'
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule added successfully","code":"success"}))
                                except:
                                    #response = '{ "code":"error", "message":"Error... Add rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Add rule faaaaaailed","code":"error"}))
                                    
                            ##### Edit rule #####
                            elif(Task == "edit"):
                                try:
                                    #### get the selected rule ####
                                    query2 = ("SELECT * FROM firewall_rules WHERE firewall_rules.id=%s")
                                    cursor.execute(query2,(sys.argv[3],))
                                    r = cursor.fetchall()
                                    print(r[0])
                                    if r[0][6] == 'HTTP' or r[0][6] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+r[0][3]+' -p tcp --dport '+r[0][5]+' -j '+r[0][1])
                                        if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p tcp --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p '+sys.argv[4]+' --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+r[0][3]+' -p '+r[0][6]+' --dport '+r[0][5]+' -j '+r[0][1])
                                        if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p tcp --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p '+sys.argv[4]+' --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                except:
                                    #response = '{ "code":"error", "message":"Error... Edit rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Edit rule failed","code":"error"}))
                                    exit()

                        ##### Delete rule #####
                            elif(Task == "delete"):
                            
                                try:
                                
                                    query2 = ("SELECT * FROM firewall_rules WHERE firewall_rules.id=%s")
                                    cursor.execute(query2,(sys.argv[3],))
                                    records = cursor.fetchall()
                                    #print(records[0][1],records[0][3])
                                    if records[0][6] == 'HTTP' or records[0][6] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+records[0][3]+' -p tcp --dport '+records[0][5]+' -j '+records[0][1])
                                        #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 66.66.66.66/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                        output = stdout.read()
                                        #print(output)
                                        #response = '{ "code":"success", "message":"Rule deleted successfully" }'
                                        #print(json.loads(response))
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule deleted successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+records[0][3]+' -p '+records[0][6]+' --dport '+records[0][5]+' -j '+records[0][1])
                                        #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 66.66.66.66/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                        output = stdout.read()
                                        #print(output)
                                        #response = '{ "code":"success", "message":"Rule deleted successfully" }'
                                        #print(json.loads(response))
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule deleted successfully","code":"success"}))
                                
                                    #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 196.179.158.204/32 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                except:
                                    #response = '{ "code":"error", "message":"Error... Delete rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Delete rule failed","code":"error"}))
                                    exit()

                        ##### List rules #####
                            elif(Task == "list"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    rules = stdout.readlines()
                                    print(rules)
                                except:
                                    #response = '{ "code":"error", "message":"Error... !" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... !","code":"error"}))
                        
                            elif(Task == "check"): 
                                r_source = '197.1.49.81'
                                r_protocol='http'
                                r_port = '80'
                                r_action='DENY'
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    output = stdout.readlines()
                                    ##print(output)
                                    rule_match = [s for s in output if r_source in s]
                                    #rule_match = [s for s in output if (sys.argv[3] or sys.argv[4]) in s]
                                    if(len(rule_match) != 0):
                                        #response = '{ "code":"success", "message":"%s" }'%rule_match
                                        print(json.dumps({"message":"success","code":rule_match}))
                                    else :
                                        #response = '{ "code":"error", "message":"Rule does not exists in iptables... !" }'
                                        #print(json.loads(response))
                                        print(json.dumps({"message":"Rule does not exists in iptables... !","code":"error"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "accesslogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo tail -100 /usr/local/apache/logs/access_log")
                                    access_logs = stdout.readlines()
                                    out = []
                                    for i in access_logs:
                                        i.split()
                                        out.append(re.split(r'"|- -',i))
                                    print(json.dumps({"data":out,"code":"success"}))
                                
                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "securelogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo head -10 /var/log/secure")
                                    secure_logs = stdout.readlines()
                                    output = []
                                    for i in secure_logs:
                                        out = i.split()
                                        output.append(out)
                                        response = '{ "code":"success", "message":"%s" }'%output
                                    print(response)
                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "csf"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.deny")
                                    csf_deny = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.allow")
                                    csf_allow = stdout.readlines()
                                    output = []
                                    output1 = []
                                    for i in csf_deny:
                                        out = re.findall("^#",i)
                                        if not out:
                                            output.append(i.split())

                                    for j in csf_allow:
                                        out = re.findall("^#",j)
                                        if not out:
                                            output1.append(j.split())

                                    print(json.dumps({'data':(output,output1),'code' : "success"}))

                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "openedports"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.conf")
                                    csf_conf = stdout.readlines()
                                    output = []
                                    for i in csf_conf:
                                        x = re.findall("^TCP_IN",i)
                                        y = re.findall("^TCP_OUT",i)
                                        z = re.findall("^UDP_IN",i)
                                        w = re.findall("^UDP_OUT",i)
                                        if (x or y or z or w) :
                                            output.append(i)
                                            response = json.dumps({'data':output,'code' : "success"})
                                    print(response)
                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "services"):
                                try:

                                    stdin, stdout, stderr = con.exec_command("service httpd status")
                                    service1 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service nginx status")
                                    service2 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service vsftpd status")
                                    service3 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service mysqld status")
                                    service4 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service mariadb status")
                                    service5 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service sshd status")
                                    service6 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service crond status")
                                    service7 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service iptables status")
                                    service8 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service csf status")
                                    service9 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service fail2ban status")
                                    service10 = stdout.readlines()

                                    if service1 == [] or "could not be found" in str(service1):
                                        response1 = "Unknown"
                                        print("Unknown")
                                    elif "running" in str(service1) :
                                        response1 = "Active"
                                        print("Active")
                                    elif "stopped" in str(service1) :
                                        response1 = "Stopped"
                                    elif "disabled" in str(service1) :
                                        response1 = "Disabled"
                                        print("Disabled")
                                    if service2 == [] or "could not be found" in str(service2):
                                        response2 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service2) :
                                        response2 = "Stopped"
                                    elif "running" in str(service2) :
                                        response2 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service2) :
                                        response2 = "Disabled"
                                        print("Disabled")
                                    if service3 == [] or "could not be found" in str(service3):
                                        response3 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service3) :
                                        response3 = "Stopped"
                                    elif "running" in str(service3) :
                                        response3 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service3) :
                                        response3 = "Disabled"
                                        print("Disabled")
                                    if service4 == [] or "could not be found" in str(service4):
                                        response4 = "Unknown"
                                        print("Unknown")

                                    elif "running" in str(service4) :
                                        response4 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service4) :
                                        response4 = "Disabled"
                                        print("Disabled")
                                    if service5 == [] or "could not be found" in str(service5):
                                        response5 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service5) :
                                        response5 = "Stopped"
                                    elif "running" in str(service5) :
                                        response5 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service5) :
                                        response5 = "Disabled"
                                        print("Disabled")
                                    if service6 == [] or "could not be found" in str(service6):
                                        response6 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service6) :
                                        response6 = "Stopped"
                                    elif "running" in str(service6) :
                                        response6 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service6) :
                                        response6 = "Disabled"
                                        print("Disabled")
                                    if service7 == [] or "could not be found" in str(service7):
                                        response7 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service7) :
                                        response7 = "Stopped"
                                    elif "running" in str(service7) :
                                        response7 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service7) :
                                        response7 = "Disabled"
                                        print("Disabled")
                                    if service8 == [] or "could not be found" in str(service8):
                                        response8 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service8) :
                                        response8 = "Stopped"
                                    elif "Table:" or "Chain" in str(service8) :
                                        response8 = "Active"
                                        print("Active")
                                    elif "disabled" or "dead" in str(service8) :
                                        response8 = "Disabled"
                                        print("Disabled")
                                    if service9 == [] or "could not be found" in str(service9):
                                        response9 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service9) :
                                        response9 = "Stopped"
                                    elif "running" in str(service9) :
                                        response9 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service9) :
                                        response9 = "Disabled"
                                        print("Disabled")
                                    if service10 == [] or "could not be found" in str(service10):
                                        response10 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service10) :
                                        response10 = "Stopped"
                                    elif "running" in str(service10) :
                                        response10 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service10) :
                                        response10 = "Disabled"
                                        print("Disabled")

                                    response = json.dumps({'data':[["Apache Web Server",response1],["Nginx Web Server",response2],["FTP Server",response3],["MySQL Database Server",response4],["Mariadb Database Server",response5],["SSH Server",response6],["Crontab",response7],["Iptables Firewall",response8],["ConfigServer Security & Firewall",response9],["Intrusion Prevention System",response10]],'code' : "success"})
                                    print(response)

                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "restartservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld restart")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server restarted successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service iptables restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -e")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                            elif(Task == "startservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld start")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server started successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service iptables start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -s")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                            elif(Task == "stopservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld stop")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server stopped successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service iptables stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -x")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                        
                            elif(Task == "checkport"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('nmap '+sys.argv[3]+' -p '+sys.argv[4])
                                    output = stdout.readlines()
                                    if "STATE" and "open" in str(output):
                                        print(json.dumps({'data':"This port is reachable",'code' : "success"}))
                                    else:
                                        print(json.dumps({'data':"This port is not reachable",'code' : "success"}))
                                except:
                                    print(json.dumps({'data':"Error",'code' : "error"}))
                                
                            elif(Task == "checkip"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    output = stdout.readlines()
                                    ##print(output)
                                    rule_match = [s for s in output if sys.argv[3] in s]

                                    stdin, stdout, stderr = con.exec_command('host '+sys.argv[3])
                                    output1 = stdout.readlines()

                                    if(len(rule_match) != 0):
                                        #response = '{ "code":"success", "message":"%s" }'%rule_match
                                        print(json.dumps({"code":"success","data":"IP Adress exists in iptables \n"+str(rule_match)}))
                                    elif "name pointer" in str(output1):
                                        print(json.dumps({"code":"success","data":str(output1)}))

                                    else :
                                        #response = '{ "code":"error", "message":"Rule does not exists in iptables... !" }'
                                        #print(json.loads(response))
                                        print(json.dumps({"data":"IP Address NOT found","code":"error"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "installservice"):
                                if sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command('yum install fail2ban')
                                        output1 = stdout.readlines()

                                        stdin, stdout, stderr = con.exec_command('systemctl enable fail2ban')
                                        output2 = stdout.readlines()

                                        stdin, stdout, stderr = con.exec_command('systemctl start fail2ban')
                                        output3 = stdout.readlines()

                                        response = json.dumps({'data':"fail2ban started successfully",'code' : "success"})
                                        print(response)

                                    except:
                                        response = '{ "code":"error", "message":"Error ... !" }'
                                        print(json.loads(response))
                        
                            elif(Task == "fail2banlogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('sudo cat /var/log/fail2ban.log')
                                    logs = stdout.readlines()
                                    output=[]
                                    for i in logs:
                                        output.append(i.split(" ",2))
                                    print(json.dumps({'data':output,'code' : "success"}))

                                except:
                                    print(json.dumps({'data':'Error','code' : "Error"}))
                        
                            elif(Task == "fail2banIPbanned"):
                                try:
                                    search_term = 'Ban'
                                    stdin, stdout, stderr = con.exec_command('sudo zgrep '+search_term+' /var/log/fail2ban.log')
                                    banned_ips = stdout.readlines()
                                    output = []
                                    for i in banned_ips:
                                        output.append(i.split(" ",2))
                                        print(output)
                                        print(json.dumps({'data':output,'code' : "success"}))
                                    
                                    print(json.dumps({'data':output,'code' : "success"}))

                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))

                            elif(Task == "addurl"):
                                try:
                                    url_to_protect = sys.argv[3]
                                    ip_add = sys.argv[4]
                                    stdin, stdout, stderr = con.exec_command('ls -a '+url_to_protect+'')
                                    output = stdout.readlines()
                                    if "htaccess" in str(output):
                                        #stdin, stdout, stderr = con.exec_command('touch '+url_to_protect+'/.htaccess')
                                        #stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+url_to_protect+'/.htaccess')
                                        #stdin, stdout, stderr = con.exec_command('echo deny from all >> '+url_to_protect+'/.htaccess')
                                        query = ("SELECT * FROM firewall_url_protection WHERE firewall_url_protection.ip_address=%s and firewall_url_protection.status IN (1,2,3)")
                                        cursor.execute(query,(sys.argv[4],))
                                        r = cursor.fetchall()
                                        print(r)
                                        if ip_add in str(r):
                                            print(json.dumps({'data':"IP Address already exists",'code' : "success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('echo "\nallow from '+ip_add+'" >> '+url_to_protect+'/.htaccess')
                                            print(json.dumps({'data':"URL added successfully",'code' : "success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('touch '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo deny from all >> '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo allow from '+ip_add+' >> '+url_to_protect+'/.htaccess')

                                        print(json.dumps({'data':"URL added successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "updateurl"):
                                try:
                                    query = ("SELECT * FROM firewall_url_protection WHERE firewall_url_protection.id=%s")
                                    cursor.execute(query,(sys.argv[3],))
                                    r = cursor.fetchall()
                                    stdin, stdout, stderr = con.exec_command('rm -f '+r[0][2]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('touch '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo deny from all >> '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo allow from '+sys.argv[5]+' >> '+sys.argv[4]+'/.htaccess')

                                    print(json.dumps({'data':"URL updated successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                            
                            elif(Task == "deleteurl"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('rm -f '+sys.argv[3]+'/.htaccess')
                                    print(json.dumps({'data':"URL delete successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))

                            else:
                                response = '{ "code":"error", "message":"Function not defined!" }'
                                print(json.loads(response))   

                        elif "openSUSE Leap" in OperatingSystem and "15.3" in SystemVersion:
                        ##### Add rule #####
                            if(Task == "add"):  
                                try:
                                    if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[3]+' -p tcp --dport '+sys.argv[5]+' -j '+sys.argv[6])
                                        #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[3]+' --dport '+sys.argv[5]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[6])
                                        out = stdout.read()
                                        print("aaaaaaaaaa")
                                        #response = '{ "code":"success", "message":"Rule added successfully" }'
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print("bbbbbbbbb")
                                        print(json.dumps("00000000000000000000000000"))

                                        print(json.dumps({"message":"Rule added successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[3]+' -p '+sys.argv[4]+' --dport '+sys.argv[5]+' -j '+sys.argv[6])
                                        #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[3]+' --dport '+sys.argv[5]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[6])
                                        out = stdout.read()
                                        print("ccccccccccccccc")
                                        #print(out)
                                        #response = '{ "code":"success", "message":"Rule added successfully" }'
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps("1111111111111111111111"))
                                        print("ddddddddddddddddd")
                                        print(json.dumps({"message":"Rule added successfully","code":"success"}))
                                except:
                                    #response = '{ "code":"error", "message":"Error... Add rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Add rule failed","code":"error"}))
                                    
                            ##### Edit rule #####
                            elif(Task == "edit"):
                                try:
                                    #### get the selected rule ####
                                    query2 = ("SELECT * FROM firewall_rules WHERE firewall_rules.id=%s")
                                    cursor.execute(query2,(sys.argv[3],))
                                    r = cursor.fetchall()
                                    print(r[0])
                                    if r[0][6] == 'HTTP' or r[0][6] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+r[0][3]+' -p tcp --dport '+r[0][5]+' -j '+r[0][1])
                                        if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p tcp --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p '+sys.argv[4]+' --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+r[0][3]+' -p '+r[0][6]+' --dport '+r[0][5]+' -j '+r[0][1])
                                        if sys.argv[4] == 'HTTP' or sys.argv[4] == 'HTTPS':
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p tcp --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p tcp -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('iptables -I INPUT -s '+sys.argv[5]+' -p '+sys.argv[4]+' --dport '+sys.argv[6]+' -j '+sys.argv[7])
                                            #stdin, stdout, stderr = con.exec_command('iptables -A INPUT -p '+sys.argv[4]+' -s '+sys.argv[5]+' --dport '+sys.argv[6]+' -m conntrack --ctstate NEW,ESTABLISHED -j '+sys.argv[7])
                                            output = stdout.read()
                                            stdin, stdout, stderr = con.exec_command('service iptables save')
                                            stdin, stdout, stderr = con.exec_command('service iptables restart')
                                            print(json.dumps({"message":"Rule edited successfully","code":"success"}))
                                except:
                                    #response = '{ "code":"error", "message":"Error... Edit rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Edit rule failed","code":"error"}))
                                    exit()

                        ##### Delete rule #####
                            elif(Task == "delete"):
                                try:
                                    query2 = ("SELECT * FROM firewall_rules WHERE firewall_rules.id=%s")
                                    cursor.execute(query2,(sys.argv[3],))
                                    records = cursor.fetchall()
                                    #print(records[0][1],records[0][3])
                                    if records[0][6] == 'HTTP' or records[0][6] == 'HTTPS':
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+records[0][3]+' -p tcp --dport '+records[0][5]+' -j '+records[0][1])
                                        #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 66.66.66.66/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                        output = stdout.read()
                                        #print(output)
                                        #response = '{ "code":"success", "message":"Rule deleted successfully" }'
                                        #print(json.loads(response))
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule deleted successfully","code":"success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s '+records[0][3]+' -p '+records[0][6]+' --dport '+records[0][5]+' -j '+records[0][1])
                                        #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 66.66.66.66/32 -p tcp -m tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                        output = stdout.read()
                                        #print(output)
                                        #response = '{ "code":"success", "message":"Rule deleted successfully" }'
                                        #print(json.loads(response))
                                        stdin, stdout, stderr = con.exec_command('service iptables save')
                                        stdin, stdout, stderr = con.exec_command('service iptables restart')
                                        print(json.dumps({"message":"Rule deleted successfully","code":"success"}))
                                    
                                    #stdin, stdout, stderr = con.exec_command('iptables -D INPUT -s 196.179.158.204/32 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT')
                                except:
                                    #response = '{ "code":"error", "message":"Error... Delete rule failed" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... Delete rule failed","code":"error"}))
                                    exit()

                        ##### List rules #####
                            elif(Task == "list"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    rules = stdout.readlines()
                                    print(rules)
                                    print(json.dumps({"data":rules,"code":"success"}))
                                except:
                                    #response = '{ "code":"error", "message":"Error... !" }'
                                    #print(json.loads(response))
                                    print(json.dumps({"message":"Error... !","code":"error"}))
                        
                            elif(Task == "check"): 
                                r_source = '197.1.49.81'
                                r_protocol='http'
                                r_port = '80'
                                r_action='DENY'
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    output = stdout.readlines()
                                    ##print(output)
                                    rule_match = [s for s in output if r_source in s]
                                    #rule_match = [s for s in output if (sys.argv[3] or sys.argv[4]) in s]
                                    if(len(rule_match) != 0):
                                        #response = '{ "code":"success", "message":"%s" }'%rule_match
                                        print(json.dumps({"message":"success","code":rule_match}))
                                    else :
                                        #response = '{ "code":"error", "message":"Rule does not exists in iptables... !" }'
                                        #print(json.loads(response))
                                        print(json.dumps({"message":"Rule does not exists in iptables... !","code":"error"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "accesslogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo tail -100 /var/log/apache2/access_log")
                                    access_logs = stdout.readlines()
                                    print(access_logs)
                                    out = []
                                    for i in access_logs:
                                        i.split()
                                        out.append(re.split(r'"|- -',i))
                                    print(json.dumps({"data":out,"code":"success"}))
                                
                                except:
                                    print(json.dumps({"message":"Error... !","code":"error"}))
                        
                            elif(Task == "securelogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo head -10 /var/log/secure")
                                    secure_logs = stdout.readlines()
                                    output = []
                                    for i in secure_logs:
                                        out = i.split()
                                        output.append(out)
                                        response = '{ "code":"success", "message":"%s" }'%output
                                    print(response)
                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "csf"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.deny")
                                    csf_deny = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.allow")
                                    csf_allow = stdout.readlines()
                                    output = []
                                    output1 = []
                                    for i in csf_deny:
                                        out = re.findall("^#",i)
                                        if not out:
                                            output.append(i.split())

                                    for j in csf_allow:
                                        out = re.findall("^#",j)
                                        if not out:
                                            output1.append(j.split())

                                    print(json.dumps({'data':(output,output1),'code' : "success"}))

                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "openedports"):
                                try:
                                    stdin, stdout, stderr = con.exec_command("sudo cat /etc/csf/csf.conf")
                                    csf_conf = stdout.readlines()
                                    output = []
                                    for i in csf_conf:
                                        x = re.findall("^TCP_IN",i)
                                        y = re.findall("^TCP_OUT",i)
                                        z = re.findall("^UDP_IN",i)
                                        w = re.findall("^UDP_OUT",i)
                                        if (x or y or z or w) :
                                            output.append(i)
                                            response = json.dumps({'data':output,'code' : "success"})
                                    print(response)
                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "services"):
                                try:

                                    stdin, stdout, stderr = con.exec_command("service httpd status")
                                    service1 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service nginx status")
                                    service2 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service vsftpd status")
                                    service3 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service mysqld status")
                                    service4 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service mariadb status")
                                    service5 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service sshd status")
                                    service6 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service crond status")
                                    service7 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service firewalld status")
                                    service8 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service csf status")
                                    service9 = stdout.readlines()
                                    stdin, stdout, stderr = con.exec_command("service fail2ban status")
                                    service10 = stdout.readlines()

                                    if service1 == [] or "could not be found" in str(service1):
                                        response1 = "Unknown"
                                        print("Unknown")
                                    elif "running" in str(service1) :
                                        response1 = "Active"
                                        print("Active")
                                    elif "stopped" in str(service1) :
                                        response1 = "Stopped"
                                    elif "disabled" in str(service1) :
                                        response1 = "Disabled"
                                        print("Disabled")
                                    if service2 == [] or "could not be found" in str(service2):
                                        response2 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service2) :
                                        response2 = "Stopped"
                                    elif "running" in str(service2) :
                                        response2 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service2) :
                                        response2 = "Disabled"
                                        print("Disabled")
                                    if service3 == [] or "could not be found" in str(service3):
                                        response3 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service3) :
                                        response3 = "Stopped"
                                    elif "running" in str(service3) :
                                        response3 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service3) :
                                        response3 = "Disabled"
                                        print("Disabled")
                                    if service4 == [] or "could not be found" in str(service4):
                                        response4 = "Unknown"
                                        print("Unknown")

                                    elif "running" in str(service4) :
                                        response4 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service4) :
                                        response4 = "Disabled"
                                        print("Disabled")
                                    if service5 == [] or "could not be found" in str(service5):
                                        response5 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service5) :
                                        response5 = "Stopped"
                                    elif "running" in str(service5) :
                                        response5 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service5) :
                                        response5 = "Disabled"
                                        print("Disabled")
                                    if service6 == [] or "could not be found" in str(service6):
                                        response6 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service6) :
                                        response6 = "Stopped"
                                    elif "running" in str(service6) :
                                        response6 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service6) :
                                        response6 = "Disabled"
                                        print("Disabled")
                                    if service7 == [] or "could not be found" in str(service7):
                                        response7 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service7) :
                                        response7 = "Stopped"
                                    elif "running" in str(service7) :
                                        response7 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service7) :
                                        response7 = "Disabled"
                                        print("Disabled")
                                    if service8 == [] or "could not be found" in str(service8):
                                        response8 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service8) :
                                        response8 = "Stopped"
                                    elif "Table:" or "Chain" in str(service8) :
                                        response8 = "Active"
                                        print("Active")
                                    elif "disabled" or "dead" in str(service8) :
                                        response8 = "Disabled"
                                        print("Disabled")
                                    if service9 == [] or "could not be found" in str(service9):
                                        response9 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service9) :
                                        response9 = "Stopped"
                                    elif "running" in str(service9) :
                                        response9 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service9) :
                                        response9 = "Disabled"
                                        print("Disabled")
                                    if service10 == [] or "could not be found" in str(service10):
                                        response10 = "Unknown"
                                        print("Unknown")
                                    elif "stopped" in str(service10) :
                                        response10 = "Stopped"
                                    elif "running" in str(service10) :
                                        response10 = "Active"
                                        print("Active")
                                    elif "disabled" in str(service10) :
                                        response10 = "Disabled"
                                        print("Disabled")

                                    response = json.dumps({'data':[["Apache Web Server",response1],["Nginx Web Server",response2],["FTP Server",response3],["MySQL Database Server",response4],["Mariadb Database Server",response5],["SSH Server",response6],["Crontab",response7],["Iptables Firewall",response8],["ConfigServer Security & Firewall",response9],["Intrusion Prevention System",response10]],'code' : "success"})
                                    print(response)

                                except:
                                    response = '{ "code":"error", "message":"Error... !" }'
                                    print(json.loads(response))

                            elif(Task == "restartservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld restart")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server restarted successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service firewalld restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -e")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban restart")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System restarted successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                            elif(Task == "startservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld start")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server started successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service firewalld start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -s")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban start")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System started successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                            
                            elif(Task == "stopservice"):
                                if sys.argv[3] == "Apache Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service httpd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Apache Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Nginx Web Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service nginx stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Nginx Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "FTP Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service vsftpd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"FTP Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "MySQL Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mysqld stop")
                                        csf_conf = stdout.readlines()
                                        print(json.dumps({'data':"MySQL Server stopped successfully",'code' : "success"}))
                                    except:
                                        print(json.dumps({'data':"Error",'code' : "Error"}))

                                elif sys.argv[3] == "Mariadb Database Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service mariadb stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Mariadb Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "SSH Server":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service sshd stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"SSH Server stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Crontab":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service crond stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Crontab stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Iptables Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service firewalld stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"Iptables Firewall stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "ConfigServer Security & Firewall":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("csf -x")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"ConfigServer Security & Firewall stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)

                                elif sys.argv[3] == "Intrusion Prevention System":
                                    try:
                                        stdin, stdout, stderr = con.exec_command("service fail2ban stop")
                                        csf_conf = stdout.readlines()
                                        response = json.dumps({'data':"intrusion Prevention System stopped successfully",'code' : "success"})
                                        print(response)
                                    except:
                                        response = json.dumps({'data':"Error",'code' : "Error"})
                                        print(response)
                        
                            elif(Task == "checkport"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('nmap '+sys.argv[3]+' -p '+sys.argv[4])
                                    output = stdout.readlines()
                                    if "STATE" and "open" in str(output):
                                        print(json.dumps({'data':"This port is reachable",'code' : "success"}))
                                    else:
                                        print(json.dumps({'data':"This port is not reachable",'code' : "success"}))
                                except:
                                    print(json.dumps({'data':"Error",'code' : "error"}))    
                        
                            elif(Task == "checkip"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('iptables -S')
                                    output = stdout.readlines()
                                    ##print(output)
                                    rule_match = [s for s in output if sys.argv[3] in s]

                                    stdin, stdout, stderr = con.exec_command('host '+sys.argv[3])
                                    output1 = stdout.readlines()

                                    if(len(rule_match) != 0):
                                        #response = '{ "code":"success", "message":"%s" }'%rule_match
                                        print(json.dumps({"code":"success","data":"IP Adress exists in iptables \n"+str(rule_match)}))
                                    elif "name pointer" in str(output1):
                                        print(json.dumps({"code":"success","data":str(output1)}))

                                    else :
                                        #response = '{ "code":"error", "message":"Rule does not exists in iptables... !" }'
                                        #print(json.loads(response))
                                        print(json.dumps({"data":"IP Address NOT found","code":"error"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "installservice"):
                                if sys.argv[3] == "Intrusion Prevention System":
                                    try:

                                        stdin, stdout, stderr = con.exec_command('yum install fail2ban')
                                        output1 = stdout.readlines()

                                        stdin, stdout, stderr = con.exec_command('systemctl enable fail2ban')
                                        output2 = stdout.readlines()

                                        stdin, stdout, stderr = con.exec_command('systemctl start fail2ban')
                                        output3 = stdout.readlines()

                                        response = json.dumps({'data':"fail2ban started successfully",'code' : "success"})
                                        print(response)

                                    except:
                                        response = '{ "code":"error", "message":"Error ... !" }'
                                        print(json.loads(response))
                        
                            elif(Task == "fail2banlogs"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('sudo cat /var/log/fail2ban.log')
                                    logs = stdout.readlines()
                                    output=[]
                                    for i in logs:
                                        output.append(i.split(" ",2))
                                    print(json.dumps({'data':output,'code' : "success"}))

                                except:
                                    print(json.dumps({'data':'Error','code' : "Error"}))
                        
                            elif(Task == "fail2banIPbanned"):
                                try:
                                    search_term = 'Ban'
                                    stdin, stdout, stderr = con.exec_command('sudo zgrep '+search_term+' /var/log/fail2ban.log')
                                    banned_ips = stdout.readlines()
                                    output = []
                                    for i in banned_ips:

                                        output.append(i.split(" ",2))
                                        print(output)
                                    print(json.dumps({'data':output,'code' : "success"}))

                                except:
                                   print(json.dumps({'data':'Error','code' : "Error"}))

                            elif(Task == "addurl"):
                                try:
                                    url_to_protect = sys.argv[3]
                                    ip_add = sys.argv[4]
                                    stdin, stdout, stderr = con.exec_command('ls -a '+url_to_protect+'')
                                    output = stdout.readlines()
                                    if "htaccess" in str(output):
                                        #stdin, stdout, stderr = con.exec_command('touch '+url_to_protect+'/.htaccess')
                                        #stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+url_to_protect+'/.htaccess')
                                        #stdin, stdout, stderr = con.exec_command('echo deny from all >> '+url_to_protect+'/.htaccess')
                                        query = ("SELECT * FROM firewall_url_protection WHERE firewall_url_protection.ip_address=%s and firewall_url_protection.status IN (1,2,3)")
                                        cursor.execute(query,(sys.argv[4],))
                                        r = cursor.fetchall()
                                        print(r)
                                        if ip_add in str(r):
                                            print(json.dumps({'data':"IP Address already exists",'code' : "success"}))
                                        else:
                                            stdin, stdout, stderr = con.exec_command('echo "\nallow from '+ip_add+'" >> '+url_to_protect+'/.htaccess')
                                            print(json.dumps({'data':"URL added successfully",'code' : "success"}))
                                    else:
                                        stdin, stdout, stderr = con.exec_command('touch '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo deny from all >> '+url_to_protect+'/.htaccess')
                                        stdin, stdout, stderr = con.exec_command('echo allow from '+ip_add+' >> '+url_to_protect+'/.htaccess')

                                        print(json.dumps({'data':"URL added successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                        
                            elif(Task == "updateurl"):
                                try:
                                    query = ("SELECT * FROM firewall_url_protection WHERE firewall_url_protection.id=%s")
                                    cursor.execute(query,(sys.argv[3],))
                                    r = cursor.fetchall()
                                    stdin, stdout, stderr = con.exec_command('rm -f '+r[0][2]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('touch '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo order deny,allow >> '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo deny from all >> '+sys.argv[4]+'/.htaccess')
                                    stdin, stdout, stderr = con.exec_command('echo allow from '+sys.argv[5]+' >> '+sys.argv[4]+'/.htaccess')

                                    print(json.dumps({'data':"URL updated successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))
                            
                            elif(Task == "deleteurl"):
                                try:
                                    stdin, stdout, stderr = con.exec_command('rm -f '+sys.argv[3]+'/.htaccess')
                                    print(json.dumps({'data':"URL delete successfully",'code' : "success"}))
                                except:
                                    response = '{ "code":"error", "message":"Error ... !" }'
                                    print(json.loads(response))

                            else:
                                response = '{ "code":"error", "message":"Function not defined!" }'
                                print(json.loads(response))   

                        else:
                             print(json.dumps({"data":"OS NOT SUPPORTED !","code":"error"}))
                
                    except:
                         print(json.dumps({"data":"Error... !!","code":"error"}))  
        except:
             print(json.dumps({"data":"Error... !","code":"error"}))

    #finally:
    #    cursor.close()
    #    connection.close()
    #    con.close()
    #    response = '{ "code":"success", "message":"Connection is closed" }'
    #    print(json.loads(response))

firewall(sys.argv[1],sys.argv[2])