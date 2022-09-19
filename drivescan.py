import textract
import datetime
import os
import argparse
import re
# Please input the keywords you want to search here:
parser = argparse.ArgumentParser()
keyword = ['(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',"((\\\"|'|`)?((?i)aws)?_?((?i)access)_?((?i)key)?_?((?i)id)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(\\\"|'|`)?)","((\\\"|'|`)?((?i)aws)?_?((?i)account)_?((?i)id)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?[0-9]{4}-?[0-9]{4}-?[0-9]{4}(\\\"|'|`)?)","((\\\"|'|`)?((?i)aws)?_?((?i)secret)_?((?i)access)?_?((?i)key)?_?((?i)id)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?[A-Za-z0-9/+=]{40}(\\\"|'|`)?)","((\\\"|'|`)?((?i)aws)?_?((?i)session)?_?((?i)token)?(\\\"|'|`)?(\\\\s{0,50})?(:|=>|=)(\\\\s{0,50})?(\\\"|'|`)?[A-Za-z0-9/+=]{100,400}(\\\"|'|`)?)","(?i)artifactory.{0,50}(\\\"|'|`)?[a-zA-Z0-9=]{112}(\\\"|'|`)?","(?i)codeclima.{0,50}(\\\"|'|`)?[0-9a-f]{64}(\\\"|'|`)?",'EAACEdEose0cBA[0-9A-Za-z]+',"((\\\"|'|`)?type(\\\"|'|`)?\\\\s{0,50}(:|=>|=)\\\\s{0,50}(\\\"|'|`)?service_account(\\\"|'|`)?,?)",'(?:r|s)k_(live|test)_[0-9a-zA-Z]{24}','[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com','AIza[0-9A-Za-z\\-_]{35}','ya29\\.[0-9A-Za-z\\-_]+','sk_[live|test]_[0-9a-z]{32}','sq0atp-[0-9A-Za-z\-_]{22}','sq0csp-[0-9A-Za-z\-_]{43}','access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}','amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}','SK[0-9a-fA-F]{32}','SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}','key-[0-9a-zA-Z]{32}','[0-9a-f]{32}-us[0-9]{12}',"sshpass -p.*['|\\\"]",'(https\\://outlook\\.office.com/webhook/[0-9a-f-]{36}\\@)',"(?i)sauce.{0,50}(\\\"|'|`)?[0-9a-f-]{36}(\\\"|'|`)?",'(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})','https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',"(?i)sonar.{0,50}(\\\"|'|`)?[0-9a-f]{40}(\\\"|'|`)?","(?i)hockey.{0,50}(\\\"|'|`)?[0-9a-f]{32}(\\\"|'|`)?",'([\w+]{1,24})(://)([^$<]{1})([^\s";]{1,}):([^$<]{1})([^\s";/]{1,})@[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,24}([^\s]+)','oy2[a-z0-9]{43}','hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20}','-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY','define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?[''|"].{10,120}[''|"]','(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\/+]{20,40}','(?i)twitter(.{0,20})?[''\"][0-9a-z]{35,44}[''\"]','(?i)twitter(.{0,20})?[''\"][0-9a-z]{18,25}[''\"]','(?i)heroku(.{0,20})?[''"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[''"]','password:','pwd:','pass:','pwd=','password=','pass=','password>','pwd>']
## settingss ##
parser.add_argument("-os", "--ostype", help="Specify OS (windows or linux)",type=str, required=True)
parser.add_argument("-p", "--path", help="Path to search",type=str, required=True)
parser.add_argument("-o", "--output", help="Path to output results, Ea /tmp/results/ OR c:\\Temp\\",type=str, required=True)

args = parser.parse_args()
ostype = str(args.ostype).lower()
if ostype == "windows":
    dirslash = "\\"
else:
    dirslash = "/"
# Please input the path for the searched list of directory
path = str(args.path)
date2 = datetime.datetime.now()
date = date2.strftime("%Y-%m-%d")

# Output File format and location
outdir = str(args.output)
outputfile = outdir + 'tempresult' + date+ '.txt'
errorfile = outdir + 'error' + date + '.txt'
if not os.path.exists(outdir):
    os.makedirs(outdir)
# Keywords to extract
textract_ext = ['docx','eml','epub','msg','pptx','ps','txt','xlsx','xls','rtf','pdf']
native_ext = ['template','conf','config','deploy','bat','vbs','LOG','xml','cmd','vb','py','pl','csv','html','json','htm']

# To search for any cleartext password
def searchstring():
    for paths in os.listdir(path):
        if paths.endswith(tuple(textract_ext)):
            print(paths)
            try:
                text = textract.process(path + dirslash + paths).decode('utf-8')
                for x in keyword:
                    if re.search(x, text, re.IGNORECASE):
                        time = datetime.datetime.now()
                        with open(outputfile,'a+',encoding='utf-8', errors='ignore') as w:
                            w.write(str(time)+ '||' + path + dirslash + paths +'||'+str(x)+'\n')
                            w.close()
            except Exception as e:
                with open (errorfile, 'a+', encoding = 'utf-8', errors = 'ignore') as k :
                    time = datetime.datetime.now()
                    k.write(str(time)+ '||' + str(e) + '\n')
                    k.close()

        elif paths.endswith(tuple(native_ext)):
            try:
                open_file=open(path + dirslash + paths,'r',encoding='utf-8',errors='ignore')
                read_file=open_file.read()
                print(read_file)
                for x in keyword:
                    if re.search(x, read_file, re.IGNORECASE):
                        time = datetime.datetime.now()
                        with open(outputfile,'a+',encoding='utf-8', errors='ignore') as w:
                            w.write(str(time)+ '||' + path + dirslash + paths +'||'+str(x)+'\n')
                            w.close()
            except Exception as e:

                with open (errorfile, 'a+', encoding = 'utf-8', errors = 'ignore') as k :
                    time = datetime.datetime.now()
                    k.write(str(time)+ '||' + str(e) + '\n')
                    k.close()
        else:
            with open (errorfile, 'a+', encoding = 'utf-8', errors = 'ignore') as e :
                time = datetime.datetime.now()
                e.write(str(time)+ '||'+ 'File Type not supported:' + path + dirslash + paths + '\n')
                e.close()


            continue;

def main():
    searchstring()

if __name__== "__main__":
    main()
