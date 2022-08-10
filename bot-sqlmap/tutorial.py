import subprocess
import query

def scan_url_vulnerability(url):
	query = "sqlmap -u "+ url +" --batch"
	vuls=[]

	f = open("output.txt", "w")
	f.write("query:" + query)
	f.write("\n")
	f.close()

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
			f = open("output.txt", "a")
			f.write("time_starting:" + time_starting)
			f.write("\n")
			f.close()
			# print("time starting = " + time_starting)
		if (stdout[x:(x+4)]) == "Type":
			vul = stdout[x+6]
			f = open("output.txt", "a")
			f.write("vul:" + vul)
			f.write("\n")
			f.close()
			vuls.append(stdout[x+6])
	return vuls		


def scan_url_database(url, tech, level):
	query = "sqlmap -u " + url + " --technique=" + tech + " --level " + level + " --dbs" + " --batch"
	process = subprocess.Popen([query], 
						stdin=subprocess.PIPE,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						shell = True, text = True)
	stdout,stderr = process.communicate()
	f = open("database.txt", "w")
	f.write(stdout)
	f.close()
	print("scanning database")
	for x in range(len(stdout)):
		if(stdout[x:(x+19)]) == "available databases":
			dbs = stdout[(x+29):(x+35)]
			f = open("output.txt", "a")
			f.write("dbs:" + dbs)
			f.write("\n")
			f.close()
		if (stdout[x:(x+6)]) == "ending":
			time_ending = stdout[(x+9):(x+17)]
			f = open("output.txt", "a")
			f.write("time_ending:" + time_ending)
			f.write("\n")
			f.close()
			# print("time ending = " + time_ending)

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
	print("database")


def main():
	mode = 1
	tech = ["B", "E", "U", "S", "T", "Q"]
	level = ["2", "3", "4", "5"]
	if(mode == 1):
		f = open("input.txt", "r")
		url =  f.read()
		f.close()
		scan_url_vulnerability(url)
		scan_url_database(url, tech[0], level[0])
	if(mode == 2):
		print("scan with query")
	if(mode == 3):
		print("test")

if __name__ == "__main__":
	main()