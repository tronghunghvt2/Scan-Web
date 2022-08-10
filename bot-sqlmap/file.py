def file_write(path, category, content):
	f = open("path", "w")
	f.write(category + ":" + content)
	f.write("\n")
	f.close()

def file_append(path, category, content):
	f = open("path", "a")
	f.write(category + ":" + content)
	f.write("\n")
	f.close()

def read(path):
	f.open(path, "r")
	content = f.read()
	f.close()
	return content