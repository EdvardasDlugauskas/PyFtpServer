import ftplib

ftp = ftplib.FTP("192.168.1.172")
print(ftp.login("anonymous", "ftplib-example-1"))
print(ftp.getwelcome())

ftp.cwd("venv")
data = []
ftp.dir(data.append)
for line in data:
    print("-", line)

# Download
with open("retrievedFile.txt", 'wb') as f:
    def callback(data):
        f.write(data)

    ftp.retrbinary(f'RETR somefile.txt', callback)

print(ftp.quit())
