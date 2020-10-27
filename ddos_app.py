import socket
import struct
import time
import numpy as np
import pandas as pd
import pickle
import sys
from ddos_ui import *


myfile =  open("config.txt", "r")

PATH_MODEL = myfile.readline().split(':')[1].strip()      #path model
TIME_SCAN =  int(myfile.readline().split(':')[1].strip()) #khoảng thời gian chương trình quét để phát hiện ddos
NAME_HOST = myfile.readline().split(':')[1].strip()       #ten host
PORT = int(myfile.readline().split(':')[1].strip())       #cổng thực hiện quét

myfile.close()

HOST = socket.gethostbyname(NAME_HOST)  #địa chỉ ip


# Tạo một raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, PORT))

# Các gói tin chặn bắt được sẽ bao gồm cả ip header
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

#array chứa tất cả các gói tin
packages_lenght = []
while True:
    if(s.recvfrom(2048)):
        start = time.time()
        break;
print("Phát hiên truy cập đến cổng :", PORT) 
while True:
    
    data = s.recvfrom(65536)
    packages_lenght.append(len(data[0]))
    ipheader = data[0][14:34]
    ip_hdr = struct.unpack("!2H2I4H",ipheader)
    flags = ip_hdr[4] & 0x003f
    
    end = time.time()
    time_scan = end - start
    if (time_scan >= TIME_SCAN):
        break;

packages_lenght   = np.array(packages_lenght)   
packages_lenght   = packages_lenght*1000
number_package    = round(packages_lenght.shape[0],2)                     #số lượng gói tin
byte_s            = round(sum(packages_lenght) / TIME_SCAN,2)             #số byte/s 
package_s         = round(number_package / TIME_SCAN, 2)                  #số gói tin/s 
sdt_package       = round(np.std(packages_lenght), 2)                     #độ lệch chuẩn kích thước (size)của tất cả gói tin
variance_package  = round(sdt_package**2,2)                               #phương sai kích thước(size) của tất cả gói tin
max_size_package  = round(max(packages_lenght),2)                         #kích thước lớn nhất trong các gói tin  
min_size_package  = round(min(packages_lenght), 2)                        #kích thước nhỏ nhất trong các gói tin 
size_package_mean = round(sum(packages_lenght) / len(packages_lenght),2)  #kích thước trung bình của tất cả gói tin

print("byte_s: ",byte_s)
print("package_s: ",package_s)
print("lengt max: ",max_size_package)
print("lengt min: ",min_size_package)
print("lengt mean: ",size_package_mean)
print("lengt std: ",sdt_package)
print("lengt variance: ",variance_package)

package = np.zeros([8])
package = package.reshape(8,1).T
package = pd.DataFrame(package)

package.columns = ['Destination Port', 
                   'Flow Bytes/s', 
                   'Flow Packets/s',
                   'Min Packet Length', 
                   'Max Packet Length',
                   'Packet Length Mean',
                   'Packet Length Std', 
                   'Packet Length Variance']

package['Destination Port'] = 80
package['Flow Bytes/s'] = byte_s
package['Flow Packets/s'] = package_s
package['Max Packet Length'] = max_size_package
package['Min Packet Length'] = min_size_package
package['Packet Length Mean'] = size_package_mean
package['Packet Length Std'] = sdt_package
package['Packet Length Variance'] = variance_package

# disabled promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

# Load model đã được lưu
model = pickle.load(open(PATH_MODEL, 'rb')) 
predict = model.predict(package)

#PyQt5

#label 1 la ddos, label 0 khong phai ddos
if(predict[0]==1):
    print("May dang bi ddos")
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow,package)
    MainWindow.show()
    app.exec_()
    app.exit()
    sys.exit()