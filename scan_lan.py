import os

def extract_info():
        f = os.popen('ifconfig eth0 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
        your_ip=f.read()
        f = os.popen('ifconfig eth0 | grep "inet\ addr" | cut -d: -f4')
        your_mask=f.read()[:-1]

        return your_ip, your_mask

def check_1(your_ip, your_mask):
        lips = []
        a = your_mask.split(".")
        print a
        if a[1] == 0:
                lips = chech_barra8(your_ip)
        elif a[2] == 0:
                lips = check_barra16(your_ip)
        elif a[3] == 0:
                lips = check_barra24(your_ip)
        return lips



def check_barra8(your_ip):
        lista_ip = []
        first_num = your_ip.split(".")[0]
        for i in range(1, 255):
                for j in range(1, 255):
                        for k in range (1, 255):
                                ipp = first_num+str(i)+str(j)+str(k)
                                lista_ip.append(ipp)
        return lista_ip

def check_barra16(your_ip):
        lista_ip = []
        first_num = your_ip.split(".")[0]
        second_num = your_ip.split(".")[1]
        for i in range(1, 255):
                for j in range(1, 255):
                        ipp = first_num+second_num+str(j)+str(k)
                        lista_ip.append(ipp)
        return lista_ip

def check_barra24(your_ip):
        lista_ip = []
        first_num = your_ip.split(".")[0]
        second_num = your_ip.split(".")[1]
        third_num = your_ip.split(".")[2]
        for k in range(1, 255):
                ipp = first_num+second_num+sthird_num+str(k)
                lista_ip.append(ipp)
        return lista_ip



if __name__ == "__main__":
        ip, mask = extract_info()
        l_ips = []
        l_ips = check_1(ip, mask)
        print l_ips
