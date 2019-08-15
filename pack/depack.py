#coding=utf-8 

import fileinput
# 本程序的bug：因为导出二进制数据时，字符串匹配以"0000  "为
# 开始标志，这与wireshark导出文件的第一个包的时间0.000000相
# 同,所以第一个你要手工把0.000000改为0.000001。
# 本程序就是为了导出数据加以分析，不必为了修正上面的bug绕半天
#

# 在介绍本程序功能之前，先了解一下wireshark文件的格式。
# wireshark导出文件格式，"No."是开始标志，开始标志的
# 下一行是ip地址和协议信息，接下来是它协议分析的一些输出
# 最后是Data。
#
#No.     Time        Source                Destination           Protocol Info
#  16    58.5      192.168.0.66          234.5.6.7              UDP      Source port: 1024  Destination port: synchronet-db
#
# 这中间是wireshark分析的输出
#
#
#Data (40 bytes)
#
#0000  e9 24 00 00 ff ff 01 00 02 00 00 00 d2 04 00 00   .$..............
#0010  14 00 00 00 42 03 01 00 00 00 00 00 05 00 00 00   ....B...........
#0020  02 00 00 00 33 00 00 00                           ....3...
#

#-------------------------------------------------------
# 本程序的功能是读取wireshark的导出文件，过滤出指定ip的数据
# 1. Print_Data_Text导出从一个"No."到下一个"No."之间的内容
# 2. Print_Data_bin 导出"Data "部分的内容，格式如下：
		#e9 24 00 00 ff ff 01 00 02 00 00 00 d2 04 00 00
		#14 00 00 00 42 03 01 00 00 00 00 00 05 00 00 00
		#02 00 00 00 33 00 00 00 
		#----                       
		#e9 24 00 00 ff ff 01 00 02 00 00 00 d2 04 00 00
		#14 00 00 00 42 03 01 00 00 00 00 00 05 00 00 00
		#02 00 00 00 33 00 00 00                        
		#在两个数据包之间插入了一样"----",

# 3. Print_IP_Line 仅导出包含ip的行，就是"No."下面的那行

#-------------------------------------------------------
# 如何设置导出数据的条件：
		# 导出数据的条件
		# and字段的内容必须全部满足
		# or字段的内容，至少满足一个
		# and 字段和 or 字段都满足
		# 如果and字段不存在，则认为条件满足
		# 如果or字段不存在，则认为条件满足
		#No.     Time        Source                Destination           Protocol Info
		#14 9.949685  192.168.0.66          234.5.6.7             UDP      Source port: onehome-remote  Destination port: synchronet-db
		# 举例：
		# 导出满足下面条件的数据：
		# No.下面一行的数据，包含"234.5.6.7"和"UDP"，
		# 并且包含"192.168.0.202"和"192.168.0.22"之一
		#    cond = []
		#    cond.append({
		#    "and":["234.5.6.7", "UDP"],
		#    "or":["192.168.0.202", "192.168.0.22"],
		#      })
		#      
#-------------------------------------------------------


# 导出满足条件的数据, 为了在导出的文件中能看到数据是从
# 源文件的那个地方来的，导出的数据可以带有行号信息，行号
# 添加在每行数据的前面
# fileName				: 原始数据文件名称
# saveto          : 导出数据保存文件名称
# cond            : 数据需要满足的条件
# with_ln_number  : 导出数据时是否带行号
# 只有带行号的数据，才能被Print_Data_bin函数使用
def Print_Data_Text(fileName, saveto, cond, with_ln_number=True):
    f1 = open(saveto, 'w+')

    ln = []
    myfile = fileinput.input(fileName)
    for x in myfile:
      ln.append(x)
    start_flag = 0
    start_ln = 0
    end_ln = 0
    end_flag = 0
    find_count = 0
    print ("  ")
    for i in range(0,len(ln)):
            
            if ln[i].find("No.") == 0 and start_flag == 1:
              start_flag = 0
            if ln[i].find("No.") == 0 and start_flag == 0:
               if Check_Expr(ln[i+1], cond)==True:
                start_ln = i
                start_flag = 1
                find_count = find_count + 1
                msg = ""
                msg = ("/b/b/b/b/b/b/b%02d")%(find_count)
                print (msg)
    
              
            if start_flag == 1:
                  msg = ""
                  if with_ln_number == True:
                      msg = ("%08d:/t%s")%(i+1,ln[i])
                  else:
                       msg = ("%s")%(ln[i])
                 	
                  f1.write(msg)
    
    f1.close()



# 导出数据包中的Data字段的内容
# 通过，查找 "0000  "作为开始标志
# 查找"Data:"作为结束标志
def Print_Data_bin(fileName, saveto, data_start, data_end, with_ln_number=True):
    f1 = open(saveto, 'w+')
    ln = []
    myfile = fileinput.input(fileName)
    for x in myfile:
      ln.append(x)
    start_flag = 0
    start_ln = 0
    end_ln = 0
    end_flag = 0
    find_count = 0
    print ("  ")
    for i in range(0,len(ln)):

            if start_flag == 0 and Check_Expr(ln[i], data_start)==True:
              start_flag = 1
              msg = ("%s")%(ln[i][16:63])
              f1.write("")
            if start_flag == 1 and Check_Expr(ln[i], data_end)==True:
              start_flag = 0
    
              
            if start_flag == 1:
                  msg = ""
                  if with_ln_number == True:
                      msg = ("%s ")%(ln[i][16:63])
                  else:
                      msg = ("%s ")%(ln[i][6:53])
                  
                  f1.write(msg)
#            if i > 100:
#              break
    f1.close()

def Check_Expr(ln, expr):
    expr_flag = False
    for x in expr:
        and_flag = True
        or_flag = False
        if 'and' in x:
            for y in x["and"]:
                if ln.find(y) == -1:
                    and_flag = False
                    break
           
        if 'or' in x:
            for y in x["or"]:
                if ln.find(y) != -1:
                    or_flag = True
                    break
        else:
            or_flag = True
         
        if and_flag == True and or_flag == True:
            expr_flag = True
            break
    return expr_flag

#
# 为了方便查看数据网来，只
# 打印带有IP地址的那行数据
#
def Print_IP_Line(fileName, saveto,cond):
    f1 = open(saveto, 'w+')
    ln = []
    myfile = fileinput.input(fileName)
    for x in myfile:
      ln.append(x)
    start_flag = 0
    start_ln = 0
    end_ln = 0
    end_flag = 0
    find_count = 0
    print ("  ")
    for i in range(0,len(ln)):
            
            if ln[i].find("No.") == 0:
               if Check_Expr(ln[i+1], cond) == True:
                 start_ln = i+1
                 start_flag = 1
                 find_count = find_count + 1
                 msg = ""
                 msg = ("/b/b/b/b/b/b/b/b%02d")%(find_count)
                 print (msg)
              
            if start_flag == 1:
                  msg = ""
                  msg = ("%08d:/t%s")%(start_ln+1,ln[start_ln])
                  f1.write(msg)
                  start_flag = 0

    f1.close()

if __name__ == '__main__': 

    src_data_file = "src.txt"
    src_data_file2 = "src1.txt"
    txt_data_file_11 = "RE_11.txt"
    bin_data_file_11 = "bin_11.txt"
    txt_data_file_66 = "RE_66.txt"
    bin_data_file_66 = "bin_66.txt"
#
# 导出数据的条件
# and字段的内容必须全部满足
# or字段的内容，至少满足一个
# and 字段和 or 字段都满足
# 如果and字段不存在，则认为条件满足
# 如果or字段不存在，则认为条件满足
# 举例：
#No.     Time        Source                Destination           Protocol Info
#14 9.949685  192.168.0.202          234.5.6.7             UDP      Source port: onehome-remote  Destination port: synchronet-db
# 导出满足下面条件的数据：
# No.下面一行的数据，包含"234.5.6.7"和"UDP"，并且并且包含"192.168.0.202"和"192.168.0.22"之一
#    cond = []
#    cond.append({
#    "and":["234.5.6.7", "UDP"],
#    "or":["192.168.0.202", "192.168.0.22"],
#      })
#      

    cond = []
    cond.append({
    "and":["127.0.0.1", "TCP"],
    "or":["127.0.0.1", "127.0.0.1"],
      })
      


    getdata_start = []
    getdata_start.append({
    "and":["0000  "],
      })
    getdata_end = []
    getdata_end.append({
    "and":["Data: "],
      })

#    print getdata_start
#    Print_IP_Line('c://RE.txt',cond)
    filter_data_11 = []
    filter_data_11.append({
    "and":["127.0.0.1", "127.0.0.1", "TCP"],
      })
    filter_data_66 = []
    filter_data_66.append({
    "and":["127.0.0.1", "127.0.0.1", "TCP"],
      })
      
    Print_Data_Text(src_data_file, txt_data_file_11, filter_data_11)
    Print_Data_bin(txt_data_file_11, bin_data_file_11,getdata_start, getdata_end)
    Print_Data_Text(src_data_file, txt_data_file_66, filter_data_66)
    Print_Data_bin(txt_data_file_66, bin_data_file_66,getdata_start, getdata_end)
    Print_Data_bin(src_data_file, "ttxx1.txt",getdata_start, getdata_end, 0)
    Print_IP_Line(src_data_file,"ttxx2.txt", cond)
    Print_Data_bin(src_data_file2, "ttxx3.txt",getdata_start, getdata_end, 0)
    
